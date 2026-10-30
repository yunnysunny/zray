//! One proxied connection: SOCKS5 client <-> REALITY/VLESS/Vision upstream.
//!
//! Non-blocking, single-threaded, driven by `Loop`. All buffers are fixed
//! size members so a connection's memory footprint is a compile-time constant
//! (`@sizeOf(Conn)`), and the pool is allocated once at startup.
//!
//! Data path (per direction) is strictly "read one chunk -> transform -> queue
//! -> drain". A side is only read when its outgoing queue is empty, which
//! gives natural back-pressure without any dynamic allocation.

const std = @import("std");
const mem = std.mem;
const tls = std.crypto.tls;
const sys = @import("sys.zig");
const client = @import("../tls/client.zig");
const hello = @import("../tls/hello.zig");
const record = @import("../tls/record.zig");
const reality = @import("../tls/reality.zig");
const vless = @import("../proxy/vless.zig");
const vision = @import("../proxy/vision.zig");
const socks5 = @import("../proxy/socks5.zig");
const fingerprint = @import("../tls/fingerprint.zig");
const sniff = @import("../proxy/sniff.zig");
const mux = @import("../proxy/mux.zig");

const max_rec = tls.max_ciphertext_record_len;
/// Largest chunk read from the SOCKS client per event (xray uses 8 KiB).
const client_chunk = 8192;

pub const Config = struct {
    server_addr: sys.SockAddr,
    sni: []const u8,
    /// null: plain TLS 1.3 (SNI only, certificate chain not verified).
    reality: ?reality.Config = null,
    uuid: [16]u8,
    handshake_timeout_s: u64 = 15,
    idle_timeout_s: u64 = 600,
    /// Per-socket SO_RCVBUF / SO_SNDBUF; 0 = kernel default.
    sock_buf: i32 = 0,
    /// Replace redirected IP targets with the sniffed TLS SNI / HTTP Host.
    sniff: bool = true,
};

pub const Inbound = enum { socks5, redirect };

pub const Side = enum(u2) { client = 0, upstream = 1, udp = 2 };

pub const State = enum {
    free,
    socks_greeting,
    socks_request,
    connecting,
    tls_handshake,
    relay,
};

pub const Conn = struct {
    state: State = .free,
    slot: u32,
    /// Incremented on every reuse so stale epoll events can be ignored.
    gen: u30 = 0,
    client_fd: sys.fd_t = -1,
    up_fd: sys.fd_t = -1,
    client_ev: u32 = 0,
    up_ev: u32 = 0,
    udp_ev: u32 = 0,

    // SOCKS5 UDP ASSOCIATE: `client_fd` is only the control connection, packets
    // flow on `udp_fd` and are carried upstream as XUDP mux frames.
    is_udp: bool = false,
    udp_fd: sys.fd_t = -1,
    udp_peer: ?sys.SockAddr = null,
    udp_started: bool = false,
    global_id: [8]u8 = undefined,
    mux_in: [mux.max_frame_len]u8 = undefined,
    mux_in_len: usize = 0,
    last_active: u64 = 0,
    client_eof: bool = false,
    /// Upstream finished sending; close once `c_out` is drained.
    up_eof: bool = false,

    // client -> upstream
    cin: [client_chunk]u8 = undefined,
    cin_len: usize = 0,
    up_out: [max_rec]u8 = undefined,
    up_out_off: usize = 0,
    up_out_len: usize = 0,

    // upstream -> client
    uin: [max_rec]u8 = undefined,
    uin_len: usize = 0,
    c_out: [2 * max_rec]u8 = undefined,
    c_out_off: usize = 0,
    c_out_len: usize = 0,

    // protocol state
    tls: client.Client = undefined,
    hs_buf: [8192]u8 = undefined,
    rl: reality.Reality = undefined,
    vstate: vision.State = undefined,
    padder: vision.Padder = undefined,
    unpadder: vision.Unpadder = undefined,
    got_resp_hdr: bool = false,
    sniff_enabled: bool = false,
    target_kind: enum { ipv4, ipv6, domain } = .domain,
    target_buf: [255]u8 = undefined,
    target_len: u8 = 0,
    target_port: u16 = 0,

    pub fn token(c: *const Conn, side: Side) u64 {
        return (@as(u64, c.gen) << 34) | (@as(u64, c.slot) << 2) | @backingInt(side);
    }

    /// Both directions switched to Vision direct copy: outer TLS is gone.
    fn fullyDirect(c: *const Conn) bool {
        return c.padder.direct and c.unpadder.direct;
    }

    fn consumeClient(c: *Conn, n: usize) void {
        mem.copyForwards(u8, c.cin[0 .. c.cin_len - n], c.cin[n..c.cin_len]);
        c.cin_len -= n;
    }
};

pub const Loop = struct {
    ep: sys.fd_t,
    cfg: *const Config,
    conns: []Conn,
    csprng: std.Random.DefaultCsprng,
    active: usize = 0,

    pub fn init(ep: sys.fd_t, cfg: *const Config, conns: []Conn) Loop {
        var seed: [32]u8 = undefined;
        sys.randomBytes(&seed);
        for (conns, 0..) |*c, i| c.* = .{ .slot = @intCast(i) };
        return .{ .ep = ep, .cfg = cfg, .conns = conns, .csprng = std.Random.DefaultCsprng.init(seed) };
    }

    // ---- lifecycle -----------------------------------------------------------

    pub fn accept(l: *Loop, fd: sys.fd_t, kind: Inbound) void {
        const c = l.findFree() orelse {
            sys.log("conn table full, dropping client", .{});
            sys.close(fd);
            return;
        };
        c.gen +%= 1;
        c.state = .socks_greeting;
        c.client_fd = fd;
        c.up_fd = -1;
        c.client_ev = 0;
        c.up_ev = 0;
        c.udp_ev = 0;
        c.is_udp = false;
        c.udp_fd = -1;
        c.udp_peer = null;
        c.udp_started = false;
        c.mux_in_len = 0;
        c.cin_len = 0;
        c.up_out_off = 0;
        c.up_out_len = 0;
        c.uin_len = 0;
        c.c_out_off = 0;
        c.c_out_len = 0;
        c.client_eof = false;
        c.up_eof = false;
        c.got_resp_hdr = false;
        c.sniff_enabled = l.cfg.sniff;
        c.last_active = sys.monotonicSeconds();
        sys.setNoDelay(fd);
        if (l.cfg.sock_buf > 0) sys.setBufferSizes(fd, l.cfg.sock_buf, l.cfg.sock_buf);
        sys.epollAdd(l.ep, fd, sys.EPOLL.IN | sys.EPOLL.RDHUP, c.token(.client)) catch {
            sys.close(fd);
            c.state = .free;
            return;
        };
        c.client_ev = sys.EPOLL.IN | sys.EPOLL.RDHUP;
        l.active += 1;

        if (kind == .redirect) {
            // Transparent (REDIRECT) inbound: the target is the original
            // destination; there is no SOCKS exchange.
            const dst = sys.originalDst(fd) catch return l.close(c, "no SO_ORIGINAL_DST");
            switch (dst) {
                .v4 => |a| {
                    c.target_kind = .ipv4;
                    c.target_buf[0..4].* = sys.SockAddr.ipv4Bytes(&a);
                    c.target_len = 4;
                },
                .v6 => |a| {
                    c.target_kind = .ipv6;
                    c.target_buf[0..16].* = a.addr;
                    c.target_len = 16;
                },
            }
            c.target_port = dst.getPort();
            l.connectUpstream(c) catch |e| return l.close(c, @errorName(e));
            l.updateInterest(c);
        }
    }

    fn findFree(l: *Loop) ?*Conn {
        for (l.conns) |*c| if (c.state == .free) return c;
        return null;
    }

    pub fn close(l: *Loop, c: *Conn, why: []const u8) void {
        if (c.state == .free) return;
        sys.log("[{d}] close: {s}", .{ c.slot, why });
        if (c.client_fd >= 0) {
            sys.epollDel(l.ep, c.client_fd);
            sys.close(c.client_fd);
            c.client_fd = -1;
        }
        if (c.up_fd >= 0) {
            sys.epollDel(l.ep, c.up_fd);
            sys.close(c.up_fd);
            c.up_fd = -1;
        }
        if (c.udp_fd >= 0) {
            sys.epollDel(l.ep, c.udp_fd);
            sys.close(c.udp_fd);
            c.udp_fd = -1;
        }
        c.state = .free;
        l.active -= 1;
    }

    /// Close connections that have been idle too long.
    pub fn sweep(l: *Loop) void {
        const now = sys.monotonicSeconds();
        for (l.conns) |*c| {
            if (c.state == .free) continue;
            const limit = if (c.state == .relay) l.cfg.idle_timeout_s else l.cfg.handshake_timeout_s;
            if (now - c.last_active > limit) l.close(c, "timeout");
        }
    }

    /// Dispatch one epoll event.
    pub fn handle(l: *Loop, tok: u64, events: u32) void {
        const slot: usize = @intCast((tok >> 2) & 0xffff_ffff);
        const gen: u30 = @intCast(tok >> 34);
        const side_bits: u2 = @intCast(tok & 3);
        if (side_bits == 3) return;
        const side: Side = @fromBackingInt(side_bits);
        if (slot >= l.conns.len) return;
        const c = &l.conns[slot];
        if (c.state == .free or c.gen != gen) return; // stale
        c.last_active = sys.monotonicSeconds();

        const fail = events & (sys.EPOLL.ERR | sys.EPOLL.HUP) != 0;
        switch (side) {
            .client => {
                if (events & sys.EPOLL.OUT != 0) l.flushClient(c) catch |e| return l.close(c, @errorName(e));
                if (events & (sys.EPOLL.IN | sys.EPOLL.RDHUP) != 0) l.readClient(c) catch |e| return l.close(c, @errorName(e));
                if (fail and c.state != .free) return l.close(c, "client hup");
            },
            .upstream => {
                if (events & sys.EPOLL.OUT != 0) l.upstreamWritable(c) catch |e| return l.close(c, @errorName(e));
                if (events & (sys.EPOLL.IN | sys.EPOLL.RDHUP) != 0) l.readUpstream(c) catch |e| switch (e) {
                    error.UpstreamEof, error.UpstreamCloseNotify => return l.upstreamDone(c),
                    else => return l.close(c, @errorName(e)),
                };
                if (fail and c.state != .free) return l.upstreamDone(c);
            },
            .udp => {
                // Unconnected UDP socket: no ERR/HUP semantics worth acting on.
                if (events & sys.EPOLL.IN != 0) l.readUdp(c) catch |e| return l.close(c, @errorName(e));
            },
        }
        if (c.state != .free) l.updateInterest(c);
    }

    /// Upstream has nothing more to send: deliver what is queued, then close.
    fn upstreamDone(l: *Loop, c: *Conn) void {
        if (c.c_out_len == 0) return l.close(c, "upstream eof");
        c.up_eof = true;
        if (c.up_fd >= 0) {
            sys.epollDel(l.ep, c.up_fd);
            sys.close(c.up_fd);
            c.up_fd = -1;
        }
        l.updateInterest(c);
    }

    /// Derive epoll interest sets from buffer state. Read a side only when the
    /// queue feeding the other side is empty.
    fn updateInterest(l: *Loop, c: *Conn) void {
        var cev: u32 = sys.EPOLL.RDHUP;
        if (c.c_out_len > 0) cev |= sys.EPOLL.OUT;
        if (c.is_udp or (!c.client_eof and c.up_out_len == 0 and c.cin_len < c.cin.len)) cev |= sys.EPOLL.IN;
        if (cev != c.client_ev) {
            sys.epollMod(l.ep, c.client_fd, cev, c.token(.client)) catch {};
            c.client_ev = cev;
        }
        if (c.udp_fd >= 0) {
            // Datagrams wait in the kernel until the tunnel is up and the
            // upstream queue is empty.
            const dev: u32 = if (c.state == .relay and c.up_out_len == 0) sys.EPOLL.IN else 0;
            if (dev != c.udp_ev) {
                sys.epollMod(l.ep, c.udp_fd, dev, c.token(.udp)) catch {};
                c.udp_ev = dev;
            }
        }
        if (c.up_fd < 0) return;
        var uev: u32 = sys.EPOLL.RDHUP;
        if (c.state == .connecting or c.up_out_len > 0) uev |= sys.EPOLL.OUT;
        if (c.state != .connecting and c.c_out_len == 0) uev |= sys.EPOLL.IN;
        if (uev != c.up_ev) {
            sys.epollMod(l.ep, c.up_fd, uev, c.token(.upstream)) catch {};
            c.up_ev = uev;
        }
    }

    // ---- client side ---------------------------------------------------------

    fn readClient(l: *Loop, c: *Conn) !void {
        if (c.client_eof) return; // RDHUP can be reported more than once
        if (c.is_udp) {
            // Control connection: nothing meaningful arrives, but its EOF ends
            // the association.
            var junk: [256]u8 = undefined;
            const n = sys.read(c.client_fd, &junk) catch |e| switch (e) {
                error.WouldBlock => return,
                else => return e,
            };
            if (n == 0) return error.UdpControlClosed;
            return;
        }
        if (c.up_out_len > 0 or c.cin_len == c.cin.len) return; // back-pressure
        const n = sys.read(c.client_fd, c.cin[c.cin_len..]) catch |e| switch (e) {
            error.WouldBlock => return,
            else => return e,
        };
        if (n == 0) {
            c.client_eof = true;
            // Nothing more to forward: let upstream finish, then close on its EOF.
            if (c.state == .relay and c.cin_len == 0 and c.up_out_len == 0) {
                if (c.fullyDirect()) sys.shutdownWrite(c.up_fd) else {
                    const rec = c.tls.close(&c.up_out) catch |e| {
                        sys.log("[{d}] tls close: {s} (tls state {s})", .{ c.slot, @errorName(e), @tagName(c.tls.state) });
                        return error.TlsClose;
                    };
                    c.up_out_off = 0;
                    c.up_out_len = rec.len;
                    try l.flushUpstream(c);
                }
            } else if (c.state != .relay) return error.ClientClosedEarly;
            return;
        }
        c.cin_len += n;
        try l.processClient(c);
    }

    fn processClient(l: *Loop, c: *Conn) !void {
        switch (c.state) {
            .socks_greeting => {
                const used = (socks5.parseGreeting(c.cin[0..c.cin_len]) catch {
                    l.queueClient(c, &socks5.greeting_reject);
                    return error.SocksGreeting;
                }) orelse return;
                c.consumeClient(used);
                l.queueClient(c, &socks5.greeting_reply);
                c.state = .socks_request;
                try l.flushClient(c);
                if (c.cin_len > 0) try l.processClient(c);
            },
            .socks_request => {
                const req = (socks5.parseRequest(c.cin[0..c.cin_len]) catch |e| {
                    l.queueClient(c, &socks5.replyForError(e));
                    l.flushClient(c) catch {};
                    return error.SocksRequest;
                }) orelse return;
                switch (req.address) {
                    .ipv4 => |a| {
                        c.target_kind = .ipv4;
                        c.target_buf[0..4].* = a;
                        c.target_len = 4;
                    },
                    .ipv6 => |a| {
                        c.target_kind = .ipv6;
                        c.target_buf[0..16].* = a;
                        c.target_len = 16;
                    },
                    .domain => |d| {
                        c.target_kind = .domain;
                        @memcpy(c.target_buf[0..d.len], d);
                        c.target_len = @intCast(d.len);
                    },
                }
                c.target_port = req.port;
                c.consumeClient(req.len);
                if (req.command == .udp_associate) {
                    try l.openUdpRelay(c);
                    try l.connectUpstream(c);
                    return;
                }
                // Reply right away (like xray) so the client starts its own TLS
                // handshake while we connect upstream; its bytes queue in `cin`.
                l.queueClient(c, &socks5.reply(.succeeded));
                try l.flushClient(c);
                try l.connectUpstream(c);
            },
            .connecting, .tls_handshake => {}, // buffer in cin until the tunnel is up
            .relay => try l.forwardClient(c),
            .free => unreachable,
        }
    }

    /// Encode everything buffered in `cin` for the upstream and start writing.
    fn forwardClient(l: *Loop, c: *Conn) !void {
        if (c.cin_len == 0 or c.up_out_len > 0) return;
        const data = c.cin[0..c.cin_len];
        if (c.padder.direct) {
            @memcpy(c.up_out[0..data.len], data);
            c.up_out_len = data.len;
        } else {
            var padded_buf: [client_chunk + 2 * vision.max_overhead]u8 = undefined;
            const padded = c.padder.pad(data, &padded_buf) catch return error.VisionPad;
            const rec = c.tls.encrypt(padded, &c.up_out) catch return error.TlsEncrypt;
            c.up_out_len = rec.len;
            if (c.padder.direct) sys.log("[{d}] vision uplink -> direct", .{c.slot});
        }
        c.up_out_off = 0;
        c.cin_len = 0;
        try l.flushUpstream(c);
    }

    // ---- UDP ASSOCIATE -------------------------------------------------------

    /// Bind a relay socket on the same local IP as the control connection and
    /// tell the client where to send datagrams.
    fn openUdpRelay(l: *Loop, c: *Conn) !void {
        var local = try sys.localAddr(c.client_fd);
        switch (local) {
            .v4 => |*a| a.port = 0,
            .v6 => |*a| a.port = 0,
        }
        const fd = try sys.udpSocket(local.family());
        errdefer sys.close(fd);
        if (l.cfg.sock_buf > 0) sys.setBufferSizes(fd, l.cfg.sock_buf, l.cfg.sock_buf);
        try sys.bind(fd, &local);
        const bound = try sys.localAddr(fd);
        try sys.epollAdd(l.ep, fd, 0, c.token(.udp));
        c.udp_fd = fd;
        c.udp_ev = 0;
        c.is_udp = true;
        c.sniff_enabled = false;
        sys.randomBytes(&c.global_id);

        var rb: [22]u8 = undefined;
        const addr: socks5.Address = switch (bound) {
            .v4 => |a| .{ .ipv4 = sys.SockAddr.ipv4Bytes(&a) },
            .v6 => |a| .{ .ipv6 = a.addr },
        };
        l.queueClient(c, socks5.replyBound(&rb, addr, bound.getPort()));
        try l.flushClient(c);
    }

    /// One datagram from the client -> one XUDP frame in one TLS record.
    fn readUdp(l: *Loop, c: *Conn) !void {
        if (c.state != .relay or c.up_out_len > 0) return;
        const dg = sys.recvFrom(c.udp_fd, &c.cin) catch |e| switch (e) {
            error.WouldBlock => return,
            else => return e,
        };
        if (c.udp_peer) |p| {
            if (!p.eql(dg.from)) return; // not our client
        } else c.udp_peer = dg.from;
        const dgram = c.cin[0..dg.len];
        const hdr = (socks5.parseUdpHeader(dgram) catch return) orelse return;
        const payload = dgram[hdr.len..];
        if (payload.len == 0 or payload.len > mux.max_packet_len) return;
        const addr: mux.Address = switch (hdr.address) {
            .ipv4 => |a| .{ .ipv4 = a },
            .ipv6 => |a| .{ .ipv6 = a },
            .domain => |d| .{ .domain = d },
        };

        var frame_buf: [client_chunk + 300]u8 = undefined;
        const frame = if (!c.udp_started)
            mux.encodeNew(&frame_buf, addr, hdr.port, c.global_id, payload) catch return
        else
            mux.encodeKeep(&frame_buf, addr, hdr.port, payload) catch return;
        c.udp_started = true;

        var padded_buf: [client_chunk + 300 + 2 * vision.max_overhead]u8 = undefined;
        const padded = c.padder.pad(frame, &padded_buf) catch return error.VisionPad;
        const rec = c.tls.encrypt(padded, &c.up_out) catch return error.TlsEncrypt;
        c.up_out_off = 0;
        c.up_out_len = rec.len;
        try l.flushUpstream(c);
    }

    /// Parse complete mux frames out of `mux_in` and hand packets to the client.
    fn drainMux(c: *Conn) !void {
        var off: usize = 0;
        while (off < c.mux_in_len) {
            const f = (mux.parse(c.mux_in[off..c.mux_in_len]) catch return error.MuxFrame) orelse break;
            off += f.len;
            switch (f.status) {
                .end => return error.UpstreamEof,
                .keep_alive, .new => continue,
                .keep => {},
            }
            if (f.data.len == 0) continue;
            const peer = c.udp_peer orelse continue;
            // Source address: what the frame says, else the association target.
            const src: socks5.Address = if (f.addr) |a| switch (a) {
                .ipv4 => |x| .{ .ipv4 = x },
                .ipv6 => |x| .{ .ipv6 = x },
                .domain => |d| .{ .domain = d },
            } else switch (c.target_kind) {
                .ipv4 => .{ .ipv4 = c.target_buf[0..4].* },
                .ipv6 => .{ .ipv6 = c.target_buf[0..16].* },
                .domain => .{ .domain = c.target_buf[0..c.target_len] },
            };
            const port = if (f.addr != null) f.port else c.target_port;
            var out: [socks5.max_udp_header_len + mux.max_packet_len]u8 = undefined;
            const h = socks5.encodeUdpHeader(&out, src, port) catch continue;
            if (h.len + f.data.len > out.len) continue;
            @memcpy(out[h.len..][0..f.data.len], f.data);
            // Best effort: a full socket buffer just drops the packet, like UDP.
            _ = sys.sendTo(c.udp_fd, out[0 .. h.len + f.data.len], &peer) catch {};
        }
        if (off > 0) {
            mem.copyForwards(u8, c.mux_in[0 .. c.mux_in_len - off], c.mux_in[off..c.mux_in_len]);
            c.mux_in_len -= off;
        }
    }

    fn queueClient(_: *Loop, c: *Conn, bytes: []const u8) void {
        if (c.c_out_len + bytes.len > c.c_out.len) return; // caller sizes guarantee this never trips
        if (c.c_out_off > 0 and c.c_out_len == 0) c.c_out_off = 0;
        @memcpy(c.c_out[c.c_out_off + c.c_out_len ..][0..bytes.len], bytes);
        c.c_out_len += bytes.len;
    }

    fn flushClient(l: *Loop, c: *Conn) !void {
        while (c.c_out_len > 0) {
            const n = sys.write(c.client_fd, c.c_out[c.c_out_off..][0..c.c_out_len]) catch |e| switch (e) {
                error.WouldBlock => return,
                else => return e,
            };
            c.c_out_off += n;
            c.c_out_len -= n;
        }
        c.c_out_off = 0;
        if (c.up_eof) return error.Done;
        // Queue drained: records still buffered in uin can now be processed.
        if (c.uin_len > 0 and c.state == .relay and !c.unpadder.direct) {
            try processRecords(c);
            if (c.c_out_len > 0) try l.flushClient(c);
        }
    }

    // ---- upstream side -------------------------------------------------------

    fn connectUpstream(l: *Loop, c: *Conn) !void {
        const fd = try sys.tcpSocket(l.cfg.server_addr.family());
        sys.setNoDelay(fd);
        if (l.cfg.sock_buf > 0) sys.setBufferSizes(fd, l.cfg.sock_buf, l.cfg.sock_buf);
        c.up_fd = fd;
        c.state = .connecting;
        const immediate = sys.connect(fd, &l.cfg.server_addr) catch |e| return e;
        const ev: u32 = sys.EPOLL.OUT | sys.EPOLL.RDHUP;
        try sys.epollAdd(l.ep, fd, ev, c.token(.upstream));
        c.up_ev = ev;
        if (immediate) try l.startTls(c);
    }

    fn upstreamWritable(l: *Loop, c: *Conn) !void {
        if (c.state == .connecting) {
            try sys.connectResult(c.up_fd);
            try l.startTls(c);
            return;
        }
        try l.flushUpstream(c);
    }

    fn startTls(l: *Loop, c: *Conn) !void {
        c.state = .tls_handshake;
        var entropy: [128]u8 = undefined;
        sys.randomBytes(&entropy);

        // REALITY: the hook back-fills session_id and the verifier checks the
        // server's REALITY auth tag. Plain TLS: standard ClientHello with a
        // random legacy_session_id and no chain verification (same posture as
        // `allowInsecure`), which is what airport vless+TLS nodes need.
        var sid: [32]u8 = undefined;
        var verifier: client.Verifier = client.Verifier.insecure;
        var hook: ?client.HelloHook = null;
        if (l.cfg.reality) |rc| {
            c.rl = reality.Reality.init(rc, sys.realtimeSeconds());
            verifier = c.rl.verifier();
            hook = c.rl.helloHook();
            sid = @splat(0);
        } else {
            l.csprng.random().bytes(&sid);
        }

        c.tls = client.Client.init(.{
            .entropy = entropy[0..64].*,
            .ml_kem_seed = entropy[64..128].*,
            .verifier = verifier,
            .handshake_buf = &c.hs_buf,
        });
        c.vstate = vision.State.init(l.cfg.uuid);
        c.padder = vision.Padder.init(&c.vstate, l.csprng.random());
        c.unpadder = vision.Unpadder.init(&c.vstate);

        var fp: fingerprint.Chrome = undefined;
        fp.build(l.csprng.random(), .{
            .sni = l.cfg.sni,
            .x25519_public = c.tls.publicKey(),
            .ml_kem_public = c.tls.mlKemPublicKey(),
            // Only offer compressed certificates to REALITY servers; a plain
            // TLS upstream may compress in a form this client does not parse.
            .compress_certificate = l.cfg.reality != null,
        });
        const first = c.tls.clientHello(&c.up_out, .{
            .random = undefined,
            .session_id = &sid,
            .cipher_suites = fp.cipherSuites(),
            .extensions = fp.extensions(),
        }, hook) catch return error.ClientHello;
        if (l.cfg.reality != null and c.rl.err != null) return error.RealityHook;
        c.up_out_off = 0;
        c.up_out_len = first.len;
        try l.flushUpstream(c);
    }

    fn flushUpstream(_: *Loop, c: *Conn) !void {
        while (c.up_out_len > 0) {
            const n = sys.write(c.up_fd, c.up_out[c.up_out_off..][0..c.up_out_len]) catch |e| switch (e) {
                error.WouldBlock => return,
                else => return e,
            };
            c.up_out_off += n;
            c.up_out_len -= n;
        }
        c.up_out_off = 0;
    }

    fn readUpstream(l: *Loop, c: *Conn) !void {
        if (c.c_out_len > 0) return; // back-pressure
        if (c.state == .relay and c.unpadder.direct) {
            // Raw inner stream: straight copy.
            const n = sys.read(c.up_fd, c.c_out[0..max_rec]) catch |e| switch (e) {
                error.WouldBlock => return,
                else => return e,
            };
            if (n == 0) return error.UpstreamEof;
            c.c_out_off = 0;
            c.c_out_len = n;
            try l.flushClient(c);
            return;
        }
        if (c.uin_len == c.uin.len) return error.RecordTooLarge;
        const n = sys.read(c.up_fd, c.uin[c.uin_len..]) catch |e| switch (e) {
            error.WouldBlock => return,
            else => return e,
        };
        if (n == 0) return error.UpstreamEof;
        c.uin_len += n;
        try l.processUpstream(c);
    }

    fn processUpstream(l: *Loop, c: *Conn) !void {
        try processRecords(c);
        if (c.c_out_len > 0) try l.flushClient(c);
        if (c.up_out_len > 0) try l.flushUpstream(c);
        if (c.state == .relay and c.cin_len > 0) try l.forwardClient(c);
    }

    /// Consume complete outer records from `uin`. Stops when `c_out` has data
    /// (one record's worth) so back-pressure applies per record.
    fn processRecords(c: *Conn) !void {
        while (c.uin_len >= record.header_len and c.c_out_len == 0) {
            // We already sent close_notify; whatever arrives now is the peer's.
            if (c.tls.state == .closed) return error.UpstreamCloseNotify;
            const hdr = record.Header.parse(c.uin[0..record.header_len]);
            const total = record.header_len + hdr.len;
            if (total > c.uin.len) return error.RecordTooLarge;
            if (c.uin_len < total) break;

            var scratch: [max_rec]u8 = undefined;
            const res = c.tls.handleRecord(c.uin[0..total], &scratch) catch |e| {
                if (c.tls.last_alert) |a| sys.log("[{d}] tls alert {s}", .{ c.slot, @tagName(a.description) });
                return e;
            };
            if (res.to_send.len > 0) {
                if (c.up_out_len + res.to_send.len > c.up_out.len) return error.UpstreamQueueFull;
                @memcpy(c.up_out[c.up_out_off + c.up_out_len ..][0..res.to_send.len], res.to_send);
                c.up_out_len += res.to_send.len;
            }
            if (res.event == .close_notify) return error.UpstreamCloseNotify;
            if (res.event == .handshake_complete) try sendVlessRequest(c);

            var data = res.app_data;
            if (c.state == .relay and data.len > 0) {
                if (!c.got_resp_hdr) {
                    const resp = (vless.parseResponse(data) catch return error.VlessResponse) orelse return error.VlessResponse;
                    c.got_resp_hdr = true;
                    data = data[resp.len..];
                }
                const content = c.unpadder.feed(data);
                if (c.is_udp) {
                    if (c.mux_in_len + content.len > c.mux_in.len) return error.MuxFrameTooLarge;
                    @memcpy(c.mux_in[c.mux_in_len..][0..content.len], content);
                    c.mux_in_len += content.len;
                    try drainMux(c);
                } else {
                    @memcpy(c.c_out[0..content.len], content);
                    c.c_out_off = 0;
                    c.c_out_len = content.len;
                }
            }

            // Drop the consumed record.
            const rest = c.uin_len - total;
            mem.copyForwards(u8, c.uin[0..rest], c.uin[total..c.uin_len]);
            c.uin_len = rest;

            if (c.state == .relay and c.unpadder.direct) {
                if (c.is_udp) return error.UnexpectedDirect; // mux is never TLS-in-TLS
                sys.log("[{d}] vision downlink -> direct", .{c.slot});
                // Whatever is left in uin is already the raw inner stream.
                @memcpy(c.c_out[c.c_out_len..][0..c.uin_len], c.uin[0..c.uin_len]);
                c.c_out_len += c.uin_len;
                c.uin_len = 0;
                return;
            }
        }
    }

    /// Outer handshake done: VLESS header + first payload (or an empty
    /// padding block) in one record.
    fn sendVlessRequest(c: *Conn) !void {
        c.state = .relay;
        var buf: [vless.max_request_len + client_chunk + 2 * vision.max_overhead]u8 = undefined;
        var addr: vless.Address = switch (c.target_kind) {
            .ipv4 => .{ .ipv4 = c.target_buf[0..4].* },
            .ipv6 => .{ .ipv6 = c.target_buf[0..16].* },
            .domain => .{ .domain = c.target_buf[0..c.target_len] },
        };
        if (c.is_udp) {
            // XUDP: everything rides one Mux stream; targets live in the frames.
            const hdr = vless.encodeRequest(&buf, .{
                .uuid = c.vstate.uuid,
                .flow = .vision,
                .command = .mux,
                .address = .{ .domain = "v1.mux.cool" },
                .port = 666,
            }) catch return error.VlessRequest;
            const padded = c.padder.padEmpty(buf[hdr.len..]) catch return error.VisionPad;
            try queueUpstreamRecord(c, buf[0 .. hdr.len + padded.len]);
            return;
        }
        if (c.sniff_enabled and c.target_kind != .domain and c.cin_len > 0) {
            switch (sniff.sniff(c.cin[0..c.cin_len])) {
                .host => |h| {
                    sys.log("[{d}] sniffed {s}:{d}", .{ c.slot, h, c.target_port });
                    addr = .{ .domain = h };
                },
                else => {},
            }
        }
        const hdr = vless.encodeRequest(&buf, .{
            .uuid = c.vstate.uuid,
            .flow = .vision,
            .address = addr,
            .port = c.target_port,
        }) catch return error.VlessRequest;
        var n = hdr.len;
        const padded = if (c.cin_len > 0)
            c.padder.pad(c.cin[0..c.cin_len], buf[n..]) catch return error.VisionPad
        else
            c.padder.padEmpty(buf[n..]) catch return error.VisionPad;
        n += padded.len;
        c.cin_len = 0;
        try queueUpstreamRecord(c, buf[0..n]);
    }

    /// Encrypt and append behind whatever is already queued in `up_out`
    /// (the client Finished, typically).
    fn queueUpstreamRecord(c: *Conn, plaintext: []const u8) !void {
        var rec_buf: [max_rec]u8 = undefined;
        const rec = c.tls.encrypt(plaintext, &rec_buf) catch return error.TlsEncrypt;
        if (c.up_out_off + c.up_out_len + rec.len > c.up_out.len) return error.UpstreamQueueFull;
        @memcpy(c.up_out[c.up_out_off + c.up_out_len ..][0..rec.len], rec);
        c.up_out_len += rec.len;
    }
};
