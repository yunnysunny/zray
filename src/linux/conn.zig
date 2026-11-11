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
const ws = @import("../proxy/ws.zig");

const max_rec = tls.max_ciphertext_record_len;
/// Largest chunk read from the SOCKS client per event (xray uses 8 KiB).
const client_chunk = 8192;

pub const max_outbounds = 16;
/// ob_index[i..][0..1] is a static one-element group for outbound i.
const ob_index = blk: {
    var a: [max_outbounds]u8 = undefined;
    for (&a, 0..) |*x, i| x.* = i;
    break :blk a;
};

/// One upstream node.
pub const Outbound = struct {
    tag: []const u8 = "",
    /// Where the TCP connection goes: the server itself, or (chained) the
    /// local hop listener served by the dialer outbound.
    addr: sys.SockAddr,
    /// Chained: SOCKS5 CONNECT to hop_host:hop_port through `addr` first.
    hop_host: []const u8 = "",
    hop_port: u16 = 0,
    sni: []const u8,
    /// null: plain TLS 1.3 (SNI only, certificate chain not verified).
    reality: ?reality.Config = null,
    uuid: [16]u8,
    /// xtls-rprx-vision (the original zray behaviour) or no flow.
    vision: bool = true,
    /// WebSocket transport (inside TLS).
    ws: bool = false,
    ws_path: []const u8 = "/",
    ws_host: []const u8 = "",
};

/// Domains ending in one of `suffixes` go to the first healthy outbound of
/// `group` (indices into Config.outbounds).
pub const Rule = struct {
    suffixes: []const []const u8,
    group: []const u8,
};

pub const Config = struct {
    outbounds: []const Outbound,
    rules: []const Rule = &.{},
    default_group: []const u8,
    handshake_timeout_s: u64 = 15,
    idle_timeout_s: u64 = 600,
    /// Hard deadline for one upstream attempt (TCP connect, hop SOCKS, TLS,
    /// WS upgrade). Not extended by traffic; on expiry the next member is tried.
    connect_timeout_s: u64 = 5,
    /// Per-socket SO_RCVBUF / SO_SNDBUF; 0 = kernel default.
    sock_buf: i32 = 0,
    /// Replace redirected IP targets with the sniffed TLS SNI / HTTP Host.
    sniff: bool = true,
    /// Seconds an outbound is skipped after it failed to connect.
    fail_backoff_s: u64 = 30,
    stats_interval_s: u64 = 60,
};

/// Does `host` equal `suffix` or end in ".suffix"? (ASCII case-insensitive)
pub fn domainMatch(host: []const u8, suffix: []const u8) bool {
    if (host.len < suffix.len) return false;
    const tail = host[host.len - suffix.len ..];
    if (!std.ascii.eqlIgnoreCase(tail, suffix)) return false;
    return host.len == suffix.len or host[host.len - suffix.len - 1] == '.';
}

pub fn routeFor(cfg: *const Config, host: ?[]const u8) []const u8 {
    const h = host orelse return cfg.default_group;
    for (cfg.rules) |r| for (r.suffixes) |suf| if (domainMatch(h, suf)) return r.group;
    return cfg.default_group;
}

test "domain suffix match" {
    try std.testing.expect(domainMatch("chatgpt.com", "chatgpt.com"));
    try std.testing.expect(domainMatch("ab.chatgpt.com", "chatgpt.com"));
    try std.testing.expect(domainMatch("AB.ChatGPT.com", "chatgpt.com"));
    try std.testing.expect(!domainMatch("notchatgpt.com", "chatgpt.com"));
    try std.testing.expect(!domainMatch("x.ai.com", "x.ai"));
}

pub const Inbound = enum { socks5, redirect };

pub const Side = enum(u2) { client = 0, upstream = 1, udp = 2 };

pub const State = enum {
    free,
    socks_greeting,
    socks_request,
    /// Waiting for the first client bytes to pick an outbound by SNI/Host.
    sniffing,
    connecting,
    /// Chained outbound: waiting for the local hop's SOCKS5 replies.
    socks_dial,
    tls_handshake,
    /// TLS up, HTTP Upgrade sent, waiting for 101.
    ws_upgrade,
    relay,
};

/// Snapshot of a hop connection, used to say which leg of a chain failed.
pub const HopEnd = struct {
    ob: u8,
    state: State,
    got_resp_hdr: bool,
    why: []const u8,
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
    up_write_closed: bool = false,
    client_write_closed: bool = false,

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

    // outbound selection
    /// Candidate outbounds (static slice into Config) and attempts so far.
    group: []const u8 = &.{},
    tries: u8 = 0,
    tried_mask: u16 = 0,
    ob: u8 = 0,
    /// Pinned outbound (hop listener connections).
    forced: ?u8 = null,
    /// Loopback port pairing a chained connection with its hop connection.
    /// Chained side: local port of up_fd (0 = outbound not chained).
    chain_lport: u16 = 0,
    /// Hop side: peer port of client_fd (0 = not a hop connection).
    hop_peer: u16 = 0,
    /// Chained side: how the paired hop connection ended, if it already did.
    hop_end: ?HopEnd = null,
    /// When sniffing started (ms).
    sniff_since_ms: u64 = 0,
    /// Current upstream attempt must reach .relay before this (ms).
    attempt_deadline_ms: u64 = 0,
    vision_on: bool = true,
    ws_on: bool = false,
    wsd: ws.Deframer = .{},
    ws_hs_len: usize = 0,

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

/// The running config (single-threaded; set by Loop.init) so the
/// free-standing record helpers can reach the current outbound.
var cur_cfg: ?*const Config = null;

pub const Loop = struct {
    ep: sys.fd_t,
    cfg: *const Config,
    conns: []Conn,
    csprng: std.Random.DefaultCsprng,
    active: usize = 0,
    bad_until: [max_outbounds]u64 = @splat(0),

    pub fn init(ep: sys.fd_t, cfg: *const Config, conns: []Conn) Loop {
        cur_cfg = cfg;
        var seed: [32]u8 = undefined;
        sys.randomBytes(&seed);
        for (conns, 0..) |*c, i| c.* = .{ .slot = @intCast(i) };
        return .{ .ep = ep, .cfg = cfg, .conns = conns, .csprng = std.Random.DefaultCsprng.init(seed) };
    }

    // ---- lifecycle -----------------------------------------------------------

    pub fn accept(l: *Loop, fd: sys.fd_t, kind: Inbound, forced: ?u8) void {
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
        c.up_write_closed = false;
        c.client_write_closed = false;
        c.got_resp_hdr = false;
        c.sniff_enabled = l.cfg.sniff and forced == null;
        c.forced = forced;
        c.tries = 0;
        c.tried_mask = 0;
        c.group = &.{};
        c.last_active = sys.monotonicSeconds();
        c.attempt_deadline_ms = 0;
        c.hop_end = null;
        c.chain_lport = 0;
        c.hop_peer = if (forced == null) 0 else if (sys.peerAddr(fd)) |a| a.getPort() else |_| 0;
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
            l.routeOrSniff(c) catch |e| return l.close(c, @errorName(e));
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
        if (c.hop_peer != 0) {
            if (l.findChained(c.hop_peer)) |a| a.hop_end = .{ .ob = c.ob, .state = c.state, .got_resp_hdr = c.got_resp_hdr, .why = why };
        }
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
        const now_ms = sys.monotonicMs();
        for (l.conns) |*c| {
            if (c.state == .free) continue;
            if (c.state == .sniffing and now_ms - c.sniff_since_ms >= 1000) {
                // Server-first protocol (or a slow client): use the default route.
                c.group = l.cfg.default_group;
                l.startUpstream(c) catch |e| {
                    l.close(c, @errorName(e));
                    continue;
                };
                l.updateInterest(c);
                continue;
            }
            if (l.preRelay(c)) {
                if (now_ms >= c.attempt_deadline_ms) l.retryAndUpdate(c, "connect timeout");
                continue;
            }
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
        switch (side) {
            .client => {
                if (events & sys.EPOLL.OUT != 0) l.flushClient(c) catch |e| return l.close(c, @errorName(e));
                if (c.state == .free) return;
                if (events & (sys.EPOLL.IN | sys.EPOLL.RDHUP | sys.EPOLL.HUP) != 0) l.readClient(c) catch |e| return l.close(c, @errorName(e));
                if (events & sys.EPOLL.ERR != 0 and c.state != .free) return l.close(c, "client error");
            },
            .upstream => {
                if (events & sys.EPOLL.OUT != 0) l.upstreamWritable(c) catch |e| {
                    if (l.preRelay(c)) return l.retryAndUpdate(c, @errorName(e));
                    return l.close(c, @errorName(e));
                };
                if (events & (sys.EPOLL.IN | sys.EPOLL.RDHUP | sys.EPOLL.HUP) != 0) l.readUpstream(c) catch |e| {
                    if (l.preRelay(c)) return l.retryAndUpdate(c, @errorName(e));
                    switch (e) {
                        error.UpstreamEof, error.UpstreamCloseNotify => return l.upstreamDone(c),
                        else => return l.close(c, @errorName(e)),
                    }
                };
                if (events & sys.EPOLL.ERR != 0 and c.state != .free) {
                    if (l.preRelay(c)) return l.retryAndUpdate(c, "upstream hup");
                    return l.upstreamDone(c);
                }
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
        c.up_eof = true;
        l.finishDirections(c) catch |e| return l.close(c, @errorName(e));
        if (c.state == .free) return;
        l.updateInterest(c);
    }

    fn finishDirections(l: *Loop, c: *Conn) (sys.Error || client.Error)!void {
        if (c.up_eof and c.c_out_len == 0 and !c.client_write_closed) {
            sys.shutdownWrite(c.client_fd);
            c.client_write_closed = true;
        }
        if (c.client_eof and c.cin_len == 0 and c.up_out_len == 0 and !c.up_write_closed and c.state == .relay) {
            c.up_write_closed = true;
            if (c.padder.direct) sys.shutdownWrite(c.up_fd) else {
                const rec = try c.tls.close(&c.up_out);
                c.up_out_off = 0;
                c.up_out_len = rec.len;
                try l.flushUpstream(c);
            }
        }
        if (c.client_eof and c.up_eof and c.cin_len == 0 and c.c_out_len == 0 and c.up_out_len == 0) l.close(c, "eof");
    }

    /// Derive epoll interest sets from buffer state. Read a side only when the
    /// queue feeding the other side is empty.
    fn updateInterest(l: *Loop, c: *Conn) void {
        var cev: u32 = 0;
        if (c.c_out_len > 0) cev |= sys.EPOLL.OUT;
        if (c.is_udp or (!c.client_eof and c.up_out_len == 0 and c.cin_len < c.cin.len)) cev |= sys.EPOLL.IN | sys.EPOLL.RDHUP;
        if (cev != c.client_ev) {
            l.setInterest(c.client_fd, &c.client_ev, cev, c.token(.client));
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
        var uev: u32 = 0;
        if (c.state == .connecting or c.up_out_len > 0 or (c.state == .relay and c.cin_len > 0 and c.padder.direct)) uev |= sys.EPOLL.OUT;
        if (!c.up_eof and c.state != .connecting and c.c_out_len == 0) uev |= sys.EPOLL.IN | sys.EPOLL.RDHUP;
        if (uev != c.up_ev) {
            l.setInterest(c.up_fd, &c.up_ev, uev, c.token(.upstream));
        }
    }

    // An empty mask still receives HUP/ERR. Remove blocked sockets entirely,
    // and re-add them when the opposite queue drains so EOF remains observable.
    fn setInterest(l: *Loop, fd: sys.fd_t, old: *u32, next: u32, tok: u64) void {
        if (next == old.*) return;
        if (next == 0) {
            sys.epollDel(l.ep, fd);
        } else if (old.* == 0) {
            sys.epollAdd(l.ep, fd, next, tok) catch return;
        } else {
            sys.epollMod(l.ep, fd, next, tok) catch return;
        }
        old.* = next;
    }

    // ---- client side ---------------------------------------------------------

    fn readClient(l: *Loop, c: *Conn) !void {
        for (0..16) |_| {
            const reads = sys.counters.reads;
            try l.readClientOnce(c);
            if (c.state != .relay or c.client_eof or c.up_out_len > 0 or c.cin_len > 0 or sys.counters.reads == reads) break;
        }
    }

    fn readClientOnce(l: *Loop, c: *Conn) !void {
        if (c.client_eof) return; // RDHUP can be reported more than once
        if (c.state == .relay and !c.is_udp and c.padder.direct and c.cin_len == 0 and c.up_out_len == 0) {
            // Read straight into the transmit queue: no cin -> up_out copy.
            const n = sys.read(c.client_fd, &c.up_out) catch |err| switch (err) {
                error.WouldBlock, error.Interrupted => return,
                else => return err,
            };
            if (n > 0) c.last_active = sys.monotonicSeconds();
            if (n == 0) {
                c.client_eof = true;
                return l.finishDirections(c);
            }
            c.up_out_off = 0;
            c.up_out_len = n;
            return l.flushUpstream(c);
        }

        if (c.is_udp) {
            // Control connection: nothing meaningful arrives, but its EOF ends
            // the association.
            var junk: [256]u8 = undefined;
            const n = sys.read(c.client_fd, &junk) catch |e| switch (e) {
                error.WouldBlock => return,
                else => return e,
            };
            if (n > 0) c.last_active = sys.monotonicSeconds();
            if (n == 0) return error.UdpControlClosed;
            return;
        }
        if (c.up_out_len > 0 or c.cin_len == c.cin.len) return; // back-pressure
        const n = sys.read(c.client_fd, c.cin[c.cin_len..]) catch |e| switch (e) {
            error.WouldBlock => return,
            else => return e,
        };
        if (n > 0) c.last_active = sys.monotonicSeconds();
        if (n == 0) {
            c.client_eof = true;
            // Hop connection whose chained outbound gave up before the relay
            // answered (dead exit): nobody is left to read the reply, and the
            // relay may keep dialing for a minute. Free the slot now.
            if (c.forced != null and !c.got_resp_hdr) return error.HopClientGone;
            if (c.state == .relay) try l.finishDirections(c) else return error.ClientClosedEarly;
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
                    c.group = l.cfg.default_group;
                    if (c.forced) |f| c.group = ob_index[f..][0..1];
                    try l.startUpstream(c);
                    return;
                }
                // Reply right away (like xray) so the client starts its own TLS
                // handshake while we connect upstream; its bytes queue in `cin`.
                l.queueClient(c, &socks5.reply(.succeeded));
                try l.flushClient(c);
                try l.routeOrSniff(c);
            },
            .sniffing => try l.sniffRoute(c),
            .connecting, .socks_dial, .tls_handshake, .ws_upgrade => {}, // buffer in cin until the tunnel is up
            .relay => try l.forwardClient(c),
            .free => unreachable,
        }
    }

    /// Encode everything buffered in `cin` for the upstream and start writing.
    fn forwardClient(l: *Loop, c: *Conn) !void {
        if (c.cin_len == 0 or c.up_out_len > 0) return;
        const data = c.cin[0..c.cin_len];
        if (c.padder.direct) {
            const n = sys.write(c.up_fd, data) catch |err| switch (err) {
                error.WouldBlock, error.Interrupted => return,
                else => return err,
            };
            if (n > 0) c.last_active = sys.monotonicSeconds();
            c.consumeClient(n);
            return l.finishDirections(c);
        } else {
            var padded_buf: [ws.max_header_len + client_chunk + 2 * vision.max_overhead]u8 = undefined;
            const off = ws.max_header_len;
            const padded = if (c.vision_on)
                c.padder.pad(data, padded_buf[off..]) catch return error.VisionPad
            else blk: {
                @memcpy(padded_buf[off..][0..data.len], data);
                break :blk padded_buf[off..][0..data.len];
            };
            const plain = if (c.ws_on) ws.frameInPlace(&padded_buf, off, padded.len, maskOf(c)) else padded;
            const rec = c.tls.encrypt(plain, &c.up_out) catch return error.TlsEncrypt;
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
        if (dg.len > 0) c.last_active = sys.monotonicSeconds();
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
            if (n > 0) c.last_active = sys.monotonicSeconds();
            c.c_out_off += n;
            c.c_out_len -= n;
        }
        c.c_out_off = 0;
        if (c.state == .relay) {
            try l.finishDirections(c);
            if (c.state == .free) return;
        }
        // Queue drained: records still buffered in uin can now be processed.
        if (c.uin_len > 0 and c.state == .relay and !c.unpadder.direct) {
            try processRecords(c);
            if (c.c_out_len > 0) try l.flushClient(c);
        }
    }

    // ---- upstream side -------------------------------------------------------

    /// Pick the outbound now if the target already tells us (domain, pinned,
    /// or no routing rules); otherwise wait for the first client bytes.
    fn routeOrSniff(l: *Loop, c: *Conn) !void {
        if (c.forced) |f| {
            c.group = ob_index[f..][0..1];
        } else if (c.target_kind == .domain) {
            c.group = routeFor(l.cfg, c.target_buf[0..c.target_len]);
        } else if (l.cfg.rules.len == 0 or !c.sniff_enabled) {
            c.group = l.cfg.default_group;
        } else {
            c.state = .sniffing;
            c.sniff_since_ms = sys.monotonicMs();
            if (c.cin_len > 0) try l.sniffRoute(c);
            return;
        }
        try l.startUpstream(c);
    }

    fn sniffRoute(l: *Loop, c: *Conn) error{AllOutboundsFailed}!void {
        const r = sniff.sniff(c.cin[0..c.cin_len]);
        if (r == .need_more and c.cin_len < c.cin.len) return;
        c.group = routeFor(l.cfg, if (r == .host) r.host else null);
        if (r == .host) sys.log("[{d}] route {s} -> {s}", .{ c.slot, r.host, l.cfg.outbounds[c.group[0]].tag });
        try l.startUpstream(c);
    }

    fn preRelay(_: *Loop, c: *const Conn) bool {
        return switch (c.state) {
            .connecting, .socks_dial, .tls_handshake, .ws_upgrade => true,
            else => false,
        };
    }

    /// Try group members: the first attempt takes the first healthy member
    /// (or, if all are in backoff, the first member as a probe); failover
    /// only moves to untried healthy members, so a dead group costs one
    /// attempt instead of one per member.
    fn startUpstream(l: *Loop, c: *Conn) !void {
        const now = sys.monotonicSeconds();
        while (c.tries < c.group.len) {
            var order: [max_outbounds]u8 = undefined;
            var n: usize = 0;
            for (c.group) |i| if (l.bad_until[i] <= now) {
                order[n] = i;
                n += 1;
            };
            const n_healthy = n;
            for (c.group) |i| if (l.bad_until[i] > now) {
                order[n] = i;
                n += 1;
            };
            // Members already tried were marked bad and moved to the back.
            const k = if (c.tries == 0) 0 else firstUntried(order[0..n_healthy], c) orelse break;
            const i = order[k];
            c.tries += 1;
            c.ob = i;
            c.tried_mask |= @as(u16, 1) << @intCast(i);
            l.connectUpstream(c) catch |e| {
                l.markBad(c, @errorName(e));
                l.dropUpstream(c);
                continue;
            };
            return;
        }
        return error.AllOutboundsFailed;
    }

    /// Silence or a dropped stream: could be either leg of a chain.
    fn isTransportFailure(why: []const u8) bool {
        const names = [_][]const u8{ "connect timeout", "upstream hup", "UpstreamEof", "UpstreamCloseNotify", "ConnectionReset", "BrokenPipe", "HopSocksRejected" };
        for (names) |n| if (mem.eql(u8, why, n)) return true;
        return false;
    }

    /// Which leg of a chain was stuck, judged from the hop connection.
    fn hopLeg(e: HopEnd) []const u8 {
        return switch (e.state) {
            .socks_greeting, .socks_request => "hop: SOCKS not finished -> local",
            .connecting => "TCP connect pending -> relay side",
            .socks_dial, .tls_handshake, .ws_upgrade => "handshake pending -> relay side",
            .relay => if (e.got_resp_hdr) "up, exit replied -> exit side" else "up, no reply from exit -> exit side",
            else => @tagName(e.state),
        };
    }

    /// The chained connection (still attempting) that owns hop port `p`.
    fn findChained(l: *Loop, p: u16) ?*Conn {
        for (l.conns) |*a| if (a.state != .free and a.chain_lport == p and l.preRelay(a) and a.up_fd >= 0) return a;
        return null;
    }

    /// The live hop connection accepted from local port `p`.
    fn findHop(l: *Loop, p: u16) ?*Conn {
        for (l.conns) |*b| if (b.state != .free and b.hop_peer == p) return b;
        return null;
    }

    fn firstUntried(order: []const u8, c: *const Conn) ?usize {
        for (order, 0..) |i, k| if (c.tried_mask & (@as(u16, 1) << @intCast(i)) == 0) return k;
        return null;
    }

    fn markBad(l: *Loop, c: *Conn, why: []const u8) void {
        const tag = l.cfg.outbounds[c.ob].tag;
        if (c.chain_lport != 0 and !isTransportFailure(why)) {
            // The exit's handshake itself failed (bad reply, rejected key,
            // config): the relay leg is irrelevant.
            sys.log("[{d}] outbound {s} failed: {s}; exit handshake error -> exit side", .{ c.slot, tag, why });
        } else if (c.chain_lport != 0) {
            const end: ?HopEnd = c.hop_end orelse if (l.findHop(c.chain_lport)) |b|
                HopEnd{ .ob = b.ob, .state = b.state, .got_resp_hdr = b.got_resp_hdr, .why = "" }
            else
                null;
            if (end) |e| {
                const relay = l.cfg.outbounds[e.ob].tag;
                const leg = hopLeg(e);
                if (e.why.len > 0)
                    sys.log("[{d}] outbound {s} failed: {s}; {s} {s} (hop closed: {s})", .{ c.slot, tag, why, relay, leg, e.why })
                else
                    sys.log("[{d}] outbound {s} failed: {s}; {s} {s}", .{ c.slot, tag, why, relay, leg });
            } else sys.log("[{d}] outbound {s} failed: {s}; hop connection never accepted", .{ c.slot, tag, why });
        } else sys.log("[{d}] outbound {s} failed: {s}", .{ c.slot, tag, why });
        l.bad_until[c.ob] = sys.monotonicSeconds() + l.cfg.fail_backoff_s;
    }

    fn dropUpstream(l: *Loop, c: *Conn) void {
        if (c.up_fd >= 0) {
            sys.epollDel(l.ep, c.up_fd);
            sys.close(c.up_fd);
            c.up_fd = -1;
        }
        c.up_ev = 0;
        c.up_out_off = 0;
        c.up_out_len = 0;
        c.uin_len = 0;
    }

    /// Handshake with the current outbound failed: move to the next one.
    /// Nothing from cin has been sent yet, so the client sees no difference.
    fn retry(l: *Loop, c: *Conn, why: []const u8) void {
        l.markBad(c, why);
        l.dropUpstream(c);
        if (c.tries >= c.group.len) return l.close(c, why);
        l.startUpstream(c) catch |e| return l.close(c, @errorName(e));
    }

    fn retryAndUpdate(l: *Loop, c: *Conn, why: []const u8) void {
        l.retry(c, why);
        if (c.state != .free) l.updateInterest(c);
    }

    fn connectUpstream(l: *Loop, c: *Conn) !void {
        const ob = &l.cfg.outbounds[c.ob];
        if (c.is_udp and (!ob.vision or ob.ws)) return error.UdpNeedsVisionTcp;
        const fd = try sys.tcpSocket(ob.addr.family());
        sys.setNoDelay(fd);
        if (l.cfg.sock_buf > 0) sys.setBufferSizes(fd, l.cfg.sock_buf, l.cfg.sock_buf);
        c.up_fd = fd;
        c.state = .connecting;
        c.uin_len = 0;
        c.up_out_off = 0;
        c.up_out_len = 0;
        c.last_active = sys.monotonicSeconds();
        c.attempt_deadline_ms = sys.monotonicMs() + l.cfg.connect_timeout_s * 1000;
        c.hop_end = null;
        c.chain_lport = 0;
        const immediate = try sys.connect(fd, &ob.addr);
        if (ob.hop_host.len > 0) c.chain_lport = if (sys.localAddr(fd)) |a| a.getPort() else |_| 0;
        const ev: u32 = sys.EPOLL.OUT | sys.EPOLL.RDHUP;
        try sys.epollAdd(l.ep, fd, ev, c.token(.upstream));
        c.up_ev = ev;
        if (immediate) try l.connected(c);
    }

    fn connected(l: *Loop, c: *Conn) !void {
        const ob = &l.cfg.outbounds[c.ob];
        if (ob.hop_host.len == 0) return l.startTls(c);
        // Pipelined SOCKS5 greeting + CONNECT hop_host:hop_port to the local hop.
        c.state = .socks_dial;
        const h = ob.hop_host;
        c.up_out[0..3].* = .{ 5, 1, 0 };
        c.up_out[3..8].* = .{ 5, 1, 0, 3, @intCast(h.len) };
        @memcpy(c.up_out[8..][0..h.len], h);
        mem.writeInt(u16, c.up_out[8 + h.len ..][0..2], ob.hop_port, .big);
        c.up_out_off = 0;
        c.up_out_len = 10 + h.len;
        try l.flushUpstream(c);
    }

    /// Parse the hop's greeting reply + CONNECT reply out of uin.
    fn socksDialReply(l: *Loop, c: *Conn) !void {
        const b = c.uin[0..c.uin_len];
        if (b.len < 2 + 5) return;
        if (b[0] != 5 or b[1] != 0 or b[2] != 5 or b[3] != 0) return error.HopSocksRejected;
        const alen: usize = switch (b[5]) {
            1 => 4,
            4 => 16,
            3 => 1 + @as(usize, b[6]),
            else => return error.HopSocksRejected,
        };
        const total = 2 + 4 + alen + 2;
        if (b.len < total) return;
        if (b.len > total) return error.HopSocksRejected; // server spoke before TLS
        c.uin_len = 0;
        try l.startTls(c);
    }

    fn upstreamWritable(l: *Loop, c: *Conn) !void {
        if (c.state == .connecting) {
            try sys.connectResult(c.up_fd);
            try l.connected(c);
            return;
        }
        try l.flushUpstream(c);
        if (c.state == .relay) {
            if (c.cin_len > 0) try l.forwardClient(c);
            try l.finishDirections(c);
        }
    }

    fn startTls(l: *Loop, c: *Conn) !void {
        const ob = &l.cfg.outbounds[c.ob];
        c.state = .tls_handshake;
        c.vision_on = ob.vision;
        c.ws_on = ob.ws;
        c.wsd = .{};
        c.ws_hs_len = 0;
        var entropy: [128]u8 = undefined;
        sys.randomBytes(&entropy);

        // REALITY: the hook back-fills session_id and the verifier checks the
        // server's REALITY auth tag. Plain TLS: standard ClientHello with a
        // random legacy_session_id and no chain verification (same posture as
        // `allowInsecure`), which is what airport vless+TLS nodes need.
        var sid: [32]u8 = undefined;
        var verifier: client.Verifier = client.Verifier.insecure;
        var hook: ?client.HelloHook = null;
        if (ob.reality) |rc| {
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
        c.vstate = vision.State.init(ob.uuid);
        c.padder = vision.Padder.init(&c.vstate, l.csprng.random());
        c.unpadder = vision.Unpadder.init(&c.vstate);

        var fp: fingerprint.Chrome = undefined;
        fp.build(l.csprng.random(), .{
            .sni = ob.sni,
            // WebSocket needs HTTP/1.1; an h2 ALPN answer would break the Upgrade.
            .alpn = if (ob.ws) &fingerprint.alpn_http11 else &fingerprint.alpn_h2_http11,
            .x25519_public = c.tls.publicKey(),
            .ml_kem_public = c.tls.mlKemPublicKey(),
            // Only offer compressed certificates to REALITY servers; a plain
            // TLS upstream may compress in a form this client does not parse.
            .compress_certificate = ob.reality != null,
        });
        const first = c.tls.clientHello(&c.up_out, .{
            .random = undefined,
            .session_id = &sid,
            .cipher_suites = fp.cipherSuites(),
            .extensions = fp.extensions(),
        }, hook) catch return error.ClientHello;
        if (ob.reality != null and c.rl.err != null) return error.RealityHook;
        c.up_out_off = 0;
        c.up_out_len = first.len;
        try l.flushUpstream(c);
    }

    fn flushUpstream(l: *Loop, c: *Conn) !void {
        while (c.up_out_len > 0) {
            const n = sys.write(c.up_fd, c.up_out[c.up_out_off..][0..c.up_out_len]) catch |e| switch (e) {
                error.WouldBlock => return,
                else => return e,
            };
            if (n > 0) c.last_active = sys.monotonicSeconds();
            c.up_out_off += n;
            c.up_out_len -= n;
        }
        c.up_out_off = 0;
        if (c.state == .relay) try l.finishDirections(c);
    }

    fn readUpstream(l: *Loop, c: *Conn) !void {
        for (0..16) |_| {
            const reads = sys.counters.reads;
            try l.readUpstreamOnce(c);
            if (c.state != .relay or c.up_eof or c.c_out_len > 0 or sys.counters.reads == reads) break;
        }
    }

    fn readUpstreamOnce(l: *Loop, c: *Conn) !void {
        if (c.up_eof) return;
        if (c.c_out_len > 0) return; // back-pressure
        if (c.state == .relay and c.unpadder.direct) {
            // Raw inner stream: straight copy.
            const n = sys.read(c.up_fd, &c.c_out) catch |e| switch (e) {
                error.WouldBlock => return,
                else => return e,
            };
            if (n > 0) c.last_active = sys.monotonicSeconds();
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
        if (n > 0) c.last_active = sys.monotonicSeconds();
        if (n == 0) return error.UpstreamEof;
        c.uin_len += n;
        if (c.state == .socks_dial) return l.socksDialReply(c);
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
            if (res.event == .handshake_complete) {
                if (c.ws_on) try sendWsUpgrade(c, cfgOf(c)) else try sendVlessRequest(c);
            }

            var data = res.app_data;
            if (c.state == .ws_upgrade and data.len > 0) {
                if (c.ws_hs_len + data.len > c.mux_in.len) return error.WsUpgradeTooLarge;
                @memcpy(c.mux_in[c.ws_hs_len..][0..data.len], data);
                c.ws_hs_len += data.len;
                data = data[0..0];
                if (try ws.parseUpgradeResponse(c.mux_in[0..c.ws_hs_len])) |hl| {
                    if (hl != c.ws_hs_len) return error.WsEarlyData;
                    try sendVlessRequest(c);
                }
            }
            if (c.ws_on and c.state == .relay and data.len > 0) {
                data = c.wsd.feed(data) catch |e| switch (e) {
                    error.WsClosed => return error.UpstreamEof,
                    else => return e,
                };
            }
            if (c.state == .relay and data.len > 0) {
                if (!c.got_resp_hdr) {
                    const resp = (vless.parseResponse(data) catch return error.VlessResponse) orelse return error.VlessResponse;
                    c.got_resp_hdr = true;
                    data = data[resp.len..];
                }
                const content = if (c.vision_on) c.unpadder.feed(data) else data;
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
        var wbuf: [ws.max_header_len + vless.max_request_len + client_chunk + 2 * vision.max_overhead]u8 = undefined;
        const buf = wbuf[ws.max_header_len..];
        var addr: vless.Address = switch (c.target_kind) {
            .ipv4 => .{ .ipv4 = c.target_buf[0..4].* },
            .ipv6 => .{ .ipv6 = c.target_buf[0..16].* },
            .domain => .{ .domain = c.target_buf[0..c.target_len] },
        };
        if (c.is_udp) {
            // XUDP: everything rides one Mux stream; targets live in the frames.
            const hdr = vless.encodeRequest(buf, .{
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
        const hdr = vless.encodeRequest(buf, .{
            .uuid = c.vstate.uuid,
            .flow = if (c.vision_on) .vision else .none,
            .address = addr,
            .port = c.target_port,
        }) catch return error.VlessRequest;
        var n = hdr.len;
        if (c.vision_on) {
            const padded = if (c.cin_len > 0)
                c.padder.pad(c.cin[0..c.cin_len], buf[n..]) catch return error.VisionPad
            else
                c.padder.padEmpty(buf[n..]) catch return error.VisionPad;
            n += padded.len;
        } else {
            @memcpy(buf[n..][0..c.cin_len], c.cin[0..c.cin_len]);
            n += c.cin_len;
        }
        c.cin_len = 0;
        if (c.ws_on) {
            try queueUpstreamRecord(c, ws.frameInPlace(&wbuf, ws.max_header_len, n, maskOf(c)));
        } else try queueUpstreamRecord(c, buf[0..n]);
    }

    fn maskOf(_: *Conn) [4]u8 {
        var m: [4]u8 = undefined;
        sys.randomBytes(&m);
        return m;
    }

    fn cfgOf(c: *Conn) *const Outbound {
        return &cur_cfg.?.outbounds[c.ob];
    }

    fn sendWsUpgrade(c: *Conn, ob: *const Outbound) !void {
        c.state = .ws_upgrade;
        var key: [16]u8 = undefined;
        sys.randomBytes(&key);
        var req_buf: [1024]u8 = undefined;
        const host = if (ob.ws_host.len > 0) ob.ws_host else ob.sni;
        const req = ws.upgradeRequest(&req_buf, host, ob.ws_path, key) catch return error.WsRequestTooLong;
        try queueUpstreamRecord(c, req);
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

test "drain queued upload before FIN and preserve reverse traffic" {
    const linux = std.os.linux;
    const cfg: Config = .{ .outbounds = &.{}, .default_group = &.{} };
    const ep = try sys.epollCreate();
    defer sys.close(ep);
    var cp: [2]sys.fd_t = undefined;
    try std.testing.expectEqual(linux.E.SUCCESS, linux.errno(linux.socketpair(linux.AF.UNIX, linux.SOCK.STREAM | linux.SOCK.NONBLOCK | linux.SOCK.CLOEXEC, 0, &cp)));
    defer sys.close(cp[1]);
    var up: [2]sys.fd_t = undefined;
    try std.testing.expectEqual(linux.E.SUCCESS, linux.errno(linux.socketpair(linux.AF.UNIX, linux.SOCK.STREAM | linux.SOCK.NONBLOCK | linux.SOCK.CLOEXEC, 0, &up)));
    defer sys.close(up[1]);
    var conns: [1]Conn = undefined;
    var loop = Loop.init(ep, &cfg, &conns);
    const c = &conns[0];
    c.state = .relay;
    c.client_fd = cp[0];
    c.up_fd = up[0];
    c.padder.direct = true;
    c.unpadder.direct = true;
    c.client_eof = true;
    c.up_out[0..3].* = "abc".*;
    c.up_out_len = 3;
    loop.active = 1;
    defer loop.close(c, "test finished");
    try loop.finishDirections(c);
    try std.testing.expect(!c.up_write_closed);
    try loop.flushUpstream(c);
    var buf: [16]u8 = undefined;
    try std.testing.expectEqual(@as(usize, 3), try sys.read(up[1], &buf));
    try std.testing.expectEqualSlices(u8, "abc", buf[0..3]);
    try std.testing.expectEqual(@as(usize, 0), try sys.read(up[1], &buf));
    try std.testing.expectEqual(@as(usize, 3), try sys.write(up[1], "xyz"));
    loop.handle(c.token(.upstream), sys.EPOLL.IN);
    try std.testing.expectEqual(@as(usize, 3), try sys.read(cp[1], &buf));
    try std.testing.expectEqualSlices(u8, "xyz", buf[0..3]);
    sys.shutdownWrite(up[1]);
    loop.handle(c.token(.upstream), sys.EPOLL.IN);
    try std.testing.expectEqual(@as(usize, 0), try sys.read(cp[1], &buf));
    try std.testing.expectEqual(State.free, c.state);
    try std.testing.expectEqual(@as(usize, 0), loop.active);
}

// Exercise real epoll readiness with unread data followed by FIN, rather than
// pre-setting an EOF flag. Both directions must pause and later resume safely.
fn backpressureHalfClose(download: bool, expire: bool) !void {
    const linux = std.os.linux;
    const cfg: Config = .{ .outbounds = &.{}, .default_group = &.{}, .idle_timeout_s = 1 };
    const ep = try sys.epollCreate();
    defer sys.close(ep);
    var cp: [2]sys.fd_t = undefined;
    var up: [2]sys.fd_t = undefined;
    const flags = linux.SOCK.STREAM | linux.SOCK.NONBLOCK | linux.SOCK.CLOEXEC;
    try std.testing.expectEqual(linux.E.SUCCESS, linux.errno(linux.socketpair(linux.AF.UNIX, flags, 0, &cp)));
    defer sys.close(cp[1]);
    try std.testing.expectEqual(linux.E.SUCCESS, linux.errno(linux.socketpair(linux.AF.UNIX, flags, 0, &up)));
    defer sys.close(up[1]);
    var conns: [1]Conn = undefined;
    var loop = Loop.init(ep, &cfg, &conns);
    loop.accept(cp[0], .socks5, null);
    const c = &conns[0];
    defer loop.close(c, "test finished");
    c.up_fd = up[0];
    c.state = .relay;
    c.padder.direct = true;
    c.unpadder.direct = true;
    const dst = if (download) cp[0] else up[0];
    const sink = if (download) cp[1] else up[1];
    const source = if (download) up[1] else cp[1];
    const side: Side = if (download) .upstream else .client;
    // Fill the destination's send buffer to force EAGAIN with a queued tail.
    const filler: [4096]u8 = @splat(0x55);
    while (true) {
        _ = sys.write(dst, &filler) catch |err| switch (err) {
            error.WouldBlock => break,
            else => return err,
        };
    }
    if (download) {
        c.c_out[0..3].* = "abc".*;
        c.c_out_len = 3;
    } else {
        c.up_out[0..3].* = "abc".*;
        c.up_out_len = 3;
    }
    try std.testing.expectEqual(@as(usize, 3), try sys.write(source, "xyz"));
    sys.shutdownWrite(source);
    c.last_active = sys.monotonicSeconds() - 3;
    const before = c.last_active;
    // A stale RDHUP from the previous event batch must not extend idle life.
    loop.handle(c.token(side), sys.EPOLL.RDHUP);
    try std.testing.expectEqual(before, c.last_active);
    for (0..4) |_| {
        var events: [4]sys.Event = undefined;
        try std.testing.expectEqual(@as(usize, 0), try sys.epollWait(ep, &events, 10));
    }
    if (expire) {
        loop.sweep();
        try std.testing.expectEqual(State.free, c.state);
        return;
    }
    // Remove only the filler, then let actual epoll events forward abc + xyz.
    var buf: [4096]u8 = undefined;
    while (true) {
        _ = sys.read(sink, &buf) catch |err| switch (err) {
            error.WouldBlock => break,
            else => return err,
        };
    }
    var result: [6]u8 = undefined;
    var used: usize = 0;
    var eof = false;
    for (0..100) |_| {
        var events: [4]sys.Event = undefined;
        const count = try sys.epollWait(ep, &events, 10);
        for (events[0..count]) |ev| loop.handle(ev.data.u64, ev.events);
        const n = sys.read(sink, &buf) catch |err| switch (err) {
            error.WouldBlock => continue,
            else => return err,
        };
        if (n > 0) c.last_active = sys.monotonicSeconds();
        if (n == 0) {
            eof = true;
            break;
        }
        try std.testing.expect(used + n <= result.len);
        @memcpy(result[used..][0..n], buf[0..n]);
        used += n;
    }
    try std.testing.expect(eof);
    try std.testing.expectEqualSlices(u8, "abcxyz", result[0..used]);
    try std.testing.expect(c.last_active > before);
    // The peer's FIN must leave the reverse direction usable.
    try std.testing.expectEqual(@as(usize, 3), try sys.write(sink, "rev"));
    var got_reverse = false;
    for (0..100) |_| {
        var events: [4]sys.Event = undefined;
        const count = try sys.epollWait(ep, &events, 10);
        for (events[0..count]) |ev| loop.handle(ev.data.u64, ev.events);
        const n = sys.read(source, &buf) catch |err| switch (err) {
            error.WouldBlock => continue,
            else => return err,
        };
        if (n > 0) c.last_active = sys.monotonicSeconds();
        try std.testing.expectEqualSlices(u8, "rev", buf[0..n]);
        got_reverse = true;
        break;
    }
    try std.testing.expect(got_reverse);
}

test "upload backpressure and FIN pause epoll then preserve tail and reverse traffic" {
    try backpressureHalfClose(false, false);
}
test "download backpressure and FIN pause epoll then preserve tail and reverse traffic" {
    try backpressureHalfClose(true, false);
}
test "blocked half-closed upload still expires without progress" {
    try backpressureHalfClose(false, true);
}
test "blocked half-closed download still expires without progress" {
    try backpressureHalfClose(true, true);
}
