//! Live probe: REALITY handshake, then optionally one proxied HTTP(S) request
//! over VLESS + xtls-rprx-vision.
//!
//!   zig build probe -- <ip> <port> <sni> <public_key_b64> [short_id_hex|-] [uuid url]
//!
//! With only the first four/five arguments it stops after the TLS handshake
//! and reports whether the REALITY certificate check passed. With `uuid url`
//! it sends a VLESS request for the URL's host:port and performs a GET:
//!   http://  -> plain request inside the tunnel (padding ends, no direct copy)
//!   https:// -> inner TLS 1.3 via our own client; exercises the Vision
//!               direct-copy switch (outer TLS dropped mid-connection).

const std = @import("std");
const Io = std.Io;
const tls = std.crypto.tls;
const client = @import("tls/client.zig");
const hello = @import("tls/hello.zig");
const reality = @import("tls/reality.zig");
const record = @import("tls/record.zig");
const vless = @import("proxy/vless.zig");
const vision = @import("proxy/vision.zig");

const max_rec = tls.max_ciphertext_record_len;

pub fn main(init: std.process.Init) !void {
    const io = init.io;
    var stdout_buf: [4096]u8 = undefined;
    var stdout: Io.File.Writer = .init(.stdout(), io, &stdout_buf);
    const out = &stdout.interface;
    defer out.flush() catch {};

    var args = try init.minimal.args.iterateAllocator(init.gpa);
    defer args.deinit();
    _ = args.next();
    const ip_text = args.next() orelse return usage(out);
    const port_text = args.next() orelse return usage(out);
    const sni = args.next() orelse return usage(out);
    const pk_text = args.next() orelse return usage(out);
    var sid_text = args.next() orelse "";
    if (std.mem.eql(u8, sid_text, "-")) sid_text = "";
    const uuid_text = args.next();
    const url_text = args.next();
    if ((uuid_text == null) != (url_text == null)) return usage(out);

    const port = try std.fmt.parseInt(u16, port_text, 10);
    const cfg: reality.Config = .{
        .server_public_key = try reality.Config.publicKeyFromBase64(pk_text),
        .short_id = try reality.Config.shortIdFromHex(sid_text),
    };

    const addr = try Io.net.IpAddress.resolve(io, ip_text, port);
    try out.print("connecting {s}:{d} (sni {s})\n", .{ ip_text, port, sni });
    const t0 = Io.Clock.awake.now(io);
    const stream = try addr.connect(io, .{ .mode = .stream });
    defer stream.close(io);

    var rbuf: [32 * 1024]u8 = undefined;
    var wbuf: [4096]u8 = undefined;
    var sr = stream.reader(io, &rbuf);
    var sw = stream.writer(io, &wbuf);
    const r = &sr.interface;
    const w = &sw.interface;

    const now_ns = Io.Clock.real.now(io).nanoseconds;
    const now_s: i64 = @intCast(@divFloor(now_ns, std.time.ns_per_s));
    var rl = reality.Reality.init(cfg, now_s);

    var seed: [32]u8 = undefined;
    try io.randomSecure(&seed);
    var csprng = std.Random.DefaultCsprng.init(seed);

    var entropy: [160]u8 = undefined;
    try io.randomSecure(&entropy);
    var hs_buf: [8 * 1024]u8 = undefined;
    var c = client.Client.init(.{
        .entropy = entropy[0..64].*,
        .hybrid_seed = entropy[64..160].*,
        .verifier = rl.verifier(),
        .handshake_buf = &hs_buf,
    });

    const zero_sid: [32]u8 = @splat(0);
    var hello_buf: [4096]u8 = undefined;
    var fp: fingerprint.Chrome = undefined;
    fp.build(csprng.random(), .{ .sni = sni, .x25519_public = c.publicKey(), .ml_kem_public = c.mlKemPublicKey() });
    const first = try c.clientHello(&hello_buf, .{
        .random = undefined,
        .session_id = &zero_sid,
        .cipher_suites = fp.cipherSuites(),
        .extensions = fp.extensions(),
    }, rl.helloHook());
    if (rl.err) |e| {
        try out.print("REALITY hook failed: {s}\n", .{@errorName(e)});
        return;
    }
    try w.writeAll(first);
    try w.flush();

    var rec_buf: [max_rec]u8 = undefined;
    var out_buf: [max_rec]u8 = undefined;
    var records: usize = 0;
    while (c.state != .connected) {
        const rec = readRecord(r, &rec_buf) catch |e| {
            try out.print("read failed after {d} records: {s} (state {s})\n", .{ records, @errorName(e), @tagName(c.state) });
            return;
        };
        records += 1;
        const hdr = record.Header.parse(rec[0..record.header_len]);
        const res = c.handleRecord(rec, &out_buf) catch |e| {
            try out.print("record #{d} {s} len {d}: {s} (state {s})\n", .{ records, @tagName(hdr.content_type), hdr.len, @errorName(e), @tagName(c.state) });
            if (c.last_alert) |a| try out.print("  alert: {s}\n", .{@tagName(a.description)});
            return;
        };
        if (res.to_send.len > 0) {
            try w.writeAll(res.to_send);
            try w.flush();
        }
        if (res.event == .close_notify) {
            try out.print("server closed during handshake\n", .{});
            return;
        }
    }
    try out.print("REALITY handshake OK in {d} ms ({s}, group {s}, cert HMAC verified)\n", .{ msSince(io, t0), @tagName(c.suite), @tagName(c.group) });

    if (uuid_text == null) {
        const bye = try c.close(&out_buf);
        try w.writeAll(bye);
        try w.flush();
        return;
    }

    // ---- VLESS + Vision -------------------------------------------------
    const uuid = try vless.parseUuid(uuid_text.?);
    const url = try parseUrl(url_text.?);
    try out.print("tunnel: {s}://{s}:{d}{s}\n", .{ if (url.https) "https" else "http", url.host, url.port, url.path });

    var vstate = vision.State.init(uuid);
    var padder = vision.Padder.init(&vstate, csprng.random());
    var unpadder = vision.Unpadder.init(&vstate);

    var tun: Tunnel = .{
        .io = io,
        .out = out,
        .w = w,
        .outer = &c,
        .padder = &padder,
        .url = url,
    };

    // Request header + first payload in one outer record, like xray.
    var req_buf: [vless.max_request_len + 2048 + 2 * vision.max_overhead]u8 = undefined;
    const hdr_bytes = try vless.encodeRequest(&req_buf, .{
        .uuid = uuid,
        .flow = .vision,
        .address = .{ .domain = url.host },
        .port = url.port,
    });
    var n: usize = hdr_bytes.len;

    var inner_hs_buf: [16 * 1024]u8 = undefined;
    var inner_entropy: [160]u8 = undefined;
    try io.randomSecure(&inner_entropy);
    var inner_sid: [32]u8 = undefined;
    try io.randomSecure(&inner_sid);
    var inner = client.Client.init(.{
        .entropy = inner_entropy[0..64].*,
        .hybrid_seed = inner_entropy[64..160].*,
        .verifier = client.Verifier.insecure, // probe only; REALITY authenticates the proxy, not the origin
        .handshake_buf = &inner_hs_buf,
    });
    var first_payload: [2048]u8 = undefined;
    var inner_fp: fingerprint.Chrome = undefined;
    const payload: []const u8 = if (url.https) blk: {
        tun.inner = &inner;
        inner_fp.build(csprng.random(), .{ .sni = url.host, .x25519_public = inner.publicKey(), .ml_kem_public = inner.mlKemPublicKey(), .alpn = &fingerprint.alpn_http11, .compress_certificate = false });
        break :blk try inner.clientHello(&first_payload, .{
            .random = undefined,
            .session_id = &inner_sid,
            .cipher_suites = inner_fp.cipherSuites(),
            .extensions = inner_fp.extensions(),
        }, null);
    } else try std.fmt.bufPrint(&first_payload, "GET {s} HTTP/1.1\r\nHost: {s}\r\nUser-Agent: zray-probe/0.1\r\nAccept: */*\r\nConnection: close\r\n\r\n", .{ url.path, url.host });
    const padded = try padder.pad(payload, req_buf[n..]);
    n += padded.len;
    const rec1 = try c.encrypt(req_buf[0..n], &out_buf);
    try w.writeAll(rec1);
    try w.flush();
    try out.print("sent VLESS header ({d} B) + first payload ({d} B) as {d} B padded block\n", .{ hdr_bytes.len, payload.len, padded.len });

    // ---- downlink loop ----------------------------------------------------
    var got_response_header = false;
    var acc: [64 * 1024]u8 = undefined; // inner stream reassembly (https)
    var acc_len: usize = 0;
    var direct_downlink = false;

    while (!tun.done) {
        var chunk: []u8 = undefined;
        if (direct_downlink) {
            // Raw inner TLS stream on the socket.
            r.fillMore() catch |e| {
                try out.print("downlink closed (raw): {s}\n", .{@errorName(e)});
                break;
            };
            chunk = r.buffered();
            defer r.toss(chunk.len);
            try tun.deliver(chunk, &acc, &acc_len, &out_buf);
            continue;
        }

        const rec = readRecord(r, &rec_buf) catch |e| {
            try out.print("downlink closed: {s}\n", .{@errorName(e)});
            break;
        };
        const res = c.handleRecord(rec, &out_buf) catch |e| {
            try out.print("outer record error: {s}\n", .{@errorName(e)});
            break;
        };
        if (res.to_send.len > 0) {
            try w.writeAll(res.to_send);
            try w.flush();
        }
        if (res.event == .close_notify) {
            try out.print("outer close_notify\n", .{});
            break;
        }
        chunk = res.app_data;
        if (chunk.len == 0) continue;

        if (!got_response_header) {
            const resp = (try vless.parseResponse(chunk)) orelse {
                try out.print("short VLESS response header\n", .{});
                break;
            };
            got_response_header = true;
            try out.print("VLESS response header OK (addons {d} B)\n", .{resp.addons.len});
            chunk = chunk[resp.len..];
            if (chunk.len == 0) continue;
        }

        const content = unpadder.feed(chunk);
        if (unpadder.direct) {
            direct_downlink = true;
            try out.print("vision: downlink switched to direct copy ({d} B inner payload in the direct block)\n", .{content.len});
        }
        try tun.deliver(content, &acc, &acc_len, &out_buf);
        if (direct_downlink) {
            // Anything already buffered beyond this record is raw inner stream.
            const left = r.buffered();
            if (left.len > 0) {
                try tun.deliver(left, &acc, &acc_len, &out_buf);
                r.toss(left.len);
            }
        }
    }

    try out.print("\n{d} B of HTTP received, total {d} ms, uplink {s}\n", .{
        tun.http_bytes,
        msSince(io, t0),
        if (padder.direct) "switched to direct copy" else "stayed inside outer TLS",
    });
}

const Tunnel = struct {
    io: Io,
    out: *Io.Writer,
    w: *Io.Writer,
    outer: *client.Client,
    padder: *vision.Padder,
    inner: ?*client.Client = null,
    url: Url,
    done: bool = false,
    http_bytes: usize = 0,
    inner_connected: bool = false,
    inner_records: usize = 0,
    printed: usize = 0,
    tail: [160]u8 = @splat(' '),

    /// Send inner-layer bytes upstream: padded through the outer TLS until the
    /// Vision direct switch, raw afterwards.
    fn uplink(t: *Tunnel, data: []const u8, scratch: *[max_rec]u8) !void {
        if (t.padder.direct) {
            try t.w.writeAll(data);
            try t.w.flush();
            return;
        }
        var pad_buf: [max_rec]u8 = undefined;
        const padded = try t.padder.pad(data, &pad_buf);
        const rec = try t.outer.encrypt(padded, scratch);
        try t.w.writeAll(rec);
        try t.w.flush();
        if (t.padder.direct) try t.out.print("vision: uplink switched to direct copy\n", .{});
    }

    /// Downlink content after Vision unpadding.
    fn deliver(t: *Tunnel, data: []u8, acc: []u8, acc_len: *usize, scratch: *[max_rec]u8) !void {
        if (t.inner == null) {
            try t.showHttp(data);
            return;
        }
        // Reassemble inner TLS records.
        if (acc_len.* + data.len > acc.len) return error.InnerBufferOverflow;
        @memcpy(acc[acc_len.*..][0..data.len], data);
        acc_len.* += data.len;
        var off: usize = 0;
        while (acc_len.* - off >= record.header_len) {
            const hdr = record.Header.parse(acc[off..][0..record.header_len]);
            const total = record.header_len + hdr.len;
            if (acc_len.* - off < total) break;
            try t.innerRecord(acc[off..][0..total], scratch);
            off += total;
            if (t.done) break;
        }
        std.mem.copyForwards(u8, acc[0 .. acc_len.* - off], acc[off..acc_len.*]);
        acc_len.* -= off;
    }

    fn innerRecord(t: *Tunnel, rec: []u8, scratch: *[max_rec]u8) !void {
        const inner = t.inner.?;
        var inner_out: [max_rec]u8 = undefined;
        t.inner_records += 1;
        const res = inner.handleRecord(rec, &inner_out) catch |e| {
            try t.out.print("inner TLS error: {s} (state {s}) at inner record #{d}, header {x}, len {d}\n", .{ @errorName(e), @tagName(inner.state), t.inner_records, rec[0..5], rec.len });
            if (e == error.BadRecordMac and rec.len <= 64) {
                // Does it decrypt under the OUTER keys? Then the proxy leaked
                // its own TLS alert into the direct-copy stream.
                var copy: [64]u8 = undefined;
                @memcpy(copy[0..rec.len], rec);
                var scratch2: [max_rec]u8 = undefined;
                if (t.outer.handleRecord(copy[0..rec.len], &scratch2)) |res2| {
                    try t.out.print("  -> decrypts under OUTER keys: event {s}", .{@tagName(res2.event)});
                    if (t.outer.last_alert) |a| try t.out.print(", alert {s}", .{@tagName(a.description)});
                    try t.out.print(" (proxy leaked outer close_notify into the raw stream)\n", .{});
                } else |e2| {
                    try t.out.print("  -> not an outer record either: {s}\n", .{@errorName(e2)});
                }
                try t.out.print("  record hex: {x}\n  last HTTP bytes: {s}\n", .{ rec, &t.tail });
            }
            if (inner.last_alert) |a| try t.out.print("  alert: {s}\n", .{@tagName(a.description)});
            t.done = true;
            return;
        };
        if (res.to_send.len > 0) try t.uplink(res.to_send, scratch);
        if (res.event == .handshake_complete and !t.inner_connected) {
            t.inner_connected = true;
            try t.out.print("inner TLS handshake OK ({s}, group {s}, alpn {s})\n", .{ @tagName(inner.suite), @tagName(inner.group), if (inner.alpn().len > 0) inner.alpn() else "-" });
            var req: [1024]u8 = undefined;
            const get = try std.fmt.bufPrint(&req, "GET {s} HTTP/1.1\r\nHost: {s}\r\nUser-Agent: zray-probe/0.1\r\nAccept: */*\r\nConnection: close\r\n\r\n", .{ t.url.path, t.url.host });
            var enc: [2048]u8 = undefined;
            const rec_out = try inner.encrypt(get, &enc);
            try t.uplink(rec_out, scratch);
        }
        if (res.app_data.len > 0) try t.showHttp(res.app_data);
        if (res.event == .close_notify) {
            try t.out.print("inner close_notify\n", .{});
            t.done = true;
        }
    }

    fn showHttp(t: *Tunnel, data: []const u8) !void {
        t.http_bytes += data.len;
        // Keep the last 160 bytes for post-mortem.
        if (data.len >= t.tail.len) {
            t.tail = data[data.len - t.tail.len ..][0..t.tail.len].*;
        } else {
            const keep = t.tail.len - data.len;
            std.mem.copyForwards(u8, t.tail[0..keep], t.tail[data.len..]);
            @memcpy(t.tail[keep..], data);
        }
        const limit = 1200;
        if (t.printed < limit) {
            const n = @min(data.len, limit - t.printed);
            if (t.printed == 0) try t.out.print("---- response ----\n", .{});
            try t.out.writeAll(data[0..n]);
            t.printed += n;
            if (t.printed >= limit) try t.out.print("\n---- (truncated) ----\n", .{});
        }
    }
};

const fingerprint = @import("tls/fingerprint.zig");

const Url = struct { https: bool, host: []const u8, port: u16, path: []const u8 };

fn parseUrl(text: []const u8) !Url {
    var rest = text;
    var https = false;
    if (std.mem.startsWith(u8, rest, "https://")) {
        https = true;
        rest = rest[8..];
    } else if (std.mem.startsWith(u8, rest, "http://")) {
        rest = rest[7..];
    } else return error.BadUrl;
    const slash = std.mem.indexOfScalar(u8, rest, '/') orelse rest.len;
    const hostport = rest[0..slash];
    const path = if (slash < rest.len) rest[slash..] else "/";
    var host = hostport;
    var port: u16 = if (https) 443 else 80;
    if (std.mem.indexOfScalar(u8, hostport, ':')) |i| {
        host = hostport[0..i];
        port = try std.fmt.parseInt(u16, hostport[i + 1 ..], 10);
    }
    if (host.len == 0) return error.BadUrl;
    return .{ .https = https, .host = host, .port = port, .path = path };
}

fn readRecord(r: *Io.Reader, buf: []u8) ![]u8 {
    try r.readSliceAll(buf[0..record.header_len]);
    const hdr = record.Header.parse(buf[0..record.header_len]);
    if (hdr.len > buf.len - record.header_len) return error.RecordTooLarge;
    try r.readSliceAll(buf[record.header_len..][0..hdr.len]);
    return buf[0 .. record.header_len + hdr.len];
}

fn msSince(io: Io, t0: Io.Timestamp) i64 {
    const t1 = Io.Clock.awake.now(io);
    return @intCast(@divFloor(t0.durationTo(t1).nanoseconds, std.time.ns_per_ms));
}

fn usage(out: *Io.Writer) !void {
    try out.print("usage: probe <ip> <port> <sni> <public_key_b64> [short_id_hex|-] [uuid url]\n", .{});
}
