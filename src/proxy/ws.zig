//! Minimal RFC 6455 WebSocket client framing for the VLESS `ws` transport.
//!
//! Upstream: one masked binary frame per write; the caller reserves
//! `max_header_len` bytes in front of the payload so the header is written
//! in place (no copy). Downstream: a streaming, in-place deframer.

const std = @import("std");
const mem = std.mem;

pub const max_header_len = 14;

/// Write a masked binary frame header ending exactly at `buf[payload_off]`
/// and mask the payload `buf[payload_off..][0..len]` in place. Returns the
/// whole frame (header + payload) as a slice of `buf`.
pub fn frameInPlace(buf: []u8, payload_off: usize, len: usize, mask: [4]u8) []u8 {
    var hdr: [max_header_len]u8 = undefined;
    var h: usize = 2;
    hdr[0] = 0x82; // FIN | binary
    if (len < 126) {
        hdr[1] = 0x80 | @as(u8, @intCast(len));
    } else if (len <= 0xffff) {
        hdr[1] = 0x80 | 126;
        mem.writeInt(u16, hdr[2..4], @intCast(len), .big);
        h = 4;
    } else {
        hdr[1] = 0x80 | 127;
        mem.writeInt(u64, hdr[2..10], len, .big);
        h = 10;
    }
    hdr[h..][0..4].* = mask;
    h += 4;
    std.debug.assert(payload_off >= h);
    const start = payload_off - h;
    @memcpy(buf[start..payload_off], hdr[0..h]);
    for (buf[payload_off..][0..len], 0..) |*b, i| b.* ^= mask[i & 3];
    return buf[start .. payload_off + len];
}

/// Build the HTTP Upgrade request.
pub fn upgradeRequest(out: []u8, host: []const u8, path: []const u8, key: [16]u8) error{BufferTooSmall}![]u8 {
    var k: [24]u8 = undefined;
    _ = std.base64.standard.Encoder.encode(&k, &key);
    return std.fmt.bufPrint(out, "GET {s} HTTP/1.1\r\nHost: {s}\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: {s}\r\nSec-WebSocket-Version: 13\r\n\r\n", .{ if (path.len > 0) path else "/", host, &k }) catch error.BufferTooSmall;
}

/// Length of the HTTP response head if complete, null if more bytes needed,
/// error if it is not a 101.
pub fn parseUpgradeResponse(b: []const u8) error{WsUpgradeRejected}!?usize {
    const end = mem.indexOf(u8, b, "\r\n\r\n") orelse return null;
    if (b.len < 12 or !mem.eql(u8, b[9..12], "101")) return error.WsUpgradeRejected;
    return end + 4;
}

pub const Deframer = struct {
    hdr: [max_header_len]u8 = undefined,
    hdr_len: u8 = 0,
    /// Payload bytes left in the current frame.
    remaining: u64 = 0,
    in_payload: bool = false,
    /// Current frame is a data frame (continuation/text/binary).
    data: bool = false,
    masked: bool = false,
    mask: [4]u8 = .{ 0, 0, 0, 0 },
    mask_pos: u2 = 0,

    pub const Error = error{ WsClosed, WsBadFrame };

    fn headerNeed(d: *const Deframer) usize {
        if (d.hdr_len < 2) return 2;
        var need: usize = 2;
        const l7 = d.hdr[1] & 0x7f;
        if (l7 == 126) need += 2 else if (l7 == 127) need += 8;
        if (d.hdr[1] & 0x80 != 0) need += 4;
        return need;
    }

    fn startFrame(d: *Deframer) Error!void {
        const op = d.hdr[0] & 0x0f;
        const l7 = d.hdr[1] & 0x7f;
        var off: usize = 2;
        d.remaining = switch (l7) {
            126 => blk: {
                off = 4;
                break :blk mem.readInt(u16, d.hdr[2..4], .big);
            },
            127 => blk: {
                off = 10;
                break :blk mem.readInt(u64, d.hdr[2..10], .big);
            },
            else => l7,
        };
        d.masked = d.hdr[1] & 0x80 != 0;
        if (d.masked) d.mask = d.hdr[off..][0..4].*;
        d.mask_pos = 0;
        if (op == 8) return error.WsClosed;
        if (op > 2 and op != 9 and op != 10) return error.WsBadFrame;
        d.data = op <= 2;
        d.hdr_len = 0;
        d.in_payload = d.remaining > 0;
    }

    /// Consume `buf`, compacting data-frame payload to its front. Control
    /// frames (ping/pong) are dropped; close raises WsClosed.
    pub fn feed(d: *Deframer, buf: []u8) Error![]u8 {
        var r: usize = 0;
        var w: usize = 0;
        while (true) {
            if (!d.in_payload) {
                if (d.hdr_len < d.headerNeed()) {
                    if (r == buf.len) break;
                    d.hdr[d.hdr_len] = buf[r];
                    d.hdr_len += 1;
                    r += 1;
                    continue;
                }
                try d.startFrame();
                continue;
            }
            if (r == buf.len) break;
            const take: usize = @intCast(@min(d.remaining, buf.len - r));
            if (d.data) {
                if (d.masked) {
                    for (0..take) |i| {
                        buf[w + i] = buf[r + i] ^ d.mask[d.mask_pos];
                        d.mask_pos +%= 1;
                    }
                } else mem.copyForwards(u8, buf[w .. w + take], buf[r .. r + take]);
                w += take;
            }
            r += take;
            d.remaining -= take;
            if (d.remaining == 0) d.in_payload = false;
        }
        return buf[0..w];
    }
};

const testing = std.testing;

test "frame roundtrip through deframer, split at every byte" {
    var buf: [max_header_len + 300]u8 = undefined;
    for (buf[max_header_len..], 0..) |*b, i| b.* = @truncate(i);
    const f = frameInPlace(&buf, max_header_len, 300, .{ 1, 2, 3, 4 });
    try testing.expectEqual(@as(usize, 4 + 4 + 300), f.len);
    var copy: [400]u8 = undefined;
    var split: usize = 0;
    while (split <= f.len) : (split += 1) {
        @memcpy(copy[0..f.len], f);
        var d: Deframer = .{};
        const a = try d.feed(copy[0..split]);
        const alen = a.len;
        var out: [400]u8 = undefined;
        @memcpy(out[0..alen], a);
        const b = try d.feed(copy[split..f.len]);
        @memcpy(out[alen..][0..b.len], b);
        try testing.expectEqual(@as(usize, 300), alen + b.len);
        for (out[0..300], 0..) |x, i| try testing.expectEqual(@as(u8, @truncate(i)), x);
    }
}

test "unmasked server frames, ping skipped, close detected" {
    var b = [_]u8{ 0x89, 1, 'p', 0x82, 2, 'h', 'i', 0x82, 0 };
    var d: Deframer = .{};
    try testing.expectEqualSlices(u8, "hi", try d.feed(&b));
    var c = [_]u8{ 0x88, 0 };
    try testing.expectError(error.WsClosed, d.feed(&c));
}

test "upgrade response" {
    try testing.expectEqual(@as(?usize, null), try parseUpgradeResponse("HTTP/1.1 101 Switching"));
    try testing.expectEqual(@as(?usize, 23), try parseUpgradeResponse("HTTP/1.1 101 Switch\r\n\r\nxx"));
    try testing.expectError(error.WsUpgradeRejected, parseUpgradeResponse("HTTP/1.1 404 NF\r\n\r\n"));
}
