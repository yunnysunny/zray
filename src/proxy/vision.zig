//! XTLS Vision flow (xtls-rprx-vision), client side. Port of xray-core
//! proxy/proxy.go: TrafficState / XtlsFilterTls / XtlsPadding / XtlsUnpadding
//! and the VisionWriter / VisionReader decision logic. Sans-I/O.
//!
//! Wire format of one padding block:
//!   [uuid(16), first block only] command(1) | content_len(2) | padding_len(2) | content | zero padding
//!   command: 0 = more blocks follow, 1 = padding ends (stay inside outer TLS),
//!            2 = padding ends and the connection switches to direct copy:
//!            everything after this block on the wire is the inner TLS stream
//!            written raw to the TCP socket, bypassing the outer TLS.
//!
//! `State` is shared between the uplink `Padder` and the downlink `Unpadder`
//! of one connection, exactly as xray shares TrafficState.

const std = @import("std");
const mem = std.mem;

pub const Command = enum(u8) { cont = 0, end = 1, direct = 2 };

pub const buf_size = 8192;
pub const header_len = 5;
/// Worst case output growth of `Padder.pad` for one piece: block header +
/// first-block uuid + long padding.
pub const max_overhead = 16 + header_len + 900 + 500;

const tls13_supported_versions = [_]u8{ 0x00, 0x2b, 0x00, 0x02, 0x03, 0x04 };

/// Traffic classification shared by both directions (xray TrafficState).
pub const State = struct {
    uuid: [16]u8,
    packets_to_filter: i32 = 8,
    enable_xtls: bool = false,
    is_tls12_or_above: bool = false,
    is_tls: bool = false,
    cipher: u16 = 0,
    remaining_server_hello: i32 = -1,

    upload_inspector: Inspector = .{},
    download_inspector: Inspector = .{},

    pub fn init(uuid: [16]u8) State {
        return .{ .uuid = uuid };
    }
};

/// Observe whole TLS records rather than spending the classification budget
/// on arbitrary TCP reads. Each direction has its own parser. Only a bounded
/// prefix of plaintext handshake records is retained; application data is
/// skipped without copying. Oversized/unknown hellos retain outer encryption.
const Inspector = struct {
    header: [5]u8 = undefined,
    used: usize = 0,
    remaining: usize = 0,
    body: [2048]u8 = undefined,
    body_len: usize = 0,
    invalid: bool = false,

    fn feed(p: *Inspector, state: *State, data: []const u8) void {
        if (p.invalid) {
            state.packets_to_filter -= 1;
            return;
        }
        var pos: usize = 0;
        while (pos < data.len and state.packets_to_filter > 0) {
            if (p.used < 5) {
                const n = @min(5 - p.used, data.len - pos);
                @memcpy(p.header[p.used..][0..n], data[pos..][0..n]);
                p.used += n;
                pos += n;
                if (p.header[0] < 0x14 or p.header[0] > 0x17 or
                    (p.used >= 2 and p.header[1] != 3) or (p.used >= 3 and p.header[2] > 3))
                {
                    p.invalid = true;
                    state.packets_to_filter -= 1;
                    return;
                }
                if (p.used < 5) return;
                const h = p.header;
                if (h[0] < 0x14 or h[0] > 0x17 or h[1] != 3 or h[2] > 3) {
                    p.invalid = true;
                    state.packets_to_filter -= 1;
                    return;
                }
                p.remaining = mem.readInt(u16, h[3..5], .big);
                if (p.remaining > 18432) {
                    p.invalid = true;
                    return;
                }
                p.body_len = 0;
            }
            const n = @min(p.remaining, data.len - pos);
            if (p.header[0] == 0x16) {
                const keep = @min(n, p.body.len - p.body_len);
                @memcpy(p.body[p.body_len..][0..keep], data[pos..][0..keep]);
                p.body_len += keep;
            }
            p.remaining -= n;
            pos += n;
            if (p.remaining > 0) return;
            state.packets_to_filter -= 1;
            if (p.header[0] == 0x16 and p.body_len > 0) {
                const body = p.body[0..p.body_len];
                if (body[0] == 1) state.is_tls = true;
                if (body[0] == 2) {
                    state.is_tls = true;
                    state.is_tls12_or_above = true;
                    if (body.len >= 41) {
                        const sid: usize = body[38];
                        if (body.len >= 41 + sid) state.cipher = mem.readInt(u16, body[39 + sid ..][0..2], .big);
                    }
                    if (mem.indexOf(u8, body, &tls13_supported_versions) != null) {
                        state.enable_xtls = switch (state.cipher) {
                            0x1301, 0x1302, 0x1303, 0x1304 => true,
                            else => false,
                        };
                    }
                    state.packets_to_filter = 0;
                }
            }
            p.used = 0;
        }
    }
};

/// True if `b` is a whole number of complete TLS application_data records.
pub fn isCompleteRecord(b: []const u8) bool {
    var i: usize = 0;
    while (i < b.len) {
        if (b.len - i < 5) return false;
        if (b[i] != 0x17 or b[i + 1] != 0x03 or b[i + 2] != 0x03) return false;
        const len: usize = mem.readInt(u16, b[i + 3 ..][0..2], .big);
        if (b.len - i - 5 < len) return false;
        i += 5 + len;
    }
    return true;
}

/// Track record boundaries without retaining payloads. TCP reads are not TLS
/// records: a 16 KiB record routinely spans several 8 KiB client reads.
pub const RecordBoundary = struct {
    header: [5]u8 = undefined,
    used: usize = 0,
    remaining: usize = 0,
    valid: bool = true,

    /// True only when this read ends exactly at an application-data boundary
    /// and starts in (or at the header of) application data. Never switch in
    /// the middle of a record, even if ciphertext contains a TLS-like header.
    pub fn feed(s: *RecordBoundary, data: []const u8) bool {
        if (!s.valid or data.len == 0) return false;
        const starts_app = if (s.used > 0 or s.remaining > 0) s.header[0] == 0x17 else data[0] == 0x17;
        var pos: usize = 0;
        var last_app = false;
        while (pos < data.len) {
            if (s.remaining > 0) {
                const n = @min(s.remaining, data.len - pos);
                s.remaining -= n;
                pos += n;
                if (s.remaining == 0) {
                    last_app = s.header[0] == 0x17;
                    s.used = 0;
                }
                continue;
            }
            const n = @min(5 - s.used, data.len - pos);
            @memcpy(s.header[s.used..][0..n], data[pos..][0..n]);
            pos += n;
            s.used += n;
            if (s.used < 5) break;
            const h = s.header;
            const len = mem.readInt(u16, h[3..5], .big);
            if (h[0] < 0x14 or h[0] > 0x17 or h[1] != 3 or h[2] > 3 or len > 18432) {
                s.valid = false;
                return false;
            }
            s.remaining = len;
            if (len == 0) {
                last_app = h[0] == 0x17;
                s.used = 0;
            }
        }
        return starts_app and last_app and s.used == 0 and s.remaining == 0;
    }
};

/// Uplink: wraps payloads in padding blocks until the switch condition.
pub const Padder = struct {
    state: *State,
    rand: std.Random,
    uuid_pending: bool = true,
    is_padding: bool = true,
    /// Set once a `direct` block has been produced. The caller must send that
    /// output through the outer TLS, then write all later payloads raw.
    direct: bool = false,
    boundary: RecordBoundary = .{},

    pub fn init(state: *State, rand: std.Random) Padder {
        return .{ .state = state, .rand = rand };
    }

    pub const Error = error{BufferTooSmall};

    /// Encode one application write. Returns the bytes to send through the
    /// outer TLS (or raw once `direct` was already true before the call).
    /// `out.len` must be at least `payload.len + 2 * max_overhead`.
    pub fn pad(p: *Padder, payload: []const u8, out: []u8) Error![]u8 {
        if (p.direct or !p.is_padding) {
            if (out.len < payload.len) return error.BufferTooSmall;
            @memcpy(out[0..payload.len], payload);
            return out[0..payload.len];
        }
        if (p.state.packets_to_filter > 0) p.state.upload_inspector.feed(p.state, payload);

        // ReshapeMultiBuffer: split oversized payloads into two pieces.
        var pieces: [2][]const u8 = .{ payload, &.{} };
        var n_pieces: usize = 1;
        if (payload.len >= buf_size - 21) {
            var idx: usize = buf_size / 2;
            if (mem.lastIndexOf(u8, payload, &[_]u8{ 0x17, 0x03, 0x03 })) |i| {
                if (i >= 21 and i <= buf_size - 21) idx = i;
            }
            pieces = .{ payload[0..idx], payload[idx..] };
            n_pieces = 2;
        }

        const complete = p.boundary.feed(payload);
        var long_padding = p.state.is_tls;
        var w: usize = 0;
        for (pieces[0..n_pieces], 0..) |b, i| {
            const last = i == n_pieces - 1;
            if (!p.is_padding) {
                // xray `break`s out of the padding loop; the rest is written as-is.
                if (out.len - w < b.len) return error.BufferTooSmall;
                @memcpy(out[w..][0..b.len], b);
                w += b.len;
                continue;
            }
            if (p.state.is_tls and complete) {
                if (last and p.state.enable_xtls) p.direct = true;
                var cmd: Command = .cont;
                if (last) cmd = if (p.state.enable_xtls) .direct else .end;
                w += try p.block(b, cmd, true, out[w..]);
                if (last) p.is_padding = false;
                long_padding = false;
                continue;
            } else if (!p.state.is_tls12_or_above and p.state.packets_to_filter <= 1) {
                p.is_padding = false;
                w += try p.block(b, .end, long_padding, out[w..]);
                continue;
            }
            var cmd: Command = .cont;
            if (last and !p.is_padding) cmd = if (p.state.enable_xtls) .direct else .end;
            w += try p.block(b, cmd, long_padding, out[w..]);
        }
        return out[0..w];
    }

    /// A padding block with no content, used to hide the VLESS header when
    /// there is no first payload to send along with it.
    pub fn padEmpty(p: *Padder, out: []u8) Error![]u8 {
        const n = try p.block(&.{}, .cont, true, out);
        return out[0..n];
    }

    fn block(p: *Padder, content: []const u8, cmd: Command, long_padding: bool, out: []u8) Error!usize {
        var padding_len: usize = if (content.len < 900 and long_padding)
            p.rand.uintLessThan(u32, 500) + 900 - content.len
        else
            p.rand.uintLessThan(u32, 256);
        if (padding_len > buf_size - 21 - content.len) padding_len = buf_size - 21 - content.len;

        const uuid_len: usize = if (p.uuid_pending) 16 else 0;
        const total = uuid_len + header_len + content.len + padding_len;
        if (out.len < total) return error.BufferTooSmall;

        var w: usize = 0;
        if (p.uuid_pending) {
            out[0..16].* = p.state.uuid;
            w = 16;
            p.uuid_pending = false;
        }
        out[w] = @backingInt(cmd);
        mem.writeInt(u16, out[w + 1 ..][0..2], @intCast(content.len), .big);
        mem.writeInt(u16, out[w + 3 ..][0..2], @intCast(padding_len), .big);
        w += header_len;
        @memcpy(out[w..][0..content.len], content);
        w += content.len;
        @memset(out[w..][0..padding_len], 0);
        w += padding_len;
        return w;
    }
};

/// Downlink: strips padding blocks and detects the direct-copy switch.
pub const Unpadder = struct {
    state: *State,
    remaining_command: i32 = -1,
    remaining_content: i32 = -1,
    remaining_padding: i32 = -1,
    current_command: u8 = 0,
    within_padding: bool = true,
    /// Set when a `direct` block completed. Bytes after that block (including
    /// any the caller already buffered) are the raw inner stream.
    direct: bool = false,

    pub fn init(state: *State) Unpadder {
        return .{ .state = state };
    }

    /// Process one chunk read from the outer TLS. Content is compacted in
    /// place; the returned slice aliases `input`.
    pub fn feed(u: *Unpadder, input: []u8) []u8 {
        if (u.direct) return input;
        var content = input;
        if (u.within_padding or u.state.packets_to_filter > 0) {
            content = u.unpad(input);
            if (u.remaining_content > 0 or u.remaining_padding > 0 or u.current_command == 0) {
                u.within_padding = true;
            } else if (u.current_command == 1) {
                u.within_padding = false;
            } else if (u.current_command == 2) {
                u.within_padding = false;
                u.direct = true;
            }
        }
        if (u.state.packets_to_filter > 0 and content.len > 0) u.state.download_inspector.feed(u.state, content);
        return content;
    }

    fn unpad(u: *Unpadder, b: []u8) []u8 {
        var r: usize = 0;
        if (u.remaining_command == -1 and u.remaining_content == -1 and u.remaining_padding == -1) {
            if (b.len >= 21 and mem.eql(u8, &u.state.uuid, b[0..16])) {
                r = 16;
                u.remaining_command = 5;
            } else {
                return b;
            }
        }
        var w: usize = 0;
        while (r < b.len) {
            if (u.remaining_command > 0) {
                const d = b[r];
                r += 1;
                switch (u.remaining_command) {
                    5 => u.current_command = d,
                    4 => u.remaining_content = @as(i32, d) << 8,
                    3 => u.remaining_content |= d,
                    2 => u.remaining_padding = @as(i32, d) << 8,
                    1 => u.remaining_padding |= d,
                    else => unreachable,
                }
                u.remaining_command -= 1;
            } else if (u.remaining_content > 0) {
                const n = @min(@as(usize, @intCast(u.remaining_content)), b.len - r);
                mem.copyForwards(u8, b[w..][0..n], b[r..][0..n]);
                w += n;
                r += n;
                u.remaining_content -= @intCast(n);
            } else {
                const n = @min(@as(usize, @intCast(u.remaining_padding)), b.len - r);
                r += n;
                u.remaining_padding -= @intCast(n);
            }
            if (u.remaining_command <= 0 and u.remaining_content <= 0 and u.remaining_padding <= 0) {
                if (u.current_command == 0) {
                    u.remaining_command = 5;
                } else {
                    u.remaining_command = -1;
                    u.remaining_content = -1;
                    u.remaining_padding = -1;
                    // Trailing bytes after a terminal block: pass through
                    // (xray: "shouldn't happen").
                    const rest = b.len - r;
                    mem.copyForwards(u8, b[w..][0..rest], b[r..][0..rest]);
                    w += rest;
                    break;
                }
            }
        }
        return b[0..w];
    }
};

// ---------------------------------------------------------------------------

const testing = std.testing;

fn fixedRandom() std.Random {
    const S = struct {
        var prng = std.Random.DefaultPrng.init(42);
    };
    return S.prng.random();
}

test "padding round trip through unpadder, non-TLS payload" {
    const uuid: [16]u8 = @splat(0xab);
    var up_state = State.init(uuid);
    var p = Padder.init(&up_state, fixedRandom());
    var down_state = State.init(uuid);
    var u = Unpadder.init(&down_state);

    var out: [buf_size]u8 = undefined;
    const msg = "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
    const wire = try p.pad(msg, &out);
    try testing.expect(wire.len >= 16 + header_len + msg.len);
    try testing.expectEqualSlices(u8, &uuid, wire[0..16]);
    try testing.expectEqual(@as(u8, 0), wire[16]); // cont: not TLS, filter count still 7
    try testing.expectEqual(@as(u16, msg.len), mem.readInt(u16, wire[17..19], .big));

    const got = u.feed(wire);
    try testing.expectEqualSlices(u8, msg, got);
    try testing.expect(u.within_padding);
    try testing.expect(!u.direct);
}

test "unpadder handles blocks split across reads" {
    const uuid: [16]u8 = @splat(1);
    var st = State.init(uuid);
    var p = Padder.init(&st, fixedRandom());
    var out: [buf_size]u8 = undefined;
    const wire = try p.pad("hello world", &out);

    var st2 = State.init(uuid);
    var u = Unpadder.init(&st2);
    // Like xray, the first read must carry uuid + block header (21 bytes);
    // after that, arbitrary fragmentation is fine.
    var acc: [64]u8 = undefined;
    var n: usize = 0;
    var i: usize = 0;
    while (i < wire.len) {
        const step: usize = if (i == 0) 21 else 7;
        const end = @min(i + step, wire.len);
        var chunk: [21]u8 = undefined;
        @memcpy(chunk[0 .. end - i], wire[i..end]);
        const c = u.feed(chunk[0 .. end - i]);
        @memcpy(acc[n..][0..c.len], c);
        n += c.len;
        i = end;
    }
    try testing.expectEqualSlices(u8, "hello world", acc[0..n]);
}

test "non-TLS traffic ends padding after the filter window" {
    const uuid: [16]u8 = @splat(2);
    var st = State.init(uuid);
    var p = Padder.init(&st, fixedRandom());
    var out: [buf_size]u8 = undefined;
    var last_cmd: u8 = 0xff;
    var i: usize = 0;
    while (i < 8) : (i += 1) {
        const wire = try p.pad("x", &out);
        if (!p.is_padding) {
            last_cmd = wire[0];
            break;
        }
    }
    try testing.expectEqual(@as(u8, 1), last_cmd); // end
    try testing.expect(st.packets_to_filter <= 1);
    // Subsequent writes are passthrough.
    const raw = try p.pad("plain", &out);
    try testing.expectEqualSlices(u8, "plain", raw);
}

test "TLS 1.3 inner stream switches to direct on first app-data record" {
    const uuid: [16]u8 = @splat(3);
    var st = State.init(uuid);
    var p = Padder.init(&st, fixedRandom());
    var u = Unpadder.init(&st);
    var out: [buf_size]u8 = undefined;

    // Client hello (uplink).
    var ch: [100]u8 = @splat(0);
    ch[0..6].* = .{ 0x16, 0x03, 0x01, 0x00, 95, 0x01 };
    const w1 = try p.pad(&ch, &out);
    try testing.expectEqual(@as(u8, 0), w1[16]);
    try testing.expect(st.is_tls);

    // Server hello (downlink, unpadded by the peer: command end). Build a
    // plausible TLS 1.3 ServerHello: 32-byte sid, cipher 0x1301, with the
    // supported_versions extension bytes somewhere in the body.
    var sh: [120]u8 = @splat(0);
    sh[0..6].* = .{ 0x16, 0x03, 0x03, 0x00, 115, 0x02 };
    sh[43] = 32;
    sh[76] = 0x13;
    sh[77] = 0x01;
    sh[90..96].* = tls13_supported_versions;
    // Peer did not pad (simulate a direct block from a hypothetical sender is
    // out of scope here); feed as raw content via the filter path.
    _ = u.feed(&sh);
    try testing.expect(st.is_tls12_or_above);
    try testing.expect(st.enable_xtls);
    try testing.expectEqual(@as(i32, 0), st.packets_to_filter);

    // CCS + Finished in one write: starts with 0x14, padding continues.
    var fin: [40]u8 = @splat(0);
    fin[0..6].* = .{ 0x14, 0x03, 0x03, 0x00, 0x01, 0x01 };
    fin[6..11].* = .{ 0x17, 0x03, 0x03, 0x00, 29 };
    const w2 = try p.pad(&fin, &out);
    try testing.expectEqual(@as(u8, 0), w2[0]); // cont, no uuid anymore
    try testing.expect(!p.direct);

    // First app data record: direct.
    var app: [30]u8 = @splat(0);
    app[0..5].* = .{ 0x17, 0x03, 0x03, 0x00, 25 };
    const w3 = try p.pad(&app, &out);
    try testing.expectEqual(@as(u8, 2), w3[0]);
    try testing.expect(p.direct);
    try testing.expect(!p.is_padding);
    const w4 = try p.pad("raw", &out);
    try testing.expectEqualSlices(u8, "raw", w4);
}

test "unpadder detects direct block and passes trailing bytes" {
    const uuid: [16]u8 = @splat(4);
    var st = State.init(uuid);
    var u = Unpadder.init(&st);
    var wire: [16 + 5 + 3 + 2 + 4]u8 = undefined;
    wire[0..16].* = uuid;
    wire[16..21].* = .{ 2, 0, 3, 0, 2 };
    wire[21..24].* = "abc".*;
    wire[24..26].* = .{ 0, 0 };
    wire[26..30].* = "RAW!".*;
    const got = u.feed(&wire);
    try testing.expectEqualSlices(u8, "abcRAW!", got);
    try testing.expect(u.direct);
    var more = "more".*;
    try testing.expectEqualSlices(u8, "more", u.feed(&more));
}

test "isCompleteRecord" {
    try testing.expect(isCompleteRecord(&.{ 0x17, 3, 3, 0, 1, 0xaa }));
    try testing.expect(isCompleteRecord(&.{ 0x17, 3, 3, 0, 1, 0xaa, 0x17, 3, 3, 0, 0 }));
    try testing.expect(!isCompleteRecord(&.{ 0x17, 3, 3, 0, 2, 0xaa }));
    try testing.expect(!isCompleteRecord(&.{ 0x14, 3, 3, 0, 1, 1 }));
    try testing.expect(isCompleteRecord(&.{}));
}

test "record boundary survives every split of a large TLS record" {
    var record_bytes: [16405]u8 = @splat(0xab);
    record_bytes[0..5].* = .{ 0x17, 3, 3, 0x40, 0x10 };
    for (1..record_bytes.len) |split| {
        var tracker: RecordBoundary = .{};
        try testing.expect(!tracker.feed(record_bytes[0..split]));
        try testing.expect(tracker.feed(record_bytes[split..]));
    }
    var tracker: RecordBoundary = .{};
    for (record_bytes[0 .. record_bytes.len - 1]) |b| {
        try testing.expect(!tracker.feed(&.{b}));
    }
    try testing.expect(tracker.feed(record_bytes[record_bytes.len - 1 ..]));
}

test "fragmented upload switches only after a complete padding command" {
    const uuid: [16]u8 = @splat(0x42);
    var st = State.init(uuid);
    st.is_tls = true;
    st.is_tls12_or_above = true;
    st.enable_xtls = true;
    st.packets_to_filter = 0;
    var pad = Padder.init(&st, fixedRandom());
    var peer = State.init(uuid);
    var unpad = Unpadder.init(&peer);
    var bytes: [16405]u8 = @splat(0xab);
    bytes[0..5].* = .{ 0x17, 3, 3, 0x40, 0x10 };
    var buffer: [8192 + 2 * max_overhead]u8 = undefined;
    var offset: usize = 0;
    while (offset < bytes.len) {
        const end = @min(offset + 8192, bytes.len);
        const wire = try pad.pad(bytes[offset..end], &buffer);
        const got = unpad.feed(wire);
        try testing.expectEqualSlices(u8, bytes[offset..end], got);
        try testing.expectEqual(end == bytes.len, pad.direct);
        try testing.expectEqual(end == bytes.len, unpad.direct);
        offset = end;
    }
}

test "reshaped complete app record sends direct command in final block" {
    const uuid: [16]u8 = @splat(0x29);
    var st = State.init(uuid);
    st.is_tls = true;
    st.is_tls12_or_above = true;
    st.enable_xtls = true;
    st.packets_to_filter = 0;
    var pad = Padder.init(&st, fixedRandom());
    var peer = State.init(uuid);
    var unpad = Unpadder.init(&peer);
    var bytes: [8192]u8 = @splat(0xab);
    bytes[0..5].* = .{ 0x17, 3, 3, 0x1f, 0xfb };
    var buffer: [8192 + 2 * max_overhead]u8 = undefined;
    const wire = try pad.pad(&bytes, &buffer);
    try testing.expectEqualSlices(u8, &bytes, unpad.feed(wire));
    try testing.expect(pad.direct and unpad.direct);
}

test "one-byte fragmented hellos preserve classification budget and enable Vision" {
    var st = State.init(@splat(0));
    var ch: [100]u8 = @splat(0);
    ch[0..6].* = .{ 0x16, 3, 1, 0, 95, 1 };
    for (ch) |b| st.upload_inspector.feed(&st, &.{b});
    try testing.expect(st.is_tls);
    try testing.expectEqual(@as(i32, 7), st.packets_to_filter);
    var sh: [120]u8 = @splat(0);
    sh[0..6].* = .{ 0x16, 3, 3, 0, 115, 2 };
    sh[43] = 32;
    sh[76..78].* = .{ 0x13, 1 };
    sh[90..96].* = tls13_supported_versions;
    for (sh) |b| st.download_inspector.feed(&st, &.{b});
    try testing.expect(st.enable_xtls);
    try testing.expectEqual(@as(u16, 0x1301), st.cipher);
    try testing.expectEqual(@as(i32, 0), st.packets_to_filter);
}

test "coalesced record with trailing partial header cannot switch early" {
    var boundary: RecordBoundary = .{};
    const bytes = [_]u8{ 0x17, 3, 3, 0, 1, 0xaa, 0x17, 3 };
    try testing.expect(!boundary.feed(&bytes));
    try testing.expect(boundary.feed(&.{ 3, 0, 1, 0xbb }));
}
