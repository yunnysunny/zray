//! HTTP/1.x forward-proxy ingress. No allocation or I/O; one plain request per
//! connection (Connection: close). CONNECT becomes an opaque TCP tunnel.
const std = @import("std");
const mem = std.mem;
const socks5 = @import("socks5.zig");

pub const max_header_len = 8192;
pub const Error = error{ BadRequest, HeaderTooLarge, Unsupported, BufferTooSmall };
pub const connected = "HTTP/1.1 200 Connection established\r\n\r\n";

fn equal(a: []const u8, b: []const u8) bool {
    return std.ascii.eqlIgnoreCase(a, b);
}
fn trim(s: []const u8) []const u8 {
    return mem.trim(u8, s, " \t");
}
fn token(s: []const u8) bool {
    if (s.len == 0) return false;
    for (s) |c| if (!std.ascii.isAlphanumeric(c) and mem.indexOfScalar(u8, "!#$%&'*+-.^_`|~", c) == null) return false;
    return true;
}
const Header = struct { name: []const u8, value: []const u8 };
fn header(line: []const u8) Error!Header {
    const colon = mem.indexOfScalar(u8, line, ':') orelse return error.BadRequest;
    if (!token(line[0..colon])) return error.BadRequest;
    for (line[colon + 1 ..]) |c| if ((c < 32 and c != '\t') or c == 127) return error.BadRequest;
    return .{ .name = line[0..colon], .value = trim(line[colon + 1 ..]) };
}
fn decimal(s: []const u8) Error!u64 {
    if (s.len == 0) return error.BadRequest;
    for (s) |c| if (!std.ascii.isDigit(c)) return error.BadRequest;
    return std.fmt.parseInt(u64, s, 10) catch error.BadRequest;
}

pub const Target = struct { address: socks5.Address, port: u16 };
pub fn authority(s: []const u8, require_port: bool) Error!Target {
    if (s.len == 0) return error.BadRequest;
    var host = s;
    var port: u16 = 80;
    var port_text: ?[]const u8 = null;
    if (s[0] == '[') {
        const end = mem.indexOfScalar(u8, s, ']') orelse return error.BadRequest;
        host = s[1..end];
        if (end + 1 < s.len) {
            if (s[end + 1] != ':') return error.BadRequest;
            port_text = s[end + 2 ..];
        }
        const ip = std.Io.net.Ip6Address.parse(host, 0) catch return error.BadRequest;
        if (port_text) |p| port = std.math.cast(u16, try decimal(p)) orelse return error.BadRequest else if (require_port) return error.BadRequest;
        if (port == 0) return error.BadRequest;
        return .{ .address = .{ .ipv6 = ip.bytes }, .port = port };
    }
    if (mem.indexOfScalar(u8, s, ':')) |colon| {
        host = s[0..colon];
        port_text = s[colon + 1 ..];
    }
    if (host.len == 0 or host.len > 255) return error.BadRequest;
    for (host) |c| if (!std.ascii.isAlphanumeric(c) and c != '-' and c != '.' and c != '_') return error.BadRequest;
    if (port_text) |p| port = std.math.cast(u16, try decimal(p)) orelse return error.BadRequest else if (require_port) return error.BadRequest;
    if (port == 0) return error.BadRequest;
    const addr: socks5.Address = if (std.Io.net.Ip4Address.parse(host, 0)) |ip| .{ .ipv4 = ip.bytes } else |_| .{ .domain = host };
    return .{ .address = addr, .port = port };
}

pub const Request = struct {
    target: Target,
    connect: bool,
    len: usize,
    method: []const u8,
    path: []const u8,
    host: []const u8,
    headers: []const u8,
    body: Body,
};

fn nominated(headers: []const u8, name: []const u8) bool {
    var lines = mem.splitSequence(u8, headers, "\r\n");
    while (lines.next()) |line| {
        const h = header(line) catch continue;
        if (!equal(h.name, "Connection")) continue;
        var names = mem.splitScalar(u8, h.value, ',');
        while (names.next()) |n| if (equal(trim(n), name)) return true;
    }
    return false;
}

pub fn parse(input: []const u8) Error!?Request {
    const end = mem.indexOf(u8, input, "\r\n\r\n") orelse {
        if (input.len >= max_header_len) return error.HeaderTooLarge;
        return null;
    };
    if (end + 4 > max_header_len) return error.HeaderTooLarge;
    const first = mem.indexOf(u8, input[0 .. end + 2], "\r\n") orelse return error.BadRequest;
    var words = mem.splitScalar(u8, input[0..first], ' ');
    const method = words.next() orelse return error.BadRequest;
    const uri = words.next() orelse return error.BadRequest;
    const version = words.next() orelse return error.BadRequest;
    if (words.next() != null or !token(method) or uri.len == 0) return error.BadRequest;
    if (!mem.eql(u8, version, "HTTP/1.1") and !mem.eql(u8, version, "HTTP/1.0")) return error.Unsupported;
    for (uri) |c| if (c <= 32 or c >= 127 or c == '#') return error.BadRequest;
    const is_connect = mem.eql(u8, method, "CONNECT");
    var host = uri;
    var path: []const u8 = "";
    if (!is_connect) {
        if (!std.ascii.startsWithIgnoreCase(uri, "http://")) return error.Unsupported;
        const rest = uri[7..];
        const boundary = mem.indexOfAny(u8, rest, "/?") orelse rest.len;
        host = rest[0..boundary];
        path = rest[boundary..];
    }
    const target = try authority(host, is_connect);
    const headers = if (first == end) "" else input[first + 2 .. end];
    var length: ?u64 = null;
    var chunked = false;
    var has_host = false;
    var lines = mem.splitSequence(u8, headers, "\r\n");
    while (lines.next()) |line| {
        if (line.len == 0) continue;
        const h = try header(line);
        if (equal(h.name, "Host")) {
            if (has_host) return error.BadRequest;
            has_host = true;
            _ = try authority(h.value, false);
        } else if (equal(h.name, "Content-Length")) {
            if (length != null) return error.BadRequest;
            length = try decimal(h.value);
        } else if (equal(h.name, "Transfer-Encoding")) {
            if (chunked or !equal(h.value, "chunked")) return error.BadRequest;
            chunked = true;
        } else if (equal(h.name, "Upgrade")) return error.Unsupported;
        if (equal(h.name, "Connection")) {
            var names = mem.splitScalar(u8, h.value, ',');
            while (names.next()) |n| {
                const name = trim(n);
                if (!token(name) or equal(name, "Host") or equal(name, "Content-Length") or equal(name, "Transfer-Encoding")) return error.BadRequest;
                if (equal(name, "Upgrade")) return error.Unsupported;
            }
        }
    }
    if (chunked and length != null) return error.BadRequest;
    if (is_connect and (chunked or (length orelse 0) != 0)) return error.BadRequest;
    return .{ .target = target, .connect = is_connect, .len = end + 4, .method = method, .path = path, .host = host, .headers = headers, .body = if (chunked) .{ .state = .size } else .{ .remaining = length orelse 0 } };
}

fn append(out: []u8, used: *usize, s: []const u8) Error!void {
    if (s.len > out.len - used.*) return error.BufferTooSmall;
    @memcpy(out[used.*..][0..s.len], s);
    used.* += s.len;
}

/// Produce an origin-form request, replacing Host from the absolute URI and
/// dropping proxy credentials and hop-by-hop headers. Body is handled separately.
pub fn rewrite(req: Request, out: []u8) Error![]u8 {
    var n: usize = 0;
    for ([_][]const u8{ req.method, " ", if (req.path.len == 0 or req.path[0] == '?') "/" else "", req.path, " HTTP/1.1\r\nHost: ", req.host, "\r\n" }) |s| try append(out, &n, s);
    var lines = mem.splitSequence(u8, req.headers, "\r\n");
    while (lines.next()) |line| {
        if (line.len == 0) continue;
        const h = try header(line);
        var drop = nominated(req.headers, h.name);
        for ([_][]const u8{ "Host", "Connection", "Proxy-Connection", "Proxy-Authorization", "Proxy-Authenticate", "Keep-Alive", "TE", "Upgrade", "Trailer" }) |name| {
            if (equal(h.name, name)) drop = true;
        }
        if (!drop) {
            try append(out, &n, line);
            try append(out, &n, "\r\n");
        }
    }
    try append(out, &n, "Connection: close\r\n\r\n");
    return out[0..n];
}

/// Tracks the end of one request body, so pipelined requests are never sent to
/// the first destination. Chunk framing is validated even across byte splits.
pub const Body = struct {
    state: enum { fixed, size, data, data_cr, data_lf, trailers, done } = .fixed,
    remaining: u64 = 0,
    line: [1024]u8 = undefined,
    line_len: usize = 0,
    trailer_bytes: usize = 0,

    pub fn done(b: *const Body) bool {
        return b.state == .done or (b.state == .fixed and b.remaining == 0);
    }
    pub fn feed(b: *Body, input: []const u8) Error!usize {
        var n: usize = 0;
        while (n < input.len and !b.done()) {
            switch (b.state) {
                .fixed, .data => {
                    const take: usize = @intCast(@min(b.remaining, input.len - n));
                    b.remaining -= take;
                    n += take;
                    if (b.state == .data and b.remaining == 0) b.state = .data_cr;
                },
                .data_cr, .data_lf => {
                    if (input[n] != (if (b.state == .data_cr) @as(u8, '\r') else '\n')) return error.BadRequest;
                    b.state = if (b.state == .data_cr) .data_lf else .size;
                    n += 1;
                },
                .size, .trailers => {
                    if (b.line_len == b.line.len) return error.BadRequest;
                    const c = input[n];
                    b.line[b.line_len] = c;
                    b.line_len += 1;
                    n += 1;
                    if (b.state == .trailers) {
                        b.trailer_bytes += 1;
                        if (b.trailer_bytes > max_header_len) return error.BadRequest;
                    }
                    if (c != '\n') continue;
                    if (b.line_len < 2 or b.line[b.line_len - 2] != '\r') return error.BadRequest;
                    const line = b.line[0 .. b.line_len - 2];
                    if (b.state == .size) {
                        const semi = mem.indexOfScalar(u8, line, ';') orelse line.len;
                        if (semi == 0) return error.BadRequest;
                        for (line[0..semi]) |ch| if (!std.ascii.isHex(ch)) return error.BadRequest;
                        for (line[semi..]) |ch| if (ch < 32 or ch == 127) return error.BadRequest;
                        b.remaining = std.fmt.parseInt(u64, line[0..semi], 16) catch return error.BadRequest;
                        b.state = if (b.remaining == 0) .trailers else .data;
                    } else if (line.len == 0) {
                        b.state = .done;
                    } else {
                        const h = try header(line);
                        for ([_][]const u8{ "Host", "Content-Length", "Transfer-Encoding", "Connection", "Proxy-Authorization", "Proxy-Connection", "Upgrade" }) |name| if (equal(h.name, name)) return error.BadRequest;
                    }
                    b.line_len = 0;
                },
                .done => unreachable,
            }
        }
        return n;
    }
};

const testing = std.testing;

test "CONNECT waits for complete headers and preserves tunnel bytes" {
    const wire = "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n";
    for (0..wire.len) |n| try testing.expectEqual(@as(?Request, null), try parse(wire[0..n]));
    const req = (try parse(wire ++ "\x16\x03\x01payload")).?;
    try testing.expect(req.connect);
    try testing.expectEqualStrings("example.com", req.target.address.domain);
    try testing.expectEqual(@as(u16, 443), req.target.port);
    try testing.expectEqual(wire.len, req.len);
}

test "HTTP rewrite uses URL authority and strips credentials and hop headers" {
    const req = (try parse("POST http://Example.com:8080/a?q=1 HTTP/1.1\r\nHost: other.example\r\nProxy-Authorization: Basic secret\r\nProxy-Connection: keep-alive\r\nConnection: keep-alive, X-Private\r\nX-Private: private\r\nKeep-Alive: timeout=60\r\nContent-Length: 4\r\nX-End: retained\r\n\r\nbody")).?;
    var out: [1024]u8 = undefined;
    try testing.expectEqualStrings("POST /a?q=1 HTTP/1.1\r\nHost: Example.com:8080\r\nContent-Length: 4\r\nX-End: retained\r\nConnection: close\r\n\r\n", try rewrite(req, &out));
    try testing.expectEqualStrings("Example.com", req.target.address.domain);
    try testing.expectEqual(@as(u16, 8080), req.target.port);
    try testing.expectError(error.BufferTooSmall, rewrite(req, out[0..10]));
    const query = (try parse("GET http://example.com?q=1 HTTP/1.0\r\n\r\n")).?;
    try testing.expectEqualStrings("GET /?q=1 HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n", try rewrite(query, &out));
    const root = (try parse("HEAD http://example.com HTTP/1.1\r\n\r\n")).?;
    try testing.expect(mem.startsWith(u8, try rewrite(root, &out), "HEAD / HTTP/1.1\r\n"));
}

test "HTTP targets include IPv4 IPv6 and strict ports" {
    const v4 = try authority("127.0.0.1:8080", false);
    try testing.expectEqualSlices(u8, &.{ 127, 0, 0, 1 }, &v4.address.ipv4);
    const v6 = try authority("[::1]:443", true);
    try testing.expectEqual(@as(u8, 1), v6.address.ipv6[15]);
    try testing.expectEqual(@as(u16, 80), (try authority("[::1]", false)).port);
    for ([_][]const u8{ "", "example.com", "example.com:0", "example.com:65536", "example.com:+80", "user@example.com:80", "::1:443", "[bad]:443", "[::1]evil:443", ":80" }) |a| try testing.expectError(error.BadRequest, authority(a, true));
}

test "HTTP rejects ambiguous framing malformed headers and unsupported requests" {
    for ([_][]const u8{
        "GET http://x/ HTTP/1.1\r\nContent-Length: 1\r\nContent-Length: 1\r\n\r\n",
        "POST http://x/ HTTP/1.1\r\nContent-Length: 1\r\nTransfer-Encoding: chunked\r\n\r\n",
        "GET http://x/ HTTP/1.1\r\nContent-Length: -1\r\n\r\n",
        "GET http://x/ HTTP/1.1\r\nTransfer-Encoding: gzip, chunked\r\n\r\n",
        "GET http://x/ HTTP/1.1\r\nHost: x\r\nHost: x\r\n\r\n",
        "GET http://x/ HTTP/1.1\r\nBad : value\r\n\r\n",
        "GET http://x/ HTTP/1.1\r\n folded: value\r\n\r\n",
        "GET http://x/ HTTP/1.1\r\nX: a\x00b\r\n\r\n",
        "GET http://x/ HTTP/1.1\r\nConnection: Content-Length\r\n\r\n",
        "CONNECT x:443 HTTP/1.1\r\nContent-Length: 1\r\n\r\n",
        "GET http://x/#fragment HTTP/1.1\r\n\r\n",
    }) |wire| try testing.expectError(error.BadRequest, parse(wire));
    for ([_][]const u8{
        "GET / HTTP/1.1\r\nHost: x\r\n\r\n",
        "GET https://x/ HTTP/1.1\r\n\r\n",
        "GET http://x/ HTTP/2.0\r\n\r\n",
        "GET http://x/ HTTP/1.1\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n",
    }) |wire| try testing.expectError(error.Unsupported, parse(wire));
    const big: [max_header_len]u8 = @splat('a');
    try testing.expectError(error.HeaderTooLarge, parse(&big));
}

test "HTTP body boundaries and chunk framing survive every split" {
    const chunks = "4;foo=bar\r\nbody\r\n1\r\n!\r\n0\r\nX-End: yes\r\n\r\n";
    for (0..chunks.len + 1) |split| {
        var b: Body = .{ .state = .size };
        try testing.expectEqual(split, try b.feed(chunks[0..split]));
        try testing.expectEqual(chunks.len - split, try b.feed((chunks ++ "GET http://other/ HTTP/1.1\r\n\r\n")[split..]));
        try testing.expect(b.done());
    }
    var b: Body = .{ .state = .size };
    for (chunks) |c| try testing.expectEqual(@as(usize, 1), try b.feed(&.{c}));
    try testing.expect(b.done());
    b = .{ .remaining = 4 };
    try testing.expectEqual(@as(usize, 2), try b.feed("bo"));
    try testing.expectEqual(@as(usize, 2), try b.feed("dyGET /"));
    try testing.expect(b.done());
    for ([_][]const u8{ "z\r\n", "1\r\nx!", "0\r\nContent-Length: 10\r\n\r\n", "1\nx", "10000000000000000\r\n" }) |wire| {
        b = .{ .state = .size };
        try testing.expectError(error.BadRequest, b.feed(wire));
    }
}
