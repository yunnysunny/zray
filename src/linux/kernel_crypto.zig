//! Linux AF_ALG and devcrypto AES-GCM backends. Each executing thread owns
//! its bounded key cache, fixed scratch space and self-tested kernel sessions.
//! Unsupported requests and unavailable backends fall back to software.
const std = @import("std");
const builtin = @import("builtin");
const linux = std.os.linux;
const sys = @import("sys.zig");
const mem = std.mem;

pub const Policy = enum { auto, off, afalg, devcrypto };
pub const minimum = 4096;
pub const maximum = 32768;
/// Bounds apply to the AEAD plaintext length, excluding its tag and AAD.
pub const Limits = struct {
    min_bytes: usize = minimum,
    max_bytes: usize = maximum,

    pub fn valid(l: Limits) bool {
        return l.min_bytes >= 1 and l.min_bytes <= l.max_bytes and l.max_bytes <= maximum;
    }
    pub fn accepts(l: Limits, n: usize) bool {
        return l.valid() and n >= l.min_bytes and n <= l.max_bytes;
    }
};
pub const Outcome = enum { software, success, authentication_failed };
pub threadlocal var current: ?*Context = null;
// Bound kernel/DMA resources across every worker, not merely per key cache.
const session_limit = 128;
var live_sessions: std.atomic.Value(usize) = .init(0);

/// Each cached session owns one fd. Each executing worker may also briefly
/// hold an AF_ALG transform socket while creating its operation descriptor.
pub fn fdReserve(policy: Policy, workers: usize) usize {
    return if (policy == .off) 0 else session_limit +| workers;
}

fn reserveSession() !void {
    if (live_sessions.fetchAdd(1, .monotonic) >= session_limit) {
        _ = live_sessions.fetchSub(1, .monotonic);
        return error.BackendUnavailable;
    }
}
fn releaseSession() void {
    _ = live_sessions.fetchSub(1, .monotonic);
}

// Availability is probed lazily for each key: no board, CPU-feature or driver
// allowlist is needed. An enabled policy may still fall back to software.
pub fn available(policy: Policy) bool {
    return policy != .off and builtin.os.tag == .linux;
}

const SessionOp = extern struct {
    cipher: u32 = 50,
    mac: u32 = 0,
    keylen: u32,
    key: ?[*]const u8,
    mackeylen: u32 = 0,
    mackey: ?[*]const u8 = null,
    session: u32 = 0,
};
const AlgorithmInfo = extern struct { name: [64]u8 = @splat(0), driver: [64]u8 = @splat(0) };
const SessionInfo = extern struct {
    session: u32,
    cipher: AlgorithmInfo = .{},
    hash: AlgorithmInfo = .{},
    alignmask: u16 = 0,
    flags: u32 = 0,
};
const AuthOp = extern struct {
    session: u32,
    op: u16,
    flags: u16 = 0,
    len: u32,
    auth_len: u32,
    auth_src: ?[*]u8,
    src: ?[*]u8,
    dst: ?[*]u8,
    tag: ?[*]u8 = null,
    tag_len: u32 = 16,
    iv: ?[*]u8,
    iv_len: u32 = 12,
};
fn ioctlCode(comptime number: u32, comptime T: type) u32 {
    return linux.IOCTL.IOWR('c', @intCast(number), T);
}
fn checked(rc: usize) !usize {
    return switch (linux.errno(rc)) {
        .SUCCESS => rc,
        .BADMSG => error.AuthenticationFailed,
        else => error.BackendUnavailable,
    };
}
const Session = struct {
    fd: sys.fd_t = -1,
    id: u32 = 0,
    dev: bool = false,
    key: [32]u8 = @splat(0),
    keylen: usize = 0,
    disabled: bool = false,
    dev_tried: bool = false,
    reserved: bool = false,

    fn close(s: *Session) void {
        if (s.fd >= 0) sys.close(s.fd); // closing cryptodev releases its session
        s.fd = -1;
        if (s.reserved) releaseSession();
        s.reserved = false;
    }
};

pub const Context = struct {
    policy: Policy = .off,
    enabled: bool = false,
    limits: Limits = .{},
    sessions: [64]Session = @splat(.{}),
    victim: usize = 0,
    // Align beyond the common DMA masks. Reject larger masks explicitly.
    input: [maximum + 272]u8 align(4096) = undefined,
    output: [maximum + 272]u8 align(4096) = undefined,
    aad_buf: [256]u8 align(4096) = undefined,
    iv_buf: [16]u8 align(4096) = undefined,
    input_used: usize = 0,
    output_used: usize = 0,
    aad_used: usize = 0,
    backend_ops: u64 = 0,
    fallbacks: u64 = 0,
    auth_failures: u64 = 0,
    // Generic algorithm names let the kernel select its preferred implementation.
    algorithm: []const u8 = "gcm(aes)",
    notice: bool = false,

    pub fn init(policy: Policy) Context {
        return .{ .policy = policy, .enabled = available(policy) };
    }
    pub fn deinit(c: *Context) void {
        for (&c.sessions) |*s| {
            s.close();
            @memset(&s.key, 0);
        }
        c.clear();
    }
    fn clear(c: *Context) void {
        std.crypto.secureZero(u8, c.input[0..c.input_used]);
        std.crypto.secureZero(u8, c.output[0..c.output_used]);
        std.crypto.secureZero(u8, c.aad_buf[0..c.aad_used]);
        c.input_used = 0;
        c.output_used = 0;
        c.aad_used = 0;
        std.crypto.secureZero(u8, &c.iv_buf);
    }
    fn session(c: *Context, key: []const u8) *Session {
        for (&c.sessions) |*s| {
            if (s.keylen == key.len and mem.eql(u8, s.key[0..s.keylen], key)) return s;
        }
        const s = &c.sessions[c.victim];
        c.victim = (c.victim + 1) % c.sessions.len;
        s.close();
        s.* = .{ .keylen = key.len };
        @memcpy(s.key[0..key.len], key);
        return s;
    }
    fn openAFALG(c: *Context, s: *Session) !void {
        try reserveSession();
        errdefer releaseSession();
        const fd: sys.fd_t = @intCast(try checked(linux.socket(38, linux.SOCK.SEQPACKET | linux.SOCK.CLOEXEC, 0)));
        defer sys.close(fd);
        var addr: [88]u8 align(8) = @splat(0);
        mem.writeInt(u16, addr[0..2], 38, builtin.cpu.arch.endian());
        @memcpy(addr[2..6], "aead");
        if (c.algorithm.len >= 64) return error.BackendUnavailable;
        @memcpy(addr[24..][0..c.algorithm.len], c.algorithm);
        _ = try checked(linux.bind(fd, @ptrCast(&addr), addr.len));
        _ = try checked(linux.setsockopt(fd, 279, 1, &s.key, @intCast(s.keylen)));
        // ALG_SET_AEAD_AUTHSIZE conveys the size via optlen, no optval.
        _ = try checked(linux.syscall5(.setsockopt, @bitCast(@as(isize, fd)), 279, 5, 0, 16));
        const op: sys.fd_t = @intCast(try checked(linux.accept4(fd, null, null, linux.SOCK.CLOEXEC)));
        errdefer sys.close(op);
        var tv: linux.timeval = .{ .sec = 1, .usec = 0 };
        for ([_]u32{ linux.SO.RCVTIMEO, linux.SO.SNDTIMEO }) |opt|
            _ = try checked(linux.setsockopt(op, linux.SOL.SOCKET, opt, mem.asBytes(&tv), @sizeOf(@TypeOf(tv))));
        s.fd = op;
        s.reserved = true;
        s.dev = false;
    }
    fn openDev(c: *Context, s: *Session) !void {
        _ = c;
        try reserveSession();
        errdefer releaseSession();
        const fd: sys.fd_t = @intCast(try checked(linux.openat(linux.AT.FDCWD, "/dev/crypto", .{ .ACCMODE = .RDWR, .CLOEXEC = true }, 0)));
        errdefer sys.close(fd);
        var op: SessionOp = .{ .keylen = @intCast(s.keylen), .key = &s.key };
        _ = try checked(linux.ioctl(fd, ioctlCode(102, SessionOp), @intFromPtr(&op)));
        var info: SessionInfo = .{ .session = op.session };
        _ = try checked(linux.ioctl(fd, ioctlCode(107, SessionInfo), @intFromPtr(&info)));
        if (!mem.eql(u8, mem.sliceTo(&info.cipher.name, 0), "gcm(aes)") or
            info.alignmask > 4095 or (info.alignmask & (info.alignmask +% 1)) != 0) return error.BackendUnavailable;
        s.fd = fd;
        s.reserved = true;
        s.id = op.session;
        s.dev = true;
    }
    fn exchange(c: *Context, s: *Session, nonce: [12]u8, data: []const u8, aad: []const u8, decrypt: bool) ![]const u8 {
        const out_len = if (decrypt) data.len - 16 else data.len + 16;
        c.input_used = @max(c.input_used, @max(data.len, out_len) + aad.len);
        c.output_used = @max(c.output_used, out_len + aad.len);
        c.aad_used = @max(c.aad_used, aad.len);
        if (s.dev) {
            @memcpy(c.input[0..data.len], data);
            @memcpy(c.aad_buf[0..aad.len], aad);
            c.iv_buf[0..12].* = nonce;
            var op: AuthOp = .{
                .session = s.id,
                .op = if (decrypt) 1 else 0,
                .len = @intCast(data.len),
                .auth_len = @intCast(aad.len),
                .auth_src = &c.aad_buf,
                .src = &c.input,
                .dst = &c.input,
                .iv = &c.iv_buf,
            };
            _ = try checked(linux.ioctl(s.fd, ioctlCode(109, AuthOp), @intFromPtr(&op)));
            if (op.len != out_len) return error.BackendUnavailable;
            return c.input[0..out_len];
        }
        @memcpy(c.input[0..aad.len], aad);
        @memcpy(c.input[aad.len..][0..data.len], data);
        var ctl: [128]u8 align(@alignOf(linux.cmsghdr)) = @splat(0);
        var len: usize = 0;
        var op: u32 = if (decrypt) 0 else 1;
        appendControl(&ctl, &len, 3, mem.asBytes(&op));
        var iv: [16]u8 = undefined;
        mem.writeInt(u32, iv[0..4], 12, builtin.cpu.arch.endian());
        iv[4..16].* = nonce;
        appendControl(&ctl, &len, 2, &iv);
        var assoc: u32 = @intCast(aad.len);
        appendControl(&ctl, &len, 4, mem.asBytes(&assoc));
        var vec: std.posix.iovec_const = .{ .base = &c.input, .len = aad.len + data.len };
        const msg: linux.msghdr_const = .{ .name = null, .namelen = 0, .iov = @ptrCast(&vec), .iovlen = 1, .control = &ctl, .controllen = len, .flags = 0 };
        const n = try checked(linux.sendmsg(s.fd, &msg, linux.MSG.NOSIGNAL));
        if (n != vec.len) return error.BackendUnavailable;
        const got = try checked(linux.read(s.fd, &c.output, aad.len + out_len));
        if (got != aad.len + out_len) return error.BackendUnavailable;
        return c.output[aad.len..][0..out_len];
    }
    fn selftest(c: *Context, s: *Session) bool {
        // Verify a complete bounded request before trusting a new session.
        const A128 = std.crypto.aead.aes_gcm.Aes128Gcm;
        const A256 = std.crypto.aead.aes_gcm.Aes256Gcm;
        var plain: [minimum]u8 = undefined;
        for (&plain, 0..) |*b, i| b.* = @truncate(i * 7);
        var expected: [minimum + 16]u8 = undefined;
        const nonce: [12]u8 = @splat(0x42);
        const aad = "zray kernel crypto verification";
        if (s.keylen == 16) A128.encrypt(expected[0..minimum], expected[minimum..], &plain, aad, nonce, s.key[0..16].*) else A256.encrypt(expected[0..minimum], expected[minimum..], &plain, aad, nonce, s.key);
        const enc = c.exchange(s, nonce, &plain, aad, false) catch return false;
        if (!mem.eql(u8, enc, &expected)) return false;
        const dec = c.exchange(s, nonce, &expected, aad, true) catch return false;
        if (!mem.eql(u8, dec, &plain)) return false;
        expected[expected.len - 1] ^= 1;
        _ = c.exchange(s, nonce, &expected, aad, true) catch |err| return err == error.AuthenticationFailed;
        return false;
    }
    fn connect(c: *Context, s: *Session) bool {
        if (c.policy != .afalg and !s.dev_tried) {
            s.dev_tried = true;
            if (c.openDev(s)) |_| {
                if (c.selftest(s)) return true;
            } else |_| {}
            s.close();
            if (c.policy == .devcrypto) return false;
        }
        if (c.policy == .devcrypto) return false;
        c.openAFALG(s) catch return false;
        if (c.selftest(s)) return true;
        s.close();
        return false;
    }
    pub fn crypt(c: *Context, key: []const u8, nonce: [12]u8, aad: []const u8, src: []const u8, dst: []u8, decrypt: bool) Outcome {
        const n = if (decrypt) src.len -| 16 else src.len;
        if (!c.enabled or (key.len != 16 and key.len != 32) or !c.limits.accepts(n) or aad.len > 256 or dst.len != (if (decrypt) n else n + 16)) return .software;
        defer c.clear();
        const s = c.session(key);
        if (s.disabled) return .software;
        while (true) {
            if (s.fd < 0 and !c.connect(s)) {
                s.disabled = true;
                c.fallbacks += 1;
                return .software;
            }
            const result = c.exchange(s, nonce, src, aad, decrypt) catch |e| {
                if (e == error.AuthenticationFailed and decrypt) {
                    c.auth_failures += 1;
                    return .authentication_failed;
                }
                const was_dev = s.dev;
                s.close();
                c.fallbacks += 1;
                if (was_dev and c.policy == .auto) continue;
                s.disabled = true;
                return .software;
            };
            @memcpy(dst, result);
            c.backend_ops += 1;
            if (!c.notice) {
                sys.log("zray AES-GCM backend: {s}, algorithm={s}", .{ if (s.dev) "devcrypto" else "AF_ALG", c.algorithm });
                c.notice = true;
            }
            return .success;
        }
    }
};
fn appendControl(buffer: []align(@alignOf(linux.cmsghdr)) u8, off: *usize, kind: i32, data: []const u8) void {
    const size = @sizeOf(linux.cmsghdr);
    const h: *linux.cmsghdr = @ptrCast(@alignCast(buffer[off.*..].ptr));
    h.* = .{ .len = size + data.len, .level = 279, .type = kind };
    @memcpy(buffer[off.* + size ..][0..data.len], data);
    off.* += mem.alignForward(usize, size + data.len, linux.cmsg_align);
}

test "kernel crypto policy and native cryptodev ABI" {
    try std.testing.expect(!available(.off));
    for ([_]Policy{ .auto, .afalg, .devcrypto }) |policy|
        try std.testing.expectEqual(builtin.os.tag == .linux, available(policy));
    if (@sizeOf(usize) == 8) {
        try std.testing.expectEqual(@as(usize, 48), @sizeOf(SessionOp));
        try std.testing.expectEqual(@as(usize, 268), @sizeOf(SessionInfo));
        try std.testing.expectEqual(@as(usize, 72), @sizeOf(AuthOp));
        try std.testing.expectEqual(@as(u32, 0xc048636d), ioctlCode(109, AuthOp));
    }
}

test "kernel GCM matches independent software and rejects authentication failures" {
    var c = Context.init(.afalg);
    c.limits = .{ .min_bytes = minimum, .max_bytes = minimum };
    defer c.deinit();
    const key: [16]u8 = @splat(0x25);
    const nonce: [12]u8 = @splat(0x73);
    const plain: [4096]u8 = @splat(0xaa);
    var expected: [4112]u8 = undefined;
    std.crypto.aead.aes_gcm.Aes128Gcm.encrypt(expected[0..4096], expected[4096..], &plain, "header", nonce, key);
    var actual: [4112]u8 = undefined;
    if (c.crypt(&key, nonce, "header", &plain, &actual, false) == .software) return error.SkipZigTest;
    try std.testing.expectEqualSlices(u8, &expected, &actual);
    var decoded: [4096]u8 = undefined;
    try std.testing.expectEqual(Outcome.success, c.crypt(&key, nonce, "header", &actual, &decoded, true));
    try std.testing.expectEqualSlices(u8, &plain, &decoded);
    actual[actual.len - 1] ^= 1;
    @memset(&decoded, 0x55);
    try std.testing.expectEqual(Outcome.authentication_failed, c.crypt(&key, nonce, "header", &actual, &decoded, true));
    for (decoded) |b| try std.testing.expectEqual(@as(u8, 0x55), b);
}

test "configured kernel crypto bounds reject requests before opening a session" {
    var c: Context = .{ .policy = .afalg, .enabled = true, .limits = .{ .min_bytes = 17, .max_bytes = 17 } };
    defer c.deinit();
    const key: [16]u8 = @splat(0);
    const nonce: [12]u8 = @splat(0);
    const data: [16]u8 = @splat(0x42);
    var out: [32]u8 = @splat(0x55);
    try std.testing.expectEqual(Outcome.software, c.crypt(&key, nonce, "", &data, &out, false));
    c.limits = .{ .min_bytes = 1, .max_bytes = 15 };
    try std.testing.expectEqual(Outcome.software, c.crypt(&key, nonce, "", &data, &out, false));
    for (out) |b| try std.testing.expectEqual(@as(u8, 0x55), b);
    for (c.sessions) |session_value| try std.testing.expectEqual(@as(usize, 0), session_value.keylen);
    try std.testing.expect(!(Limits{ .min_bytes = 0 }).valid());
    try std.testing.expect(!(Limits{ .min_bytes = 18, .max_bytes = 17 }).valid());
    try std.testing.expect(!(Limits{ .max_bytes = maximum + 1 }).valid());
    try std.testing.expect((Limits{ .min_bytes = 1, .max_bytes = maximum }).accepts(1));
    try std.testing.expect((Limits{ .min_bytes = 1, .max_bytes = maximum }).accepts(maximum));
}

test "kernel crypto fd reserve covers cached and concurrent temporary sessions" {
    try std.testing.expectEqual(@as(usize, 0), fdReserve(.off, 4));
    try std.testing.expectEqual(@as(usize, 132), fdReserve(.afalg, 4));
    try std.testing.expectEqual(fdReserve(.afalg, 4), fdReserve(.auto, 4));
    try std.testing.expectEqual(fdReserve(.afalg, 4), fdReserve(.devcrypto, 4));
}
