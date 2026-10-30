//! Thin, allocation-free wrappers over the Linux syscalls the event loop
//! needs. Everything is non-blocking; EAGAIN is surfaced as `WouldBlock`.

const std = @import("std");
const linux = std.os.linux;

pub const fd_t = linux.fd_t;
pub const E = linux.E;

pub const Error = error{ WouldBlock, ConnectionReset, BrokenPipe, Interrupted, Unexpected };

fn check(rc: usize) Error!usize {
    return switch (linux.errno(rc)) {
        .SUCCESS => rc,
        .AGAIN => error.WouldBlock,
        .INTR => error.Interrupted,
        .CONNRESET, .CONNABORTED, .TIMEDOUT, .HOSTUNREACH, .NETUNREACH, .CONNREFUSED => error.ConnectionReset,
        .PIPE => error.BrokenPipe,
        else => error.Unexpected,
    };
}

pub fn errnoName(rc: usize) []const u8 {
    return @tagName(linux.errno(rc));
}

// ---- sockets ----------------------------------------------------------------

pub const SockAddr = union(enum) {
    v4: linux.sockaddr.in,
    v6: linux.sockaddr.in6,

    /// `sin_addr` holds the four octets in memory order. Go through a pointer,
    /// not `@bitCast`: an array <-> integer bitcast maps element 0 to the low
    /// bits regardless of endianness, which reverses the address on
    /// big-endian MIPS (127.0.0.1 became 1.0.0.127).
    pub fn fromIpv4(ip: [4]u8, port: u16) SockAddr {
        const raw: *align(1) const u32 = @ptrCast(&ip);
        return .{ .v4 = .{ .port = std.mem.nativeToBig(u16, port), .addr = raw.* } };
    }
    /// The IPv4 octets in memory order; the inverse of `fromIpv4`.
    pub fn ipv4Bytes(a: *const linux.sockaddr.in) [4]u8 {
        const raw: *const [4]u8 = @ptrCast(&a.addr);
        return raw.*;
    }
    pub fn fromIpv6(ip: [16]u8, port: u16) SockAddr {
        return .{ .v6 = .{ .port = std.mem.nativeToBig(u16, port), .flowinfo = 0, .addr = ip, .scope_id = 0 } };
    }
    pub fn getPort(a: SockAddr) u16 {
        return std.mem.bigToNative(u16, switch (a) {
            .v4 => |p| p.port,
            .v6 => |p| p.port,
        });
    }
    pub fn family(a: SockAddr) u32 {
        return switch (a) {
            .v4 => linux.AF.INET,
            .v6 => linux.AF.INET6,
        };
    }
    fn ptr(a: *const SockAddr) *const linux.sockaddr {
        return switch (a.*) {
            .v4 => |*p| @ptrCast(p),
            .v6 => |*p| @ptrCast(p),
        };
    }
    /// Decode the kernel's sockaddr output (sockaddr_in6 is large enough for both).
    fn fromRaw(raw: *const linux.sockaddr.in6) Error!SockAddr {
        const fam = @as(*const linux.sockaddr, @ptrCast(raw)).family;
        if (fam == linux.AF.INET) return .{ .v4 = @as(*const linux.sockaddr.in, @ptrCast(raw)).* };
        if (fam == linux.AF.INET6) return .{ .v6 = raw.* };
        return error.Unexpected;
    }

    pub fn eql(a: SockAddr, b: SockAddr) bool {
        return switch (a) {
            .v4 => |x| b == .v4 and x.port == b.v4.port and x.addr == b.v4.addr,
            .v6 => |x| b == .v6 and x.port == b.v6.port and std.mem.eql(u8, &x.addr, &b.v6.addr),
        };
    }

    fn len(a: SockAddr) linux.socklen_t {
        return switch (a) {
            .v4 => @sizeOf(linux.sockaddr.in),
            .v6 => @sizeOf(linux.sockaddr.in6),
        };
    }

    /// Parse "1.2.3.4" / "[::1]" / "::1" style text (no port).
    pub fn parseIp(text: []const u8, port: u16) !SockAddr {
        var t = text;
        if (t.len > 0 and t[0] == '[' and t[t.len - 1] == ']') t = t[1 .. t.len - 1];
        if (std.mem.indexOfScalar(u8, t, ':') != null) {
            const a = try std.Io.net.Ip6Address.parse(t, port);
            return fromIpv6(a.bytes, port);
        }
        const a = try std.Io.net.Ip4Address.parse(t, port);
        return fromIpv4(a.bytes, port);
    }
};

pub fn tcpSocket(fam: u32) Error!fd_t {
    const rc = try check(linux.socket(fam, linux.SOCK.STREAM | linux.SOCK.NONBLOCK | linux.SOCK.CLOEXEC, 0));
    return @intCast(rc);
}

pub fn udpSocket(fam: u32) Error!fd_t {
    const rc = try check(linux.socket(fam, linux.SOCK.DGRAM | linux.SOCK.NONBLOCK | linux.SOCK.CLOEXEC, 0));
    return @intCast(rc);
}

pub fn localAddr(fd: fd_t) Error!SockAddr {
    var raw: linux.sockaddr.in6 = undefined;
    var alen: linux.socklen_t = @sizeOf(linux.sockaddr.in6);
    _ = try check(linux.getsockname(fd, @ptrCast(&raw), &alen));
    return SockAddr.fromRaw(&raw);
}

pub const Datagram = struct { len: usize, from: SockAddr };

pub fn recvFrom(fd: fd_t, buf: []u8) Error!Datagram {
    var raw: linux.sockaddr.in6 = undefined;
    var alen: linux.socklen_t = @sizeOf(linux.sockaddr.in6);
    const n = try check(linux.recvfrom(fd, buf.ptr, buf.len, 0, @ptrCast(&raw), &alen));
    return .{ .len = n, .from = try SockAddr.fromRaw(&raw) };
}

pub fn sendTo(fd: fd_t, buf: []const u8, to: *const SockAddr) Error!usize {
    return check(linux.sendto(fd, buf.ptr, buf.len, 0, to.ptr(), to.len()));
}

/// Block until `fd` is readable or `timeout_ms` elapses (startup helpers
/// only; the event loop uses epoll). Returns false on timeout.
pub fn pollIn(fd: fd_t, timeout_ms: i32) Error!bool {
    var fds = [_]linux.pollfd{.{ .fd = fd, .events = linux.POLL.IN }};
    const n = check(linux.poll(&fds, 1, timeout_ms)) catch |e| switch (e) {
        error.Interrupted => return false,
        else => return e,
    };
    return n > 0;
}

pub fn setsockoptInt(fd: fd_t, level: i32, opt: u32, value: i32) Error!void {
    _ = try check(linux.setsockopt(fd, level, opt, @ptrCast(&value), @sizeOf(i32)));
}

pub fn setNoDelay(fd: fd_t) void {
    setsockoptInt(fd, linux.IPPROTO.TCP, linux.TCP.NODELAY, 1) catch {};
}

pub fn setReuseAddr(fd: fd_t) void {
    setsockoptInt(fd, linux.SOL.SOCKET, linux.SO.REUSEADDR, 1) catch {};
}

/// Per-socket buffer limits so memory stays predictable on small boxes.
pub fn setBufferSizes(fd: fd_t, rcv: i32, snd: i32) void {
    setsockoptInt(fd, linux.SOL.SOCKET, linux.SO.RCVBUF, rcv) catch {};
    setsockoptInt(fd, linux.SOL.SOCKET, linux.SO.SNDBUF, snd) catch {};
}

pub fn bind(fd: fd_t, addr: *const SockAddr) Error!void {
    const rc = linux.bind(fd, addr.ptr(), addr.len());
    // Startup-only call; keep the raw errno visible since `check` folds it.
    if (linux.errno(rc) != .SUCCESS) log("bind: {s}", .{errnoName(rc)});
    _ = try check(rc);
}

pub fn listen(fd: fd_t, backlog: u32) Error!void {
    _ = try check(linux.listen(fd, backlog));
}

/// Returns the accepted fd, or `WouldBlock`.
pub fn accept(fd: fd_t) Error!fd_t {
    const rc = try check(linux.accept4(fd, null, null, linux.SOCK.NONBLOCK | linux.SOCK.CLOEXEC));
    return @intCast(rc);
}

/// Non-blocking connect. Returns true if connected immediately, false if in
/// progress (wait for EPOLLOUT and call `connectResult`).
pub fn connect(fd: fd_t, addr: *const SockAddr) Error!bool {
    const rc = linux.connect(fd, addr.ptr(), addr.len());
    return switch (linux.errno(rc)) {
        .SUCCESS => true,
        .INPROGRESS => false,
        .INTR => false,
        .CONNREFUSED, .HOSTUNREACH, .NETUNREACH, .TIMEDOUT => error.ConnectionReset,
        else => error.Unexpected,
    };
}

/// SO_ERROR after an asynchronous connect completes.
pub fn connectResult(fd: fd_t) Error!void {
    var err: i32 = 0;
    var len: linux.socklen_t = @sizeOf(i32);
    _ = try check(linux.getsockopt(fd, linux.SOL.SOCKET, linux.SO.ERROR, @ptrCast(&err), &len));
    if (err != 0) _ = try check(@as(usize, @bitCast(@as(isize, -err))));
}

/// Original destination of a connection redirected by netfilter REDIRECT
/// (iptables -j REDIRECT / nft redirect). Linux reports it via
/// SO_ORIGINAL_DST (80) on SOL_IP, or IP6T_SO_ORIGINAL_DST (80) on SOL_IPV6.
pub fn originalDst(fd: fd_t) Error!SockAddr {
    const SO_ORIGINAL_DST: u32 = 80;
    var v4: linux.sockaddr.in = undefined;
    var len4: linux.socklen_t = @sizeOf(linux.sockaddr.in);
    if (linux.errno(linux.getsockopt(fd, linux.SOL.IP, SO_ORIGINAL_DST, @ptrCast(&v4), &len4)) == .SUCCESS) {
        return .{ .v4 = v4 };
    }
    var v6: linux.sockaddr.in6 = undefined;
    var len6: linux.socklen_t = @sizeOf(linux.sockaddr.in6);
    _ = try check(linux.getsockopt(fd, linux.SOL.IPV6, SO_ORIGINAL_DST, @ptrCast(&v6), &len6));
    return .{ .v6 = v6 };
}

pub fn read(fd: fd_t, buf: []u8) Error!usize {
    return check(linux.read(fd, buf.ptr, buf.len));
}

pub fn write(fd: fd_t, buf: []const u8) Error!usize {
    return check(linux.write(fd, buf.ptr, buf.len));
}

pub fn close(fd: fd_t) void {
    _ = linux.close(fd);
}

pub fn shutdownWrite(fd: fd_t) void {
    _ = linux.shutdown(fd, linux.SHUT.WR);
}

// ---- epoll ------------------------------------------------------------------

pub const Event = linux.epoll_event;
pub const EPOLL = linux.EPOLL;

pub fn epollCreate() Error!fd_t {
    return @intCast(try check(linux.epoll_create1(linux.EPOLL.CLOEXEC)));
}

pub fn epollAdd(ep: fd_t, fd: fd_t, events: u32, data: u64) Error!void {
    var ev: Event = .{ .events = events, .data = .{ .u64 = data } };
    _ = try check(linux.epoll_ctl(ep, linux.EPOLL.CTL_ADD, fd, &ev));
}

pub fn epollMod(ep: fd_t, fd: fd_t, events: u32, data: u64) Error!void {
    var ev: Event = .{ .events = events, .data = .{ .u64 = data } };
    _ = try check(linux.epoll_ctl(ep, linux.EPOLL.CTL_MOD, fd, &ev));
}

pub fn epollDel(ep: fd_t, fd: fd_t) void {
    _ = linux.epoll_ctl(ep, linux.EPOLL.CTL_DEL, fd, null);
}

/// Returns the number of ready events; `timeout_ms` < 0 blocks forever.
pub fn epollWait(ep: fd_t, events: []Event, timeout_ms: i32) Error!usize {
    return check(linux.epoll_wait(ep, events.ptr, @intCast(events.len), timeout_ms)) catch |e| switch (e) {
        error.Interrupted => 0,
        else => e,
    };
}

// ---- misc -------------------------------------------------------------------

pub fn monotonicSeconds() u64 {
    var ts: linux.timespec = undefined;
    _ = linux.clock_gettime(.MONOTONIC, &ts);
    return @intCast(ts.sec);
}

pub fn realtimeSeconds() i64 {
    var ts: linux.timespec = undefined;
    _ = linux.clock_gettime(.REALTIME, &ts);
    return @intCast(ts.sec);
}

pub fn randomBytes(buf: []u8) void {
    var off: usize = 0;
    while (off < buf.len) {
        const rc = linux.getrandom(buf[off..].ptr, buf.len - off, 0);
        if (linux.errno(rc) != .SUCCESS) continue;
        off += rc;
    }
}

pub fn ignoreSigpipe() void {
    var act: linux.Sigaction = .{
        .handler = .{ .handler = linux.SIG.IGN },
        .mask = linux.sigemptyset(),
        .flags = 0,
    };
    _ = linux.sigaction(.PIPE, &act, null);
}

/// Unbuffered stderr logging.
pub fn log(comptime fmt: []const u8, args: anytype) void {
    var buf: [512]u8 = undefined;
    const s = std.fmt.bufPrint(&buf, fmt ++ "\n", args) catch blk: {
        buf[buf.len - 1] = '\n';
        break :blk buf[0..];
    };
    var off: usize = 0;
    while (off < s.len) {
        const rc = linux.write(2, s[off..].ptr, s.len - off);
        if (linux.errno(rc) != .SUCCESS) return;
        off += rc;
    }
}
