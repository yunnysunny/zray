//! A lazily allocated, bounded, nonblocking socket -> pipe -> socket relay.
//! The owner drains pre-existing user buffers before calling pump. Socket
//! readiness is enough: read source only with an empty pipe, poll destination
//! for writable readiness while bytes remain. Each direction owns its pipe.
const std = @import("std");
const linux = std.os.linux;
const sys = @import("sys.zig");
const fd_budget = @import("fd_budget.zig");

pub const Pipe = struct {
    fds: ?[2]sys.fd_t = null,
    budget: *fd_budget.Budget = &fd_budget.pipes,
    pending: usize = 0,
    disabled: bool = false,
    eof: bool = false,
    bytes: u64 = 0,

    pub fn deinit(p: *Pipe) void {
        if (p.fds) |fds| {
            for (fds) |fd| sys.close(fd);
            p.budget.release();
        }
        p.fds = null;
        p.pending = 0;
    }

    /// Return false only if no source bytes were consumed and ordinary
    /// read/write should be used instead. The pipe is at most its kernel
    /// capacity; the budget bounds work per event so other clients run.
    pub fn pump(p: *Pipe, src: sys.fd_t, dst: sys.fd_t, budget: usize) !bool {
        if (p.disabled) return false;
        if (p.fds == null) {
            if (!p.budget.acquire()) {
                p.disabled = true;
                return false;
            }
            var fds: [2]sys.fd_t = undefined;
            const rc = linux.pipe2(&fds, .{ .NONBLOCK = true, .CLOEXEC = true });
            if (linux.errno(rc) != .SUCCESS) {
                p.budget.release();
                p.disabled = true;
                return false;
            }
            p.fds = fds;
        }
        const fds = p.fds.?;
        var transferred: usize = 0;
        while (transferred < budget) {
            if (p.pending > 0) {
                const n = transfer(fds[0], dst, p.pending) catch |e| switch (e) {
                    error.WouldBlock => return true,
                    error.Interrupted => continue,
                    else => return e,
                };
                if (n == 0) return error.BrokenPipe;
                p.pending -= n;
                p.bytes += n;
                sys.counters.splice_bytes += n;
                transferred += n;
                continue;
            }
            if (p.eof) return true;
            const n = transfer(src, fds[1], @min(budget - transferred, 65536)) catch |e| switch (e) {
                error.WouldBlock => return true,
                error.Interrupted => continue,
                error.Unsupported => {
                    p.disabled = true;
                    p.deinit();
                    return false;
                },
                else => return e,
            };
            if (n == 0) {
                p.eof = true;
                return true;
            }
            p.pending = n;
        }
        return true;
    }
};

fn transfer(src: sys.fd_t, dst: sys.fd_t, len: usize) !usize {
    sys.counters.splice_calls += 1;
    const rc = linux.syscall6(.splice, @bitCast(@as(isize, src)), 0, @bitCast(@as(isize, dst)), 0, len, 3); // MOVE | NONBLOCK
    return switch (linux.errno(rc)) {
        .SUCCESS => rc,
        .AGAIN => error.WouldBlock,
        .INTR => error.Interrupted,
        .INVAL, .NOSYS, .OPNOTSUPP => error.Unsupported,
        .PIPE => error.BrokenPipe,
        else => error.ConnectionReset,
    };
}

test "low fd limit: pipe quota exhaustion preserves new TCP connections and copy fallback" {
    var saved: linux.rlimit = undefined;
    try std.testing.expectEqual(linux.E.SUCCESS, linux.errno(linux.getrlimit(.NOFILE, &saved)));
    const low: linux.rlimit = .{ .cur = @min(saved.cur, 64), .max = saved.max };
    try std.testing.expectEqual(linux.E.SUCCESS, linux.errno(linux.setrlimit(.NOFILE, &low)));
    defer _ = linux.setrlimit(.NOFILE, &saved);
    const old_limit = fd_budget.pipes.limit;
    defer fd_budget.pipes.limit = old_limit;
    fd_budget.configure(4, 2, 0);
    var quota: fd_budget.Budget = .{ .limit = fd_budget.pipes.limit };
    try std.testing.expect(quota.limit > 0 and quota.limit < 32);
    var pair: [2]sys.fd_t = undefined;
    try std.testing.expectEqual(linux.E.SUCCESS, linux.errno(linux.socketpair(linux.AF.UNIX, linux.SOCK.STREAM | linux.SOCK.NONBLOCK | linux.SOCK.CLOEXEC, 0, &pair)));
    defer for (pair) |fd| sys.close(fd);
    var pipes: [32]Pipe = @splat(.{ .budget = &quota });
    defer for (&pipes) |*p| p.deinit();
    for (pipes[0..quota.limit]) |*p| try std.testing.expect(try p.pump(pair[0], pair[1], 1024));
    try std.testing.expectEqual(quota.limit, quota.used.load(.monotonic));
    const fallback = &pipes[quota.limit];
    try std.testing.expect(!try fallback.pump(pair[0], pair[1], 1024));
    // Start and accept an actual new TCP connection while all pipe quota is used.
    const listener = try sys.tcpSocket(linux.AF.INET);
    defer sys.close(listener);
    const local = sys.SockAddr.fromIpv4(.{ 127, 0, 0, 1 }, 0);
    try sys.bind(listener, &local);
    try sys.listen(listener, 1);
    const sender = try sys.tcpSocket(linux.AF.INET);
    defer sys.close(sender);
    const addr = try sys.localAddr(listener);
    _ = try sys.connect(sender, &addr);
    try std.testing.expect(try sys.pollIn(listener, 5000));
    const accepted = try sys.accept(listener);
    defer sys.close(accepted);
    const upstream = try sys.tcpSocket(linux.AF.INET);
    defer sys.close(upstream);
    try std.testing.expectEqual(@as(usize, 4), try sys.write(sender, "tail"));
    var buf: [4]u8 = undefined;
    try std.testing.expect(try sys.pollIn(accepted, 5000));
    try std.testing.expectEqual(@as(usize, 4), try sys.read(accepted, &buf));
    try std.testing.expectEqualSlices(u8, "tail", &buf);
    // Refused pipe admission must not consume source bytes.
    try std.testing.expectEqual(@as(usize, 4), try sys.write(pair[1], "copy"));
    try std.testing.expect(!try fallback.pump(pair[0], pair[1], 1024));
    try std.testing.expectEqual(@as(usize, 4), try sys.read(pair[0], &buf));
    try std.testing.expectEqualSlices(u8, "copy", &buf);
    pipes[0].deinit();
    pipes[0].deinit(); // release exactly once
    var replacement: Pipe = .{ .budget = &quota };
    defer replacement.deinit();
    try std.testing.expect(try replacement.pump(pair[0], pair[1], 1024));
    try std.testing.expectEqual(quota.limit, quota.used.load(.monotonic));
}

test "failed pipe2 returns its reserved quota" {
    var saved: linux.rlimit = undefined;
    try std.testing.expectEqual(linux.E.SUCCESS, linux.errno(linux.getrlimit(.NOFILE, &saved)));
    const low: linux.rlimit = .{ .cur = @min(saved.cur, 64), .max = saved.max };
    try std.testing.expectEqual(linux.E.SUCCESS, linux.errno(linux.setrlimit(.NOFILE, &low)));
    defer _ = linux.setrlimit(.NOFILE, &saved);
    var fds: [64]sys.fd_t = undefined;
    var count: usize = 0;
    defer for (fds[0..count]) |fd| sys.close(fd);
    while (count < fds.len) {
        const rc = linux.openat(linux.AT.FDCWD, "/dev/null", .{ .CLOEXEC = true }, 0);
        if (linux.errno(rc) != .SUCCESS) break;
        fds[count] = @intCast(rc);
        count += 1;
    }
    var quota: fd_budget.Budget = .{ .limit = 1 };
    var p: Pipe = .{ .budget = &quota };
    defer p.deinit();
    try std.testing.expect(!try p.pump(-1, -1, 1024));
    try std.testing.expect(p.fds == null);
    try std.testing.expectEqual(@as(usize, 0), quota.used.load(.monotonic));
}
