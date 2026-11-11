//! Process-wide admission for optional pipe pairs. Configure before starting
//! workers; connections and mandatory infrastructure always take precedence.
const std = @import("std");
const linux = std.os.linux;
const sys = @import("sys.zig");

pub const Budget = struct {
    limit: usize = 0,
    used: std.atomic.Value(usize) = .init(0),

    pub fn acquire(b: *Budget) bool {
        var n = b.used.load(.monotonic);
        while (n < b.limit) {
            n = b.used.cmpxchgWeak(n, n + 1, .monotonic, .monotonic) orelse return true;
        }
        return false;
    }
    pub fn release(b: *Budget) void {
        const previous = b.used.fetchSub(1, .monotonic);
        std.debug.assert(previous > 0);
    }
};
pub var pipes: Budget = .{};

pub fn pipeLimit(soft: u64, open: usize, connections: usize, workers: usize, extra: usize) usize {
    // Three sockets per slot covers SOCKS UDP control + UDP + upstream too.
    // Count existing/inherited descriptors, future epolls, and a small margin
    // for temporary descriptors. Saturation handles tiny and infinite limits.
    const reserve: u64 = @as(u64, open) +| (@as(u64, connections) *| 3) +| workers +| extra +| 16;
    return @intCast(@min((soft -| reserve) / 2, std.math.maxInt(usize)));
}

pub fn configure(connections: usize, workers: usize, extra: usize) void {
    std.debug.assert(pipes.used.load(.monotonic) == 0);
    pipes.limit = 0;
    var limit: linux.rlimit = undefined;
    if (linux.errno(linux.getrlimit(.NOFILE, &limit)) != .SUCCESS) return;
    const open = openDescriptors() orelse return; // optional optimization
    pipes.limit = pipeLimit(limit.cur, open, connections, workers, extra);
    sys.log("splice pipe budget: {d} pairs, fd soft limit {d}", .{ pipes.limit, limit.cur });
}

fn openDescriptors() ?usize {
    const rc = linux.openat(linux.AT.FDCWD, "/proc/self/fd", .{ .DIRECTORY = true, .CLOEXEC = true }, 0);
    if (linux.errno(rc) != .SUCCESS) return null;
    const fd: sys.fd_t = @intCast(rc);
    defer sys.close(fd);
    var buf: [4096]u8 align(@alignOf(linux.dirent64)) = undefined;
    var count: usize = 0;
    while (true) {
        const n = linux.getdents64(fd, &buf, buf.len);
        switch (linux.errno(n)) {
            .INTR => continue,
            .SUCCESS => {},
            else => return null,
        }
        if (n == 0) break;
        var off: usize = 0;
        while (off < n) {
            const e: *align(1) const linux.dirent64 = @ptrCast(&buf[off]);
            if (e.reclen == 0 or off + e.reclen > n) return null;
            const name = buf[off + @offsetOf(linux.dirent64, "name")];
            if (name != '.') count += 1;
            off += e.reclen;
        }
    }
    return count - 1; // exclude our temporary directory descriptor
}

test "pipe budget reserves sockets and infrastructure even under tiny fd limits" {
    try std.testing.expectEqual(@as(usize, 0), pipeLimit(64, 8, 16, 2, 0));
    try std.testing.expectEqual(@as(usize, 20), pipeLimit(128, 8, 16, 2, 14));
    try std.testing.expectEqual(@as(usize, 0), pipeLimit(1, 8, 16, 2, 0));
    try std.testing.expect(openDescriptors().? >= 3);
}

test "workers compete for one process-wide pipe quota" {
    var quota: Budget = .{ .limit = 8 };
    var admitted = std.atomic.Value(usize).init(0);
    const contender = struct {
        fn run(b: *Budget, total: *std.atomic.Value(usize)) void {
            for (0..32) |_| if (b.acquire()) {
                _ = total.fetchAdd(1, .monotonic);
            };
        }
    };
    var threads: [4]std.Thread = undefined;
    for (&threads) |*t| t.* = try std.Thread.spawn(.{}, contender.run, .{ &quota, &admitted });
    for (threads) |t| t.join();
    try std.testing.expectEqual(@as(usize, 8), admitted.load(.monotonic));
    try std.testing.expectEqual(@as(usize, 8), quota.used.load(.monotonic));
    for (0..8) |_| quota.release();
    try std.testing.expectEqual(@as(usize, 0), quota.used.load(.monotonic));
}
