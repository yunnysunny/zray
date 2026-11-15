//! Process-wide admission for optional pipe pairs. Connections and mandatory
//! infrastructure always take precedence.
const std = @import("std");
const linux = std.os.linux;
const sys = @import("sys.zig");

pub const Budget = struct {
    limit: usize = 0,
    used: usize = 0,

    pub fn acquire(b: *Budget) bool {
        if (b.used >= b.limit) return false;
        b.used += 1;
        return true;
    }
    pub fn release(b: *Budget) void {
        std.debug.assert(b.used > 0);
        b.used -= 1;
    }
};
pub var pipes: Budget = .{};

pub fn pipeLimit(soft: u64, open: usize, connections: usize, extra: usize) usize {
    // Three sockets per slot covers SOCKS UDP control + UDP + upstream too.
    // Count existing/inherited descriptors and a small margin
    // for temporary descriptors. Saturation handles tiny and infinite limits.
    const reserve: u64 = @as(u64, open) +| (@as(u64, connections) *| 3) +| extra +| 16;
    return @intCast(@min((soft -| reserve) / 2, std.math.maxInt(usize)));
}

pub fn configure(connections: usize, extra: usize) void {
    std.debug.assert(pipes.used == 0);
    pipes.limit = 0;
    var limit: linux.rlimit = undefined;
    if (linux.errno(linux.getrlimit(.NOFILE, &limit)) != .SUCCESS) return;
    const open = openDescriptors() orelse return; // optional optimization
    pipes.limit = pipeLimit(limit.cur, open, connections, extra);
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
    try std.testing.expectEqual(@as(usize, 0), pipeLimit(64, 8, 16, 0));
    try std.testing.expectEqual(@as(usize, 21), pipeLimit(128, 8, 16, 14));
    try std.testing.expectEqual(@as(usize, 0), pipeLimit(1, 8, 16, 0));
    try std.testing.expect(openDescriptors().? >= 3);
}

test "pipe quota is bounded and reusable" {
    var quota: Budget = .{ .limit = 8 };
    for (0..8) |_| try std.testing.expect(quota.acquire());
    try std.testing.expect(!quota.acquire());
    try std.testing.expectEqual(@as(usize, 8), quota.used);
    for (0..8) |_| quota.release();
    try std.testing.expectEqual(@as(usize, 0), quota.used);
    try std.testing.expect(quota.acquire());
    quota.release();
}
