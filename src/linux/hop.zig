//! Bounded snapshots shared by network workers. No worker reads another
//! worker's Conn. An outer attempt reserves its key before connect can be
//! accepted; dropping the attempt removes its snapshot, including closed hops.
const std = @import("std");
const conn = @import("conn.zig");

pub const Registry = struct {
    pub const Entry = struct { key: u32 = 0, snapshot: ?conn.HopEnd = null };
    mutex: std.atomic.Mutex = .unlocked,
    entries: []Entry,

    pub fn init(entries: []Entry) Registry {
        @memset(entries, .{});
        return .{ .entries = entries };
    }
    pub fn reserve(r: *Registry, id: u32) !void {
        std.debug.assert(id != 0);
        while (!r.mutex.tryLock()) std.atomic.spinLoopHint();
        defer r.mutex.unlock();
        for (r.entries) |*e| if (e.key == 0) {
            e.* = .{ .key = id };
            return;
        };
        return error.HopRegistryFull;
    }
    pub fn publish(r: *Registry, id: u32, snapshot: conn.HopEnd) void {
        while (!r.mutex.tryLock()) std.atomic.spinLoopHint();
        defer r.mutex.unlock();
        for (r.entries) |*e| if (e.key == id) {
            e.snapshot = snapshot;
            return;
        };
    }
    pub fn get(r: *Registry, id: u32) ?conn.HopEnd {
        while (!r.mutex.tryLock()) std.atomic.spinLoopHint();
        defer r.mutex.unlock();
        for (r.entries) |e| if (e.key == id) return e.snapshot;
        return null;
    }
    pub fn release(r: *Registry, id: u32) void {
        while (!r.mutex.tryLock()) std.atomic.spinLoopHint();
        defer r.mutex.unlock();
        for (r.entries) |*e| if (e.key == id) {
            e.* = .{};
            return;
        };
    }
};

// Local listener port plus the peer's ephemeral port identifies the loopback
// connection even when different hop listeners reuse an ephemeral port.
pub fn key(peer: u16, listener: u16) u32 {
    return (@as(u32, peer) << 16) | listener;
}
