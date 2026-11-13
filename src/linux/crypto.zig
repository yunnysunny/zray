//! A single-producer/single-consumer crypto executor per network worker.
//! Jobs borrow a paused connection's TLS state and persistent record buffers.
//! Release/acquire publication and eventfd completion keep ownership explicit.
const std = @import("std");
const sys = @import("sys.zig");
const kernel_crypto = @import("kernel_crypto.zig");
const client = @import("../tls/client.zig");
const max_rec = std.crypto.tls.max_ciphertext_record_len;

pub const Operation = enum { encrypt, decrypt };
pub const Status = enum(u8) { idle, queued, running, done };
pub const Job = struct {
    status: std.atomic.Value(Status) = .init(.idle),
    operation: Operation = .encrypt,
    tls: *client.Client = undefined,
    data: []u8 = undefined,
    output: []u8 = undefined,
    input: [max_rec]u8 = undefined,
    reply: [max_rec]u8 = undefined,
    result: client.Result = .{},
    produced: usize = 0,
    failure: ?client.Error = null,
    notify_fd: sys.fd_t = -1,

    pub fn pending(j: *const Job) bool {
        return j.status.load(.acquire) != .idle;
    }
    pub fn submit(j: *Job, operation: Operation, tls: *client.Client, data: []u8, output: []u8) void {
        std.debug.assert(!j.pending());
        j.operation = operation;
        j.tls = tls;
        j.data = data;
        j.output = output;
        j.failure = null;
        j.produced = 0;
        j.result = .{};
        j.status.store(.queued, .release);
        sys.eventNotify(j.notify_fd);
    }
};

pub const Executor = struct {
    jobs: []Job,
    request_fd: sys.fd_t,
    completed_fd: sys.fd_t,
    stopping: std.atomic.Value(bool) = .init(false),
    thread: ?std.Thread = null,
    backend: kernel_crypto.Context,
    submitted: u64 = 0,
    completed: u64 = 0,
    // Network-thread diagnostics use published counters, never borrow the
    // executor-owned Context while a kernel request is running.
    backend_ops: std.atomic.Value(usize) = .init(0),
    fallbacks: std.atomic.Value(usize) = .init(0),
    auth_failures: std.atomic.Value(usize) = .init(0),

    /// The caller keeps Executor at a stable address through stop().
    pub fn init(allocator: std.mem.Allocator, count: usize, policy: kernel_crypto.Policy) !Executor {
        const request = try sys.eventCreate(false);
        errdefer sys.close(request);
        const completed = try sys.eventCreate(true);
        errdefer sys.close(completed);
        const jobs = try allocator.alloc(Job, count);
        for (jobs) |*j| j.* = .{ .notify_fd = request };
        return .{ .jobs = jobs, .request_fd = request, .completed_fd = completed, .backend = kernel_crypto.Context.init(policy) };
    }
    pub fn start(e: *Executor) !void {
        e.thread = try std.Thread.spawn(.{}, run, .{e});
    }
    pub fn stop(e: *Executor, allocator: std.mem.Allocator) void {
        e.stopping.store(true, .release);
        sys.eventNotify(e.request_fd);
        if (e.thread) |t| t.join();
        e.thread = null;
        sys.close(e.request_fd);
        sys.close(e.completed_fd);
        allocator.free(e.jobs);
    }
    fn run(e: *Executor) void {
        kernel_crypto.current = &e.backend;
        defer {
            e.backend.deinit();
            kernel_crypto.current = null;
        }
        while (true) {
            sys.eventDrain(e.request_fd);
            var completed = false;
            for (e.jobs) |*j| {
                if (j.status.load(.acquire) != .queued) continue;
                j.status.store(.running, .release);
                switch (j.operation) {
                    .encrypt => {
                        if (j.tls.encrypt(j.data, j.output)) |record| j.produced = record.len else |err| j.failure = err;
                    },
                    .decrypt => {
                        if (j.tls.handleRecord(j.data, &j.reply)) |result| j.result = result else |err| j.failure = err;
                    },
                }
                e.backend_ops.store(@truncate(e.backend.backend_ops), .monotonic);
                e.fallbacks.store(@truncate(e.backend.fallbacks), .monotonic);
                e.auth_failures.store(@truncate(e.backend.auth_failures), .monotonic);
                j.status.store(.done, .release);
                completed = true;
            }
            if (completed) sys.eventNotify(e.completed_fd);
            if (e.stopping.load(.acquire)) break;
        }
    }
};

fn waitDone(e: *Executor, index: usize) !void {
    const ep = try sys.epollCreate();
    defer sys.close(ep);
    try sys.epollAdd(ep, e.completed_fd, sys.EPOLL.IN, 0);
    const deadline = sys.monotonicMs() + 5000;
    while (e.jobs[index].status.load(.acquire) != .done) {
        if (sys.monotonicMs() >= deadline) return error.CryptoTimeout;
        var events: [1]sys.Event = undefined;
        _ = try sys.epollWait(ep, &events, 100);
        sys.eventDrain(e.completed_fd);
    }
}

test "crypto executor preserves per-connection TLS ownership through reuse and bad tags" {
    const record = @import("../tls/record.zig");
    var hs: [2][64]u8 = undefined;
    var clients: [2]client.Client = undefined;
    const key: [16]u8 = @splat(0x25);
    const iv: [12]u8 = @splat(0x41);
    var e = try Executor.init(std.testing.allocator, 2, .off);
    // Exercise the production AF_ALG selection; software remains the oracle.
    e.backend = kernel_crypto.Context.init(.afalg);
    try e.start();
    defer e.stop(std.testing.allocator);
    for (&clients, 0..) |*c, i| {
        c.* = client.Client.init(.{ .entropy = @splat(0), .verifier = client.Verifier.insecure, .handshake_buf = &hs[i] });
        c.state = .connected;
        c.write = record.Cipher.init(.aes_128_gcm_sha256, &key, &iv);
        c.read = record.Cipher.init(.aes_128_gcm_sha256, &key, &iv);
        @memset(e.jobs[i].input[0..8192], @intCast(0x61 + i));
        e.jobs[i].submit(.encrypt, c, e.jobs[i].input[0..8192], &e.jobs[i].reply);
    }
    for (&clients, 0..) |*c, i| {
        const j = &e.jobs[i];
        try waitDone(&e, i);
        try std.testing.expect(j.failure == null);
        var reference = record.Cipher.init(.aes_128_gcm_sha256, &key, &iv);
        var expected: [max_rec]u8 = undefined;
        const sealed = try reference.seal(.application_data, j.input[0..8192], &expected);
        try std.testing.expectEqualSlices(u8, sealed, j.reply[0..j.produced]);
        const size = j.produced;
        @memcpy(j.input[0..size], j.reply[0..size]);
        j.status.store(.idle, .release);
        j.submit(.decrypt, c, j.input[0..size], &j.reply);
        try waitDone(&e, i);
        try std.testing.expect(j.failure == null);
        try std.testing.expectEqual(@as(usize, 8192), j.result.app_data.len);
        for (j.result.app_data) |b| try std.testing.expectEqual(@as(u8, @intCast(0x61 + i)), b);
        // A fresh sequence-zero ciphertext with a corrupted tag must fail;
        // no success result may survive from the previous job in this slot.
        c.read = record.Cipher.init(.aes_128_gcm_sha256, &key, &iv);
        @memcpy(j.input[0..sealed.len], sealed);
        j.input[sealed.len - 1] ^= 1;
        j.status.store(.idle, .release);
        j.submit(.decrypt, c, j.input[0..sealed.len], &j.reply);
        try waitDone(&e, i);
        try std.testing.expectEqual(error.BadRecordMac, j.failure.?);
        try std.testing.expectEqual(@as(usize, 0), j.result.app_data.len);
        j.status.store(.idle, .release);
    }
}
