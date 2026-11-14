const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const dynamic = b.option(bool, "dynamic", "Dynamically link the system C library") orelse false;
    // `--release` defaults to ReleaseSmall (routers have small flash);
    // `-Doptimize=fast` overrides it for targets with room to spare.
    const optimize = b.option(
        std.builtin.Optimize,
        "optimize",
        "Override the optimization mode (default: small with --release, debug otherwise)",
    ) orelse b.standardOptimizeOption(.{ .preferred_optimize_mode = .small });

    const root_mod = b.createModule(.{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
        // Routers have small flash; keep the binary lean.
        .strip = optimize != .debug,
        .link_libc = dynamic,
    });

    const exe = b.addExecutable(.{
        .name = "zray",
        .linkage = if (dynamic) .dynamic else .static,
        .root_module = root_mod,
    });
    b.installArtifact(exe);

    const run_cmd = b.addRunArtifact(exe);
    run_cmd.step.dependOn(b.getInstallStep());
    run_cmd.addPassthruArgs();
    const run_step = b.step("run", "Run zray");
    run_step.dependOn(&run_cmd.step);

    // Live REALITY handshake probe: zig build probe -- <ip> <port> <sni> <pk> [short_id]
    const probe_mod = b.createModule(.{
        .root_source_file = b.path("src/probe.zig"),
        .link_libc = dynamic,
        .target = target,
        .optimize = optimize,
    });
    const probe = b.addExecutable(.{
        .name = "probe",
        .root_module = probe_mod,
        .linkage = if (dynamic) .dynamic else .static,
    });
    const probe_run = b.addRunArtifact(probe);
    probe_run.addPassthruArgs();
    const probe_step = b.step("probe", "Run a live REALITY handshake probe");
    probe_step.dependOn(&probe_run.step);

    const test_mod = b.createModule(.{
        .root_source_file = b.path("src/tests.zig"),
        .link_libc = dynamic,
        .target = target,
        .optimize = optimize,
    });
    const unit_tests = b.addTest(.{ .root_module = test_mod });
    unit_tests.linkage = if (dynamic) .dynamic else .static;
    const run_tests = b.addRunArtifact(unit_tests);
    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&run_tests.step);
}
