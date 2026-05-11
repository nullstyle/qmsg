const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const paseto_dep = b.dependency("paseto", .{
        .target = target,
        .optimize = optimize,
    });
    const paseto_mod = paseto_dep.module("paseto");

    const qmsg_mod = b.addModule("qmsg", .{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
    });
    qmsg_mod.addImport("paseto", paseto_mod);

    const lib = b.addLibrary(.{
        .name = "qmsg",
        .root_module = qmsg_mod,
        .linkage = .static,
    });
    b.installArtifact(lib);

    const unit_tests = b.addTest(.{ .root_module = qmsg_mod });
    const run_unit_tests = b.addRunArtifact(unit_tests);

    const examples_step = b.step("examples", "Build qmsg examples");
    addExample(b, examples_step, qmsg_mod, target, optimize, "inproc-reqrep", "examples/inproc_reqrep.zig");
    addExample(b, examples_step, qmsg_mod, target, optimize, "app-ergonomics", "examples/app_ergonomics.zig");

    const test_step = b.step("test", "Run qmsg unit tests");
    test_step.dependOn(&run_unit_tests.step);
}

fn addExample(
    b: *std.Build,
    step: *std.Build.Step,
    qmsg_mod: *std.Build.Module,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    comptime name: []const u8,
    comptime path: []const u8,
) void {
    const mod = b.createModule(.{
        .root_source_file = b.path(path),
        .target = target,
        .optimize = optimize,
    });
    mod.addImport("qmsg", qmsg_mod);

    const exe = b.addExecutable(.{
        .name = name,
        .root_module = mod,
    });
    const install = b.addInstallArtifact(exe, .{});
    step.dependOn(&install.step);
}
