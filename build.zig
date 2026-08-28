const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // .optimize is deliberately NOT forwarded: dependency builds on
    // this toolchain reject an `optimize` option (quic-zig's build
    // errors with `invalid option: optimize` before any module is
    // requested), which made qmsg itself unbuildable as a dependency
    // of a consumer that forwards optimize here. Consumers forward
    // .optimize to qmsg; qmsg forwards only .target onward.
    const paseto_dep = b.dependency("paseto", .{
        .target = target,
    });
    const paseto_mod = paseto_dep.module("paseto");
    const quic_dep = b.dependency("quic", .{
        .target = target,
    });
    const quic_mod = quic_dep.module("quic");

    const qmsg_mod = b.addModule("qmsg", .{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
    });
    qmsg_mod.addImport("paseto", paseto_mod);
    qmsg_mod.addImport("quic", quic_mod);

    const lib = b.addLibrary(.{
        .name = "qmsg",
        .root_module = qmsg_mod,
        .linkage = .static,
    });
    b.installArtifact(lib);

    const unit_tests = b.addTest(.{ .root_module = qmsg_mod });
    const run_unit_tests = b.addRunArtifact(unit_tests);

    const quic_tests_mod = b.createModule(.{
        .root_source_file = b.path("src/quic_transport_test.zig"),
        .target = target,
        .optimize = optimize,
    });
    quic_tests_mod.addImport("quic", quic_mod);
    const quic_tests = b.addTest(.{ .root_module = quic_tests_mod });
    const run_quic_tests = b.addRunArtifact(quic_tests);
    const quic_test_step = b.step("quic-test", "Run qmsg QUIC transport skeleton tests");
    quic_test_step.dependOn(&run_quic_tests.step);

    const examples_step = b.step("examples", "Build qmsg examples");
    addExample(b, examples_step, qmsg_mod, paseto_mod, quic_mod, target, optimize, "inproc-reqrep", "examples/inproc_reqrep.zig");
    addExample(b, examples_step, qmsg_mod, paseto_mod, quic_mod, target, optimize, "embedded-inproc-node", "examples/embedded_inproc_node.zig");
    addExample(b, examples_step, qmsg_mod, paseto_mod, quic_mod, target, optimize, "embedded-quic-attach", "examples/embedded_quic_attach.zig");
    addExample(b, examples_step, qmsg_mod, paseto_mod, quic_mod, target, optimize, "app-ergonomics", "examples/app_ergonomics.zig");
    addExample(b, examples_step, qmsg_mod, paseto_mod, quic_mod, target, optimize, "auth-paseto", "examples/auth_paseto.zig");
    addExample(b, examples_step, qmsg_mod, paseto_mod, quic_mod, target, optimize, "quic-runtime-reqrep", "examples/quic_runtime_reqrep.zig");
    addExample(b, examples_step, qmsg_mod, paseto_mod, quic_mod, target, optimize, "quic-socket-hooks", "examples/quic_socket_hooks.zig");
    addExample(b, examples_step, qmsg_mod, paseto_mod, quic_mod, target, optimize, "quic-app-dispatch", "examples/quic_app_dispatch.zig");
    addExample(b, examples_step, qmsg_mod, paseto_mod, quic_mod, target, optimize, "quic-node-localhost", "examples/quic_node_localhost.zig");

    const test_step = b.step("test", "Run qmsg unit tests");
    test_step.dependOn(&run_unit_tests.step);
    test_step.dependOn(&run_quic_tests.step);
}

fn addExample(
    b: *std.Build,
    step: *std.Build.Step,
    qmsg_mod: *std.Build.Module,
    paseto_mod: *std.Build.Module,
    quic_mod: *std.Build.Module,
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
    mod.addImport("paseto", paseto_mod);
    mod.addImport("quic", quic_mod);

    const exe = b.addExecutable(.{
        .name = name,
        .root_module = mod,
    });
    const install = b.addInstallArtifact(exe, .{});
    step.dependOn(&install.step);
}
