const std = @import("std");

pub fn build(b: *std.Build) !void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const paseto_dep = b.dependency("paseto", .{
        .target = target,
    });
    const paseto_mod = paseto_dep.module("paseto");
    // quic-zig deliberately registers NO `optimize` option: its build
    // exposes a `-Drelease` policy knob instead (preferred mode
    // ReleaseSafe), because ReleaseFast/ReleaseSmall would compile out
    // the runtime safety checks its wire parsers rely on. Forwarding
    // `.optimize` here therefore failed with `invalid option:
    // "optimize"` on a COLD cache — a fresh clone's first
    // `zig build` — and only appeared to work on the second run,
    // after the lazy fetch had already completed. Do not add it back.
    //
    // The remaining map ({target, sanitize-c}) is also exactly
    // qmesh-zig's, and Zig keys the dependency cache on
    // {pkg_hash, option-set}: one binary linking both qmsg and qmesh
    // shares a single quic module instead of compiling BoringSSL twice
    // and minting two incompatible `quic.Connection` types.
    const quic_dep = try b.dependencyLazy("quic", .{
        .target = target,
        .@"sanitize-c" = @as([]const u8, "trap"),
    });
    const quic_mod = quic_dep.module("quic");

    const qmsg_mod = b.addModule("qmsg", .{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
    });
    qmsg_mod.addImport("paseto", paseto_mod);
    qmsg_mod.addImport("quic", quic_mod);

    // Optional Cap'n Proto body codec (`zig build -Dcapnp=true`). The
    // dependency is declared LAZY in build.zig.zon, so default builds —
    // and consumers that never opt in — neither fetch nor compile
    // capnp-zig. Registering the public modules BEFORE resolving the lazy
    // dependency mirrors capnp-zig's own opt-in-QUIC pattern: when qmsg is
    // itself a child dependency, Zig retries the child build after the
    // fetch and needs the partial module set to already exist.
    const enable_capnp = b.option(
        bool,
        "capnp",
        "Enable the optional capnp body codec module (fetches capnp-zig)",
    ) orelse false;
    if (enable_capnp) {
        const capnp_dep = b.dependency("capnp", .{
            .target = target,
        });
        // The DEFAULT capnp-zig root (no options): a binary linking
        // capnp-zig directly alongside this codec must resolve the same
        // module or the build duplicates shared source files.
        const capnp_mod = capnp_dep.module("capnpc-zig");

        const codec_mod = b.addModule("qmsg-codec-capnp", .{
            .root_source_file = b.path("src/codec_capnp.zig"),
            .target = target,
            .optimize = optimize,
        });
        codec_mod.addImport("capnpc-zig", capnp_mod);

        const codec_tests = b.addTest(.{ .root_module = codec_mod });
        const run_codec_tests = b.addRunArtifact(codec_tests);
        const codec_test_step = b.step("capnp-test", "Run the optional capnp body codec tests");
        codec_test_step.dependOn(&run_codec_tests.step);
    }

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

    // Two independent Nodes over real UDP. Separate step as well as
    // part of `test`: it binds sockets, which some sandboxes deny.
    const pair_tests_mod = b.createModule(.{
        .root_source_file = b.path("src/node_pair_test.zig"),
        .target = target,
        .optimize = optimize,
    });
    pair_tests_mod.addImport("quic", quic_mod);
    pair_tests_mod.addImport("paseto", paseto_mod);
    const pair_tests = b.addTest(.{ .root_module = pair_tests_mod });
    const run_pair_tests = b.addRunArtifact(pair_tests);
    const pair_test_step = b.step("node-pair-test", "Run the two-node live UDP tests");
    pair_test_step.dependOn(&run_pair_tests.step);

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
    test_step.dependOn(&run_pair_tests.step);
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
