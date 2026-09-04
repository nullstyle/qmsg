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
    // `.optimize` IS forwarded to quic (and quic forwards it to boringssl):
    // quic v0.19.0 declares both options — capnp-zig already forwards
    // `.optimize` to the same pin — and aligning the option set exactly is
    // what lets a consumer link qmsg and capnp-zig (both on quic v0.19.0)
    // in one binary: the build system only deduplicates the shared quic
    // module when every parent configures it identically. The historical
    // note below no longer applies to this pin.
    //
    // (Earlier versions of this comment said quic's build rejected an
    // `optimize` option; that was true of an older quic build.zig and was
    // the reason qmsg forwarded only `.target`. Consumers forward
    // `.optimize` to qmsg; qmsg forwards `.target`, `.optimize`, and the
    // sanitize-c policy onward.)
    //
    // `.@"sanitize-c" = "trap"` mirrors capnp-zig's setting for the same
    // quic pin: BoringSSL's C/C++ objects are linked as static archives
    // into Zig binaries, so ReleaseSafe links fail on Linux/lld without
    // either a UBSan runtime or trap-based checks (`trap` keeps the checks
    // and needs no runtime). It also keeps this dependency's option map
    // identical to capnp-zig's, preserving the shared-module dedup above.
    const paseto_dep = b.dependency("paseto", .{
        .target = target,
    });
    const paseto_mod = paseto_dep.module("paseto");
    const quic_dep = b.dependency("quic", .{
        .target = target,
        .optimize = optimize,
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
