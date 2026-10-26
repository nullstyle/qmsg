//! Repeatable localhost workload; owner loop is in the reusable public scenario.
const std = @import("std");
const workload = @import("reliable_pubsub_workload.zig");
pub fn main(init: std.process.Init) !void {
    if (init.environ_map.get("QMSG_RUN_LIVE_UDP") == null) {
        std.debug.print("set QMSG_RUN_LIVE_UDP=1 to run reliable pub/sub\n", .{});
        return;
    }
    var options: workload.Options = .{};
    var args = try std.process.Args.Iterator.initAllocator(init.minimal.args, init.gpa);
    defer args.deinit();
    _ = args.next();
    while (args.next()) |arg| {
        const value = args.next() orelse return error.MissingArgument;
        if (std.mem.eql(u8, arg, "--publications")) {
            options.publications = try std.fmt.parseInt(usize, value, 10);
        } else if (std.mem.eql(u8, arg, "--payload-bytes")) {
            options.payload_bytes = try std.fmt.parseInt(usize, value, 10);
        } else if (std.mem.eql(u8, arg, "--timeout-ms")) {
            const ms = try std.fmt.parseInt(u64, value, 10);
            if (ms > 120_000) return error.InvalidWorkloadOptions;
            options.timeout_us = ms * 1000;
        } else return error.UnknownArgument;
    }
    const report = try workload.run(init.gpa, init.io, options);
    const json = try std.json.Stringify.valueAlloc(init.gpa, report, .{});
    defer init.gpa.free(json);
    std.debug.print("PUBSUB_WORKLOAD {s}\n", .{json});
}
