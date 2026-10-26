//! Public fault acceptance CLI; a successful run emits one machine JSON record.
const std = @import("std");
const faults = @import("public_fault_workload.zig");
pub fn main(init: std.process.Init) !void {
    if (init.environ_map.get("QMSG_RUN_LIVE_UDP") == null) {
        std.debug.print("set QMSG_RUN_LIVE_UDP=1 to run public faults\n", .{});
        return;
    }
    var options: faults.Options = .{};
    var args = try std.process.Args.Iterator.initAllocator(init.minimal.args, init.gpa);
    defer args.deinit();
    _ = args.next();
    while (args.next()) |arg| {
        const value = args.next() orelse return error.MissingArgument;
        if (std.mem.eql(u8, arg, "--seed")) options.seed = try std.fmt.parseInt(u64, value, 0) else if (std.mem.eql(u8, arg, "--payload-bytes")) options.payload_bytes = try std.fmt.parseInt(usize, value, 10) else if (std.mem.eql(u8, arg, "--stream-window")) options.stream_window = try std.fmt.parseInt(u64, value, 10) else if (std.mem.eql(u8, arg, "--deadline-ms")) options.deadline_ms = try std.fmt.parseInt(u64, value, 10) else if (std.mem.eql(u8, arg, "--timeout-ms")) {
            const ms = try std.fmt.parseInt(u64, value, 10);
            if (ms > 30_000) return error.InvalidOptions;
            options.timeout_us = ms * 1000;
        } else return error.UnknownArgument;
    }
    const report = try faults.run(init.gpa, init.io, options);
    const json = try std.json.Stringify.valueAlloc(init.gpa, report, .{});
    defer init.gpa.free(json);
    std.debug.print("PUBLIC_FAULTS {s}\n", .{json});
}
