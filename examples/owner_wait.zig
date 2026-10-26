//! Example-owned clock/wait, separate from qmsg's nonblocking pumps.
const std = @import("std");

pub fn nowUs(io: std.Io) u64 {
    return @intCast(std.Io.Clock.awake.now(io).toMicroseconds());
}

pub fn earliest(a: ?u64, b: ?u64) ?u64 {
    if (a) |left| return if (b) |right| @min(left, right) else left;
    return b;
}

pub fn wait(io: std.Io, handles: []const std.Io.net.Socket.Handle, deadline: u64) !void {
    const now = nowUs(io);
    if (deadline <= now) return;
    var descriptors: [16]std.posix.pollfd = undefined;
    if (handles.len > descriptors.len) return error.BufferTooSmall;
    for (handles, descriptors[0..handles.len]) |handle, *descriptor| descriptor.* = .{
        .fd = handle,
        .events = std.posix.POLL.IN,
        .revents = 0,
    };
    const milliseconds = @min((deadline - now + 999) / 1000, std.math.maxInt(i32));
    _ = try std.posix.poll(descriptors[0..handles.len], @intCast(milliseconds));
}
