const std = @import("std");

pub const inproc = @import("inproc.zig");

pub const Kind = enum {
    inproc,
    quic,
};

pub const Endpoint = union(Kind) {
    inproc: InprocEndpoint,
    quic: []const u8,
};

pub const InprocEndpoint = struct {
    network: *inproc.Network,
    address: []const u8,
};

pub const Error = error{
    InvalidEndpoint,
    InvalidState,
    EndpointClosed,
    EndpointInUse,
    EndpointNotFound,
    QueueFull,
    FlowControlled,
    WouldBlock,
    MessageTooLarge,
};

test {
    std.testing.refAllDecls(@This());
}
