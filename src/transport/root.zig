const std = @import("std");

pub const inproc = @import("inproc.zig");
pub const quic = @import("quic.zig");
pub const quic_runtime = @import("quic_runtime.zig");
pub const quic_udp = @import("quic_udp.zig");
pub const quic_session_runtime = @import("quic_session_runtime.zig");
pub const quic_streams = @import("quic_streams.zig");
pub const quic_cancel = @import("quic_cancel.zig");
pub const quic_datagram = @import("quic_datagram.zig");
pub const quic_control = @import("quic_control.zig");
pub const quic_app_server = @import("quic_app_server.zig");

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
    StreamNotFound,
    StreamAlreadyOpen,
    QueueFull,
    FlowControlled,
    WouldBlock,
    MessageTooLarge,
    UnsupportedTransport,
};

test {
    std.testing.refAllDecls(@This());
}
