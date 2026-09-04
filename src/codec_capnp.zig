//! Optional Cap'n Proto body codec — the "typed codecs" slot from the
//! ROADMAP's phase 9, layered exactly like the JSON/protobuf/msgpack
//! helpers will be: qmsg message bodies stay raw bytes, and this codec
//! packs Cap'n Proto structs into them (schema evolution and compactness
//! without involving any RPC protocol).
//!
//! This module is only compiled when the package is built with
//! `-Dcapnp=true`, which resolves the (lazy) capnp-zig dependency. Bodies
//! produced here interoperate with any Cap'n Proto implementation: the
//! encoding is the standard packed format.
//!
//! Module-boundary note: the codec imports the `capnpc-zig` module at its
//! default root. A binary that links capnp-zig DIRECTLY alongside qmsg must
//! configure its own capnp dependency identically (default root, no extra
//! options, same version) — the build system only deduplicates a shared
//! dependency module when every parent resolves it to the same module.

const std = @import("std");
const capnpc = @import("capnpc-zig");

const message = capnpc.message;

/// Serialize a `MessageBuilder` into packed capnp bytes owned by
/// `allocator`. The result is a complete qmsg message body — write it
/// straight into an `OutgoingMessage.body`.
pub fn encode(allocator: std.mem.Allocator, builder: *message.MessageBuilder) ![]u8 {
    const packed_bytes = try builder.toPackedBytes();
    defer allocator.free(packed_bytes);
    return try allocator.dupe(u8, packed_bytes);
}

/// Parse a qmsg body as a packed capnp message. The returned `Message`
/// owns its decoded segments; `deinit` it when done. Reads are zero-copy
/// against the decoded segments. A malformed body is a decode error,
/// never a crash — the default validation options bound what untrusted
/// input can make the reader do.
pub fn decode(allocator: std.mem.Allocator, body: []const u8) !message.Message {
    return try message.Message.initPacked(allocator, body, .{});
}

test "body codec round trips a packed struct" {
    const allocator = std.testing.allocator;

    var builder = message.MessageBuilder.init(allocator);
    defer builder.deinit();
    var body_struct = try builder.allocateStruct(1, 1);
    body_struct.writeU32(0, 42);
    try body_struct.writeText(0, "user-42");

    const body = try encode(allocator, &builder);
    defer allocator.free(body);

    var decoded = try decode(allocator, body);
    defer decoded.deinit();
    const root = try decoded.getRootStruct();
    try std.testing.expectEqual(@as(u32, 42), root.readU32(0));
    try std.testing.expectEqualStrings("user-42", try root.readText(0));
}

test "body codec encodes deterministically" {
    const allocator = std.testing.allocator;

    const build = struct {
        fn once(alloc: std.mem.Allocator) ![]u8 {
            var builder = message.MessageBuilder.init(alloc);
            defer builder.deinit();
            var s = try builder.allocateStruct(1, 1);
            s.writeU32(0, 7);
            try s.writeText(0, "stable");
            return encode(alloc, &builder);
        }
    }.once;

    const a = try build(allocator);
    defer allocator.free(a);
    const b = try build(allocator);
    defer allocator.free(b);
    try std.testing.expectEqualSlices(u8, a, b);
}

test "body codec rejects a malformed body as an error" {
    const allocator = std.testing.allocator;
    // Not a valid packed stream (dangling zero-lit run).
    const garbage = [_]u8{ 0xff, 0x00, 0x01 };
    try std.testing.expectError(error.UnexpectedEof, decode(allocator, &garbage));
}
