const std = @import("std");
const quic_zig = @import("quic_zig");
const message = @import("../message.zig");
const subject_mod = @import("../subject.zig");

pub const max_truncated_message_id: message.MessageId = (1 << 30) - 1;

pub const CodecOptions = struct {
    max_payload_size: usize = 1200,
    max_headers: usize = 32,
    max_header_bytes: usize = 16 * 1024,
};

pub const QueueFullMapping = enum {
    queue_full,
    flow_controlled,
};

pub const FallbackPolicy = enum {
    datagram_only,
    allow_reliable,
};

pub const SendOptions = struct {
    codec: CodecOptions = .{},
    fallback: FallbackPolicy = .datagram_only,
    queue_full_mapping: QueueFullMapping = .queue_full,
};

pub const SendResult = enum {
    sent_datagram,
    use_reliable_fallback,
};

pub const ReceiveOptions = struct {
    codec: CodecOptions = .{},
};

pub const Received = struct {
    msg: message.Message,
    arrived_in_early_data: bool = false,

    pub fn deinit(self: *Received) void {
        self.msg.deinit();
        self.* = undefined;
    }
};

pub fn encodedSize(outgoing: message.OutgoingMessage, options: CodecOptions) !usize {
    try validateOutgoing(outgoing, options);

    var size: usize = 0;
    size = try addSize(size, try truncatedMessageIdLen(outgoing.id));
    size = try addSize(size, try varIntLen(outgoing.flags.bits()));
    size = try addSize(size, try bytesSize(outgoing.subject));
    size = try addSize(size, try varIntLen(outgoing.headers.len));

    for (outgoing.headers) |header| {
        size = try addSize(size, try bytesSize(header.name));
        size = try addSize(size, try bytesSize(header.value));
    }

    size = try addSize(size, outgoing.body.len);
    if (size > options.max_payload_size) return error.MessageTooLarge;
    return size;
}

pub fn encode(
    allocator: std.mem.Allocator,
    outgoing: message.OutgoingMessage,
    options: CodecOptions,
) ![]u8 {
    const expected_size = try encodedSize(outgoing, options);

    var bytes = try std.ArrayList(u8).initCapacity(allocator, expected_size);
    errdefer bytes.deinit(allocator);

    try appendTruncatedMessageId(allocator, &bytes, outgoing.id);
    try appendVarInt(allocator, &bytes, outgoing.flags.bits());
    try appendBytes(allocator, &bytes, outgoing.subject);
    try appendVarInt(allocator, &bytes, outgoing.headers.len);

    for (outgoing.headers) |header| {
        try appendBytes(allocator, &bytes, header.name);
        try appendBytes(allocator, &bytes, header.value);
    }

    try bytes.appendSlice(allocator, outgoing.body);
    std.debug.assert(bytes.items.len == expected_size);
    return try bytes.toOwnedSlice(allocator);
}

pub fn decode(
    allocator: std.mem.Allocator,
    datagram: []const u8,
    options: CodecOptions,
) !message.Message {
    if (datagram.len > options.max_payload_size) return error.MessageTooLarge;

    var reader: Reader = .{ .bytes = datagram };

    const id = try readTruncatedMessageId(&reader);
    const flags = try message.Flags.fromBits(try reader.readVarInt());
    const subject = try reader.readBytes();

    const header_count_u64 = try reader.readVarInt();
    const header_count = std.math.cast(usize, header_count_u64) orelse return error.HeaderLimitExceeded;
    if (header_count > options.max_headers) return error.HeaderLimitExceeded;

    const headers = try allocator.alloc(message.Header, header_count);
    defer allocator.free(headers);

    var header_bytes: usize = 0;
    for (headers) |*header| {
        const name = try reader.readBytes();
        const value = try reader.readBytes();
        header_bytes = try addSize(header_bytes, name.len);
        header_bytes = try addSize(header_bytes, value.len);
        if (header_bytes > options.max_header_bytes) return error.HeaderBytesLimitExceeded;
        header.* = .{
            .name = name,
            .value = value,
        };
    }

    return message.Message.init(allocator, .{
        .subject = subject,
        .id = id,
        .flags = flags,
        .deadline_ms = null,
        .headers = headers,
        .body = reader.remainingBytes(),
    });
}

pub fn send(
    conn: *quic_zig.Connection,
    allocator: std.mem.Allocator,
    outgoing: message.OutgoingMessage,
    options: SendOptions,
) !SendResult {
    const payload = encode(allocator, outgoing, options.codec) catch |err| {
        if (shouldUseReliableFallback(err, options.fallback)) return .use_reliable_fallback;
        return err;
    };
    defer allocator.free(payload);

    conn.sendDatagram(payload) catch |err| {
        if (shouldUseReliableFallback(err, options.fallback)) return .use_reliable_fallback;
        return mapSendError(err, options.queue_full_mapping);
    };

    return .sent_datagram;
}

pub fn receive(
    conn: *quic_zig.Connection,
    allocator: std.mem.Allocator,
    options: ReceiveOptions,
) !?Received {
    const scratch = try allocator.alloc(u8, options.codec.max_payload_size);
    defer allocator.free(scratch);

    const info = conn.receiveDatagramInfo(scratch) orelse return null;
    var msg = try decode(allocator, scratch[0..info.len], options.codec);
    errdefer msg.deinit();

    return .{
        .msg = msg,
        .arrived_in_early_data = info.arrived_in_early_data,
    };
}

pub fn mapSendError(err: anyerror, queue_full_mapping: QueueFullMapping) anyerror {
    return switch (err) {
        error.DatagramUnavailable => error.UnsupportedTransport,
        error.DatagramTooLarge => error.MessageTooLarge,
        error.DatagramQueueFull => switch (queue_full_mapping) {
            .queue_full => error.QueueFull,
            .flow_controlled => error.FlowControlled,
        },
        else => err,
    };
}

pub fn shouldUseReliableFallback(err: anyerror, policy: FallbackPolicy) bool {
    if (policy != .allow_reliable) return false;
    return switch (err) {
        error.DatagramUnavailable, error.DatagramTooLarge, error.MessageTooLarge => true,
        else => false,
    };
}

fn validateOutgoing(outgoing: message.OutgoingMessage, options: CodecOptions) !void {
    try subject_mod.validate(outgoing.subject);
    if (outgoing.deadline_ms != null) return error.InvalidMessage;
    if (outgoing.id > max_truncated_message_id) return error.InvalidMessage;
    if (outgoing.headers.len > options.max_headers) return error.HeaderLimitExceeded;

    _ = try varIntLen(outgoing.flags.bits());
    _ = try varIntLen(outgoing.headers.len);

    var header_bytes: usize = 0;
    for (outgoing.headers) |header| {
        header_bytes = try addSize(header_bytes, header.name.len);
        header_bytes = try addSize(header_bytes, header.value.len);
        if (header_bytes > options.max_header_bytes) return error.HeaderBytesLimitExceeded;
    }
}

fn appendTruncatedMessageId(
    allocator: std.mem.Allocator,
    bytes: *std.ArrayList(u8),
    id: message.MessageId,
) !void {
    if (id > max_truncated_message_id) return error.InvalidMessage;
    try appendVarInt(allocator, bytes, id);
}

fn readTruncatedMessageId(reader: *Reader) !message.MessageId {
    const id = try reader.readVarInt();
    if (id > max_truncated_message_id) return error.InvalidMessage;
    return id;
}

fn truncatedMessageIdLen(id: message.MessageId) !usize {
    if (id > max_truncated_message_id) return error.InvalidMessage;
    return varIntLen(id);
}

fn appendBytes(allocator: std.mem.Allocator, bytes: *std.ArrayList(u8), value: []const u8) !void {
    try appendVarInt(allocator, bytes, value.len);
    try bytes.appendSlice(allocator, value);
}

fn appendVarInt(allocator: std.mem.Allocator, bytes: *std.ArrayList(u8), value: u64) !void {
    switch (try varIntLen(value)) {
        1 => try bytes.append(allocator, @intCast(value)),
        2 => {
            const encoded: u16 = 0x4000 | @as(u16, @intCast(value));
            try bytes.append(allocator, @intCast(encoded >> 8));
            try bytes.append(allocator, @intCast(encoded & 0xff));
        },
        4 => {
            const encoded: u32 = 0x8000_0000 | @as(u32, @intCast(value));
            try bytes.append(allocator, @intCast(encoded >> 24));
            try bytes.append(allocator, @intCast((encoded >> 16) & 0xff));
            try bytes.append(allocator, @intCast((encoded >> 8) & 0xff));
            try bytes.append(allocator, @intCast(encoded & 0xff));
        },
        else => unreachable,
    }
}

fn bytesSize(bytes: []const u8) !usize {
    return addSize(try varIntLen(bytes.len), bytes.len);
}

fn addSize(left: usize, right: usize) !usize {
    return std.math.add(usize, left, right) catch error.MessageTooLarge;
}

fn varIntLen(value: u64) !usize {
    if (value < (1 << 6)) return 1;
    if (value < (1 << 14)) return 2;
    if (value < (1 << 30)) return 4;
    return error.InvalidMessage;
}

const Reader = struct {
    bytes: []const u8,
    index: usize = 0,

    fn remaining(self: Reader) usize {
        return self.bytes.len - self.index;
    }

    fn remainingBytes(self: Reader) []const u8 {
        return self.bytes[self.index..];
    }

    fn readBytes(self: *Reader) ![]const u8 {
        const len_u64 = try self.readVarInt();
        const len = std.math.cast(usize, len_u64) orelse return error.MessageTooLarge;
        if (len > self.remaining()) return error.MalformedFrame;

        const start = self.index;
        self.index += len;
        return self.bytes[start..self.index];
    }

    fn readVarInt(self: *Reader) !u64 {
        if (self.remaining() == 0) return error.MalformedFrame;

        const first = self.bytes[self.index];
        const length: usize = switch (first >> 6) {
            0 => 1,
            1 => 2,
            2 => 4,
            3 => return error.InvalidMessage,
            else => unreachable,
        };
        if (self.remaining() < length) return error.MalformedFrame;

        var value: u64 = first & 0x3f;
        var offset: usize = 1;
        while (offset < length) : (offset += 1) {
            value = (value << 8) | self.bytes[self.index + offset];
        }
        self.index += length;

        const canonical_len = try varIntLen(value);
        if (canonical_len != length) return error.MalformedFrame;

        return value;
    }
};

test "datagram envelope round trips owned message fields" {
    const allocator = std.testing.allocator;

    const encoded = try encode(allocator, .{
        .subject = "presence.ada",
        .id = 42,
        .flags = .{ .final = true, .unreliable = true },
        .headers = &.{
            .{ .name = "trace", .value = "abc" },
            .{ .name = "content-type", .value = "text/plain" },
        },
        .body = "online",
    }, .{ .max_payload_size = 256 });
    defer allocator.free(encoded);

    var decoded = try decode(allocator, encoded, .{ .max_payload_size = 256 });
    defer decoded.deinit();

    try std.testing.expectEqual(@as(message.MessageId, 42), decoded.id);
    try std.testing.expect(decoded.flags.final);
    try std.testing.expect(decoded.flags.unreliable);
    try std.testing.expectEqual(@as(?u64, null), decoded.deadline_ms);
    try std.testing.expectEqualStrings("presence.ada", decoded.subject);
    try std.testing.expectEqualStrings("online", decoded.body);
    try std.testing.expectEqual(@as(usize, 2), decoded.headers.len);
    try std.testing.expectEqualStrings("trace", decoded.headers[0].name);
    try std.testing.expectEqualStrings("abc", decoded.headers[0].value);

    @memset(encoded, 0xaa);
    try std.testing.expectEqualStrings("presence.ada", decoded.subject);
    try std.testing.expectEqualStrings("online", decoded.body);
    try std.testing.expectEqualStrings("content-type", decoded.headers[1].name);
}

test "datagram envelope enforces compact bounds" {
    const allocator = std.testing.allocator;

    try std.testing.expectError(error.MessageTooLarge, encode(allocator, .{
        .subject = "presence.ada",
        .body = "too large",
    }, .{ .max_payload_size = 4 }));

    try std.testing.expectError(error.InvalidMessage, encode(allocator, .{
        .subject = "presence.ada",
        .id = max_truncated_message_id + 1,
    }, .{}));

    try std.testing.expectError(error.InvalidMessage, encode(allocator, .{
        .subject = "presence.ada",
        .deadline_ms = 10,
    }, .{}));

    try std.testing.expectError(error.HeaderLimitExceeded, encode(allocator, .{
        .subject = "presence.ada",
        .headers = &.{
            .{ .name = "a", .value = "b" },
            .{ .name = "c", .value = "d" },
        },
    }, .{ .max_headers = 1 }));

    try std.testing.expectError(error.HeaderBytesLimitExceeded, encode(allocator, .{
        .subject = "presence.ada",
        .headers = &.{.{ .name = "long-name", .value = "long-value" }},
    }, .{ .max_header_bytes = 4 }));
}

test "datagram envelope rejects malformed compact fields" {
    const allocator = std.testing.allocator;

    try std.testing.expectError(error.MalformedFrame, decode(allocator, &.{0x40}, .{}));
    try std.testing.expectError(error.InvalidMessage, decode(allocator, &.{ 0, 0xf0 }, .{}));
    try std.testing.expectError(error.InvalidMessage, decode(allocator, &.{ 0xc0, 0, 0, 0, 0, 0, 0, 0 }, .{}));

    const encoded = try encode(allocator, .{
        .subject = "presence.ada",
        .headers = &.{.{ .name = "trace", .value = "abc" }},
        .body = "online",
    }, .{});
    defer allocator.free(encoded);

    try std.testing.expectError(error.MalformedFrame, decode(allocator, encoded[0 .. encoded.len - 7], .{}));
}

test "datagram send error mapping and fallback policy" {
    try std.testing.expectEqual(error.UnsupportedTransport, mapSendError(error.DatagramUnavailable, .queue_full));
    try std.testing.expectEqual(error.MessageTooLarge, mapSendError(error.DatagramTooLarge, .queue_full));
    try std.testing.expectEqual(error.QueueFull, mapSendError(error.DatagramQueueFull, .queue_full));
    try std.testing.expectEqual(error.FlowControlled, mapSendError(error.DatagramQueueFull, .flow_controlled));

    try std.testing.expect(shouldUseReliableFallback(error.DatagramUnavailable, .allow_reliable));
    try std.testing.expect(shouldUseReliableFallback(error.DatagramTooLarge, .allow_reliable));
    try std.testing.expect(shouldUseReliableFallback(error.MessageTooLarge, .allow_reliable));
    try std.testing.expect(!shouldUseReliableFallback(error.DatagramQueueFull, .allow_reliable));
    try std.testing.expect(!shouldUseReliableFallback(error.DatagramUnavailable, .datagram_only));
}
