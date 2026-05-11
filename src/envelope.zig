const std = @import("std");
const message = @import("message.zig");
const subject_mod = @import("subject.zig");

pub const CodecOptions = struct {
    max_message_size: usize = 1024 * 1024,
    max_headers: usize = 32,
    max_header_bytes: usize = 16 * 1024,
};

pub fn encodedSize(outgoing: message.OutgoingMessage, options: CodecOptions) !usize {
    try validateOutgoing(outgoing, options);

    var size: usize = 0;
    size = try addSize(size, try varIntLen(outgoing.id));
    size = try addSize(size, try varIntLen(outgoing.flags.bits()));
    size = try addSize(size, try bytesSize(outgoing.subject));
    size = try addSize(size, try varIntLen(outgoing.deadline_ms orelse 0));
    size = try addSize(size, try varIntLen(outgoing.headers.len));

    for (outgoing.headers) |header| {
        size = try addSize(size, try bytesSize(header.name));
        size = try addSize(size, try bytesSize(header.value));
    }

    size = try addSize(size, try bytesSize(outgoing.body));
    if (size > options.max_message_size) return error.MessageTooLarge;
    return size;
}

pub fn encode(allocator: std.mem.Allocator, outgoing: message.OutgoingMessage, options: CodecOptions) ![]u8 {
    const expected_size = try encodedSize(outgoing, options);

    var bytes = try std.ArrayList(u8).initCapacity(allocator, expected_size);
    errdefer bytes.deinit(allocator);

    try appendVarInt(allocator, &bytes, outgoing.id);
    try appendVarInt(allocator, &bytes, outgoing.flags.bits());
    try appendBytes(allocator, &bytes, outgoing.subject);
    try appendVarInt(allocator, &bytes, outgoing.deadline_ms orelse 0);
    try appendVarInt(allocator, &bytes, outgoing.headers.len);

    for (outgoing.headers) |header| {
        try appendBytes(allocator, &bytes, header.name);
        try appendBytes(allocator, &bytes, header.value);
    }

    try appendBytes(allocator, &bytes, outgoing.body);
    std.debug.assert(bytes.items.len == expected_size);
    return try bytes.toOwnedSlice(allocator);
}

pub fn decode(allocator: std.mem.Allocator, frame: []const u8, options: CodecOptions) !message.Message {
    if (frame.len > options.max_message_size) return error.MessageTooLarge;

    var reader: Reader = .{ .bytes = frame };

    const id = try reader.readVarInt();
    const flags = try message.Flags.fromBits(try reader.readVarInt());
    const subject = try reader.readBytes();
    const deadline_wire = try reader.readVarInt();
    const deadline_ms: ?u64 = if (deadline_wire == 0) null else deadline_wire;

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

    const body = try reader.readBytes();
    if (reader.remaining() != 0) return error.MalformedFrame;

    return message.Message.init(allocator, .{
        .subject = subject,
        .id = id,
        .flags = flags,
        .deadline_ms = deadline_ms,
        .headers = headers,
        .body = body,
    });
}

fn validateOutgoing(outgoing: message.OutgoingMessage, options: CodecOptions) !void {
    try subject_mod.validate(outgoing.subject);
    if (outgoing.headers.len > options.max_headers) return error.HeaderLimitExceeded;
    if (outgoing.deadline_ms == 0) return error.InvalidMessage;

    _ = try varIntLen(outgoing.id);
    _ = try varIntLen(outgoing.flags.bits());
    _ = try varIntLen(outgoing.deadline_ms orelse 0);
    _ = try varIntLen(outgoing.headers.len);

    var header_bytes: usize = 0;
    for (outgoing.headers) |header| {
        header_bytes = try addSize(header_bytes, header.name.len);
        header_bytes = try addSize(header_bytes, header.value.len);
        if (header_bytes > options.max_header_bytes) return error.HeaderBytesLimitExceeded;
    }
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
        8 => {
            const encoded: u64 = 0xc000_0000_0000_0000 | value;
            try bytes.append(allocator, @intCast(encoded >> 56));
            try bytes.append(allocator, @intCast((encoded >> 48) & 0xff));
            try bytes.append(allocator, @intCast((encoded >> 40) & 0xff));
            try bytes.append(allocator, @intCast((encoded >> 32) & 0xff));
            try bytes.append(allocator, @intCast((encoded >> 24) & 0xff));
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
    if (value < (1 << 62)) return 8;
    return error.InvalidMessage;
}

const Reader = struct {
    bytes: []const u8,
    index: usize = 0,

    fn remaining(self: Reader) usize {
        return self.bytes.len - self.index;
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
            3 => 8,
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

test "envelope round trips owned message fields" {
    const allocator = std.testing.allocator;
    const options: CodecOptions = .{
        .max_message_size = 1024,
        .max_headers = 4,
        .max_header_bytes = 64,
    };

    const encoded = try encode(allocator, .{
        .subject = "user.get",
        .id = 99,
        .flags = .{ .final = true, .no_reply = true },
        .deadline_ms = 500,
        .headers = &.{
            .{ .name = "accept", .value = "application/qmsg" },
            .{ .name = "trace", .value = "abc" },
        },
        .body = "123",
    }, options);
    defer allocator.free(encoded);

    var decoded = try decode(allocator, encoded, options);
    defer decoded.deinit();

    try std.testing.expectEqual(@as(message.MessageId, 99), decoded.id);
    try std.testing.expect(decoded.flags.final);
    try std.testing.expect(decoded.flags.no_reply);
    try std.testing.expectEqual(@as(?u64, 500), decoded.deadline_ms);
    try std.testing.expectEqualStrings("user.get", decoded.subject);
    try std.testing.expectEqualStrings("123", decoded.body);
    try std.testing.expectEqual(@as(usize, 2), decoded.headers.len);
    try std.testing.expectEqualStrings("accept", decoded.headers[0].name);
    try std.testing.expectEqualStrings("application/qmsg", decoded.headers[0].value);
}

test "envelope encodes null deadline as zero" {
    const allocator = std.testing.allocator;
    const encoded = try encode(allocator, .{
        .subject = "metrics.cpu",
        .body = "42",
    }, .{});
    defer allocator.free(encoded);

    var decoded = try decode(allocator, encoded, .{});
    defer decoded.deinit();

    try std.testing.expectEqual(@as(?u64, null), decoded.deadline_ms);
}

test "envelope enforces message and header caps" {
    const allocator = std.testing.allocator;

    try std.testing.expectError(error.MessageTooLarge, encode(allocator, .{
        .subject = "metrics.cpu",
        .body = "too large",
    }, .{ .max_message_size = 4 }));

    try std.testing.expectError(error.HeaderLimitExceeded, encode(allocator, .{
        .subject = "metrics.cpu",
        .headers = &.{
            .{ .name = "a", .value = "b" },
            .{ .name = "c", .value = "d" },
        },
    }, .{ .max_headers = 1 }));

    try std.testing.expectError(error.HeaderBytesLimitExceeded, encode(allocator, .{
        .subject = "metrics.cpu",
        .headers = &.{.{ .name = "long-name", .value = "long-value" }},
    }, .{ .max_header_bytes = 4 }));
}

test "envelope rejects malformed frames" {
    const allocator = std.testing.allocator;

    try std.testing.expectError(error.MalformedFrame, decode(allocator, &.{0x40}, .{}));
    try std.testing.expectError(error.InvalidMessage, decode(allocator, &.{ 0, 0x10 }, .{}));

    const encoded = try encode(allocator, .{
        .subject = "metrics.cpu",
        .body = "42",
    }, .{});
    defer allocator.free(encoded);

    try std.testing.expectError(error.MalformedFrame, decode(allocator, encoded[0 .. encoded.len - 1], .{}));
}

test "varint uses canonical QUIC-style lengths" {
    const allocator = std.testing.allocator;
    var bytes = std.ArrayList(u8).empty;
    defer bytes.deinit(allocator);

    try appendVarInt(allocator, &bytes, 63);
    try appendVarInt(allocator, &bytes, 64);
    try appendVarInt(allocator, &bytes, 16_383);
    try appendVarInt(allocator, &bytes, 16_384);

    try std.testing.expectEqualSlices(u8, &.{ 0x3f, 0x40, 0x40, 0x7f, 0xff, 0x80, 0x00, 0x40, 0x00 }, bytes.items);
}
