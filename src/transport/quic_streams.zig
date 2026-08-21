const std = @import("std");
const quic_zig = @import("quic");

const control = @import("../control.zig");
const envelope = @import("../envelope.zig");
const message = @import("../message.zig");

pub const control_stream_type: u64 = 0x51;

pub const Role = enum {
    client,
    server,
};

pub const StreamIdAllocator = struct {
    next_bidi: u64,
    next_uni: u64,

    pub fn init(role: Role) StreamIdAllocator {
        return switch (role) {
            .client => .{ .next_bidi = 0, .next_uni = 2 },
            .server => .{ .next_bidi = 1, .next_uni = 3 },
        };
    }

    pub fn nextBidi(self: *StreamIdAllocator) !u64 {
        return self.next(&self.next_bidi);
    }

    pub fn nextUni(self: *StreamIdAllocator) !u64 {
        return self.next(&self.next_uni);
    }

    fn next(_: *StreamIdAllocator, cursor: *u64) !u64 {
        const id = cursor.*;
        cursor.* = std.math.add(u64, cursor.*, 4) catch return error.InvalidState;
        return id;
    }
};

pub fn localControlStreamId(role: Role) u64 {
    return switch (role) {
        .client => 2,
        .server => 3,
    };
}

pub fn peerControlStreamId(role: Role) u64 {
    return switch (role) {
        .client => localControlStreamId(.server),
        .server => localControlStreamId(.client),
    };
}

pub const ReceiveStatus = struct {
    reset: bool = false,
    final_size: ?u64 = null,
    read_offset: u64 = 0,
};

pub const WriteProgress = enum {
    pending,
    complete,
};

pub const QuicConnectionAdapter = struct {
    conn: *quic_zig.Connection,

    pub fn init(conn: *quic_zig.Connection) QuicConnectionAdapter {
        return .{ .conn = conn };
    }

    pub fn openBidi(self: *QuicConnectionAdapter, stream_id: u64) !void {
        _ = try self.conn.openBidi(stream_id);
    }

    pub fn openUni(self: *QuicConnectionAdapter, stream_id: u64) !void {
        _ = try self.conn.openUni(stream_id);
    }

    pub fn streamWrite(self: *QuicConnectionAdapter, stream_id: u64, bytes: []const u8) !usize {
        return self.conn.streamWrite(stream_id, bytes);
    }

    pub fn streamRead(self: *QuicConnectionAdapter, stream_id: u64, out: []u8) !usize {
        return self.conn.streamRead(stream_id, out);
    }

    pub fn streamFinish(self: *QuicConnectionAdapter, stream_id: u64) !void {
        try self.conn.streamFinish(stream_id);
    }

    pub fn streamReceiveStatus(self: *QuicConnectionAdapter, stream_id: u64) ?ReceiveStatus {
        const stream = self.conn.stream(stream_id) orelse return null;
        return .{
            .reset = stream.recv.reset != null,
            .final_size = stream.recv.final_size,
            .read_offset = stream.recv.read_offset,
        };
    }
};

pub const ControlWriteOptions = struct {
    open_uni: bool = true,
    finish: bool = true,
};

pub const ControlStreamSender = struct {
    allocator: std.mem.Allocator,
    stream_id: u64,
    bytes: []u8,
    offset: usize = 0,
    options: ControlWriteOptions = .{},
    opened: bool = false,
    finished: bool = false,

    pub fn init(
        allocator: std.mem.Allocator,
        stream_id: u64,
        frames: []const control.Frame,
        codec_options: control.CodecOptions,
        options: ControlWriteOptions,
    ) !ControlStreamSender {
        const bytes = try encodeControlStream(allocator, frames, codec_options);
        errdefer allocator.free(bytes);

        return .{
            .allocator = allocator,
            .stream_id = stream_id,
            .bytes = bytes,
            .options = options,
        };
    }

    pub fn deinit(self: *ControlStreamSender) void {
        self.allocator.free(self.bytes);
        self.* = undefined;
    }

    pub fn pump(self: *ControlStreamSender, transport: anytype) !WriteProgress {
        if (!self.opened) {
            if (self.options.open_uni) _ = try transport.openUni(self.stream_id);
            self.opened = true;
        }

        return try pumpBytes(
            self.stream_id,
            self.bytes,
            &self.offset,
            &self.finished,
            self.options.finish,
            transport,
        );
    }
};

pub const ControlStreamOptions = struct {
    codec: control.CodecOptions = .{},
    max_buffered_bytes: usize = 64 * 1024,
    scratch_size: usize = 4096,
};

pub const ControlReadResult = struct {
    bytes_read: usize = 0,
    frames_read: usize = 0,
    stream_complete: bool = false,
};

pub const ControlStreamReceiver = struct {
    allocator: std.mem.Allocator,
    stream_id: u64,
    options: ControlStreamOptions = .{},
    bytes: std.ArrayList(u8) = .empty,
    stream_type_seen: bool = false,

    pub fn init(
        allocator: std.mem.Allocator,
        stream_id: u64,
        options: ControlStreamOptions,
    ) ControlStreamReceiver {
        return .{
            .allocator = allocator,
            .stream_id = stream_id,
            .options = options,
        };
    }

    pub fn deinit(self: *ControlStreamReceiver) void {
        self.bytes.deinit(self.allocator);
        self.* = undefined;
    }

    pub fn pump(
        self: *ControlStreamReceiver,
        transport: anytype,
        out: *std.ArrayList(control.Frame),
    ) !ControlReadResult {
        try self.checkStatus(transport);

        var result: ControlReadResult = .{};
        var scratch = try self.allocator.alloc(u8, self.options.scratch_size);
        defer self.allocator.free(scratch);

        while (true) {
            const n = try transport.streamRead(self.stream_id, scratch);
            if (n == 0) break;
            result.bytes_read += n;
            if (n > self.options.max_buffered_bytes or
                self.bytes.items.len > self.options.max_buffered_bytes - n)
            {
                return error.FrameTooLarge;
            }
            try self.bytes.appendSlice(self.allocator, scratch[0..n]);
        }

        result.frames_read = try self.parseAvailable(out);
        result.stream_complete = try self.streamComplete(transport);
        if (result.stream_complete and (!self.stream_type_seen or self.bytes.items.len != 0)) {
            return error.MalformedFrame;
        }
        return result;
    }

    fn checkStatus(self: *ControlStreamReceiver, transport: anytype) !void {
        const status = transport.streamReceiveStatus(self.stream_id) orelse return error.StreamNotFound;
        if (status.reset) return error.StreamReset;
    }

    fn streamComplete(self: *ControlStreamReceiver, transport: anytype) !bool {
        const status = transport.streamReceiveStatus(self.stream_id) orelse return error.StreamNotFound;
        if (status.reset) return error.StreamReset;
        const final_size = status.final_size orelse return false;
        return status.read_offset == final_size;
    }

    fn parseAvailable(self: *ControlStreamReceiver, out: *std.ArrayList(control.Frame)) !usize {
        var consumed: usize = 0;
        var frames_read: usize = 0;

        if (!self.stream_type_seen) {
            var reader: Reader = .{ .bytes = self.bytes.items };
            const stream_type = reader.readVarInt() catch |err| switch (err) {
                error.NeedMoreData => return 0,
                else => return err,
            };
            if (stream_type != control_stream_type) return error.InvalidControlFrame;
            self.stream_type_seen = true;
            consumed = reader.index;
        }

        while (consumed < self.bytes.items.len) {
            var reader: Reader = .{
                .bytes = self.bytes.items,
                .index = consumed,
            };
            const payload_len_u64 = reader.readVarInt() catch |err| switch (err) {
                error.NeedMoreData => break,
                else => return err,
            };
            const payload_len = std.math.cast(usize, payload_len_u64) orelse return error.FrameTooLarge;
            if (payload_len > self.options.codec.max_frame_size) return error.FrameTooLarge;
            if (reader.remaining() < payload_len) break;

            const payload = reader.bytes[reader.index..][0..payload_len];
            var frame = try control.decode(self.allocator, payload, self.options.codec);
            errdefer frame.deinit();
            try out.append(self.allocator, frame);

            consumed = reader.index + payload_len;
            frames_read += 1;
        }

        self.discard(consumed);
        return frames_read;
    }

    fn discard(self: *ControlStreamReceiver, count: usize) void {
        if (count == 0) return;
        const remaining = self.bytes.items.len - count;
        std.mem.copyForwards(u8, self.bytes.items[0..remaining], self.bytes.items[count..]);
        self.bytes.shrinkRetainingCapacity(remaining);
    }
};

pub const ReliableWriteOptions = struct {
    open_bidi: bool = true,
    finish: bool = true,
};

pub const ReliableMessageSender = struct {
    allocator: std.mem.Allocator,
    stream_id: u64,
    bytes: []u8,
    offset: usize = 0,
    options: ReliableWriteOptions = .{},
    opened: bool = false,
    finished: bool = false,

    pub fn init(
        allocator: std.mem.Allocator,
        stream_id: u64,
        outgoing: message.OutgoingMessage,
        codec_options: envelope.CodecOptions,
        options: ReliableWriteOptions,
    ) !ReliableMessageSender {
        const bytes = try encodeReliableMessage(allocator, outgoing, codec_options);
        errdefer allocator.free(bytes);

        return .{
            .allocator = allocator,
            .stream_id = stream_id,
            .bytes = bytes,
            .options = options,
        };
    }

    pub fn deinit(self: *ReliableMessageSender) void {
        self.allocator.free(self.bytes);
        self.* = undefined;
    }

    pub fn pump(self: *ReliableMessageSender, transport: anytype) !WriteProgress {
        if (!self.opened) {
            if (self.options.open_bidi) _ = try transport.openBidi(self.stream_id);
            self.opened = true;
        }

        return try pumpBytes(
            self.stream_id,
            self.bytes,
            &self.offset,
            &self.finished,
            self.options.finish,
            transport,
        );
    }
};

pub const ReliableMessageReceiver = struct {
    allocator: std.mem.Allocator,
    stream_id: u64,
    codec_options: envelope.CodecOptions,
    bytes: std.ArrayList(u8) = .empty,
    decoded: bool = false,

    pub fn init(
        allocator: std.mem.Allocator,
        stream_id: u64,
        codec_options: envelope.CodecOptions,
    ) ReliableMessageReceiver {
        return .{
            .allocator = allocator,
            .stream_id = stream_id,
            .codec_options = codec_options,
        };
    }

    pub fn deinit(self: *ReliableMessageReceiver) void {
        self.bytes.deinit(self.allocator);
        self.* = undefined;
    }

    pub fn pump(self: *ReliableMessageReceiver, transport: anytype) !?message.Message {
        if (self.decoded) return error.InvalidState;

        try self.checkStatus(transport);
        var scratch: [4096]u8 = undefined;
        while (true) {
            const n = try transport.streamRead(self.stream_id, &scratch);
            if (n == 0) break;
            if (n > self.codec_options.max_message_size or
                self.bytes.items.len > self.codec_options.max_message_size - n)
            {
                return error.MessageTooLarge;
            }
            try self.bytes.appendSlice(self.allocator, scratch[0..n]);
        }

        if (!try self.streamComplete(transport)) return null;

        self.decoded = true;
        return try decodeReliableMessage(self.allocator, self.bytes.items, self.codec_options);
    }

    fn checkStatus(self: *ReliableMessageReceiver, transport: anytype) !void {
        const status = transport.streamReceiveStatus(self.stream_id) orelse return error.StreamNotFound;
        if (status.reset) return error.StreamReset;
        if (status.final_size) |final_size| {
            if (final_size > self.codec_options.max_message_size) return error.MessageTooLarge;
        }
    }

    fn streamComplete(self: *ReliableMessageReceiver, transport: anytype) !bool {
        const status = transport.streamReceiveStatus(self.stream_id) orelse return error.StreamNotFound;
        if (status.reset) return error.StreamReset;
        const final_size = status.final_size orelse return false;
        return status.read_offset == final_size;
    }
};

pub const RequestCorrelation = struct {
    stream_id: u64,
    message_id: message.MessageId,

    pub fn expectReply(self: RequestCorrelation, stream_id: u64, reply: message.Message) !void {
        if (stream_id != self.stream_id) return error.UnexpectedFrame;
        if (reply.id != self.message_id) return error.UnexpectedFrame;
    }
};

pub fn encodeReliableMessage(
    allocator: std.mem.Allocator,
    outgoing: message.OutgoingMessage,
    options: envelope.CodecOptions,
) ![]u8 {
    if (outgoing.flags.unreliable) return error.InvalidMessage;
    return envelope.encode(allocator, outgoing, options);
}

pub fn decodeReliableMessage(
    allocator: std.mem.Allocator,
    bytes: []const u8,
    options: envelope.CodecOptions,
) !message.Message {
    return envelope.decode(allocator, bytes, options);
}

pub fn requestCorrelation(stream_id: u64, outgoing: message.OutgoingMessage) !RequestCorrelation {
    if (outgoing.id == 0) return error.InvalidMessage;
    return .{
        .stream_id = stream_id,
        .message_id = outgoing.id,
    };
}

pub fn encodeControlStream(
    allocator: std.mem.Allocator,
    frames: []const control.Frame,
    options: control.CodecOptions,
) ![]u8 {
    if (frames.len == 0) return error.MalformedFrame;

    var bytes = try std.ArrayList(u8).initCapacity(allocator, try varIntLen(control_stream_type));
    errdefer bytes.deinit(allocator);

    try appendVarInt(allocator, &bytes, control_stream_type);
    for (frames) |frame| {
        try appendControlFrame(allocator, &bytes, frame, options);
    }

    return try bytes.toOwnedSlice(allocator);
}

pub fn encodeControlFrame(
    allocator: std.mem.Allocator,
    frame: control.Frame,
    options: control.CodecOptions,
) ![]u8 {
    var bytes: std.ArrayList(u8) = .empty;
    errdefer bytes.deinit(allocator);
    try appendControlFrame(allocator, &bytes, frame, options);
    return try bytes.toOwnedSlice(allocator);
}

fn appendControlFrame(
    allocator: std.mem.Allocator,
    bytes: *std.ArrayList(u8),
    frame: control.Frame,
    options: control.CodecOptions,
) !void {
    const payload = try control.encode(allocator, frame, options);
    defer allocator.free(payload);

    try appendVarInt(allocator, bytes, payload.len);
    try bytes.appendSlice(allocator, payload);
}

fn pumpBytes(
    stream_id: u64,
    bytes: []const u8,
    offset: *usize,
    finished: *bool,
    finish: bool,
    transport: anytype,
) !WriteProgress {
    while (offset.* < bytes.len) {
        const written = try transport.streamWrite(stream_id, bytes[offset.*..]);
        if (written == 0) return .pending;
        offset.* += written;
    }

    if (finish and !finished.*) {
        try transport.streamFinish(stream_id);
        finished.* = true;
    }

    return .complete;
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

fn varIntLen(value: u64) !usize {
    if (value < (1 << 6)) return 1;
    if (value < (1 << 14)) return 2;
    if (value < (1 << 30)) return 4;
    if (value < (1 << 62)) return 8;
    return error.InvalidControlFrame;
}

const Reader = struct {
    bytes: []const u8,
    index: usize = 0,

    fn remaining(self: Reader) usize {
        return self.bytes.len - self.index;
    }

    fn readVarInt(self: *Reader) !u64 {
        if (self.remaining() == 0) return error.NeedMoreData;

        const first = self.bytes[self.index];
        const length: usize = switch (first >> 6) {
            0 => 1,
            1 => 2,
            2 => 4,
            3 => 8,
            else => unreachable,
        };
        if (self.remaining() < length) return error.NeedMoreData;

        var value: u64 = first & 0x3f;
        var offset: usize = 1;
        while (offset < length) : (offset += 1) {
            value = (value << 8) | self.bytes[self.index + offset];
        }
        self.index += length;

        if ((try varIntLen(value)) != length) return error.MalformedFrame;
        return value;
    }
};

const FakeStream = struct {
    allocator: std.mem.Allocator,
    incoming: []const u8 = "",
    readable_len: usize = 0,
    read_offset: usize = 0,
    read_limit: usize = std.math.maxInt(usize),
    final_size: ?u64 = null,
    reset: bool = false,
    writes: std.ArrayList(u8) = .empty,
    write_limit: usize = std.math.maxInt(usize),
    opened_bidi: bool = false,
    opened_uni: bool = false,
    finished: bool = false,

    fn deinit(self: *FakeStream) void {
        self.writes.deinit(self.allocator);
        self.* = undefined;
    }

    fn openBidi(self: *FakeStream, _: u64) !void {
        self.opened_bidi = true;
    }

    fn openUni(self: *FakeStream, _: u64) !void {
        self.opened_uni = true;
    }

    fn streamWrite(self: *FakeStream, _: u64, bytes: []const u8) !usize {
        const writable = @min(bytes.len, self.write_limit);
        if (writable == 0) return 0;
        try self.writes.appendSlice(self.allocator, bytes[0..writable]);
        return writable;
    }

    fn streamFinish(self: *FakeStream, _: u64) !void {
        self.finished = true;
    }

    fn streamRead(self: *FakeStream, _: u64, out: []u8) !usize {
        const available = self.readable_len - self.read_offset;
        if (available == 0) return 0;
        const n = @min(@min(available, self.read_limit), out.len);
        std.mem.copyForwards(u8, out[0..n], self.incoming[self.read_offset..][0..n]);
        self.read_offset += n;
        return n;
    }

    fn streamReceiveStatus(self: *FakeStream, _: u64) ?ReceiveStatus {
        return .{
            .reset = self.reset,
            .final_size = self.final_size,
            .read_offset = @intCast(self.read_offset),
        };
    }
};

test "stream ids follow QUIC client server parity" {
    var client = StreamIdAllocator.init(.client);
    var server = StreamIdAllocator.init(.server);

    try std.testing.expectEqual(@as(u64, 0), try client.nextBidi());
    try std.testing.expectEqual(@as(u64, 4), try client.nextBidi());
    try std.testing.expectEqual(@as(u64, 2), try client.nextUni());
    try std.testing.expectEqual(@as(u64, 1), try server.nextBidi());
    try std.testing.expectEqual(@as(u64, 3), try server.nextUni());
    try std.testing.expectEqual(@as(u64, 2), localControlStreamId(.client));
    try std.testing.expectEqual(@as(u64, 3), peerControlStreamId(.client));
}

test "reliable sender preserves short-write state and finishes once complete" {
    const allocator = std.testing.allocator;

    var sender = try ReliableMessageSender.init(allocator, 0, .{
        .subject = "pair.echo",
        .id = 42,
        .body = "ping",
    }, .{}, .{});
    defer sender.deinit();

    var io: FakeStream = .{
        .allocator = allocator,
        .write_limit = 3,
    };
    defer io.deinit();

    while (try sender.pump(&io) == .pending) {}

    try std.testing.expect(io.opened_bidi);
    try std.testing.expect(io.finished);
    try std.testing.expectEqual(sender.bytes.len, io.writes.items.len);

    var decoded = try decodeReliableMessage(allocator, io.writes.items, .{});
    defer decoded.deinit();
    try std.testing.expectEqual(@as(message.MessageId, 42), decoded.id);
    try std.testing.expectEqualStrings("pair.echo", decoded.subject);
    try std.testing.expectEqualStrings("ping", decoded.body);
}

test "reliable receiver waits for final size before decoding" {
    const allocator = std.testing.allocator;

    const encoded = try encodeReliableMessage(allocator, .{
        .subject = "user.get",
        .id = 7,
        .body = "alice",
    }, .{});
    defer allocator.free(encoded);

    var io: FakeStream = .{
        .allocator = allocator,
        .incoming = encoded,
        .readable_len = encoded.len,
        .final_size = null,
    };
    defer io.deinit();

    var receiver = ReliableMessageReceiver.init(allocator, 0, .{});
    defer receiver.deinit();

    try std.testing.expect((try receiver.pump(&io)) == null);

    io.final_size = encoded.len;
    var decoded = (try receiver.pump(&io)).?;
    defer decoded.deinit();

    try std.testing.expectEqual(@as(message.MessageId, 7), decoded.id);
    try std.testing.expectEqualStrings("user.get", decoded.subject);
    try std.testing.expectEqualStrings("alice", decoded.body);
}

test "reliable receiver rejects oversize final size and resets" {
    const allocator = std.testing.allocator;

    var too_large: FakeStream = .{
        .allocator = allocator,
        .final_size = 5,
    };
    defer too_large.deinit();

    var receiver = ReliableMessageReceiver.init(allocator, 0, .{ .max_message_size = 4 });
    defer receiver.deinit();

    try std.testing.expectError(error.MessageTooLarge, receiver.pump(&too_large));

    var reset: FakeStream = .{
        .allocator = allocator,
        .reset = true,
    };
    defer reset.deinit();
    try std.testing.expectError(error.StreamReset, receiver.pump(&reset));
}

test "control sender writes stream type and frames with short-write state" {
    const allocator = std.testing.allocator;

    const frames = [_]control.Frame{
        .{ .hello = .{
            .peer_id = "node-a",
            .supported_patterns = control.PatternBits.req,
        } },
    };
    var sender = try ControlStreamSender.init(allocator, localControlStreamId(.client), &frames, .{}, .{});
    defer sender.deinit();

    var io: FakeStream = .{
        .allocator = allocator,
        .write_limit = 2,
    };
    defer io.deinit();

    while (try sender.pump(&io) == .pending) {}

    try std.testing.expect(io.opened_uni);
    try std.testing.expect(io.finished);

    var out: std.ArrayList(control.Frame) = .empty;
    defer {
        for (out.items) |*frame| frame.deinit();
        out.deinit(allocator);
    }
    var reader_io: FakeStream = .{
        .allocator = allocator,
        .incoming = io.writes.items,
        .readable_len = io.writes.items.len,
        .final_size = io.writes.items.len,
    };
    defer reader_io.deinit();

    var receiver = ControlStreamReceiver.init(allocator, peerControlStreamId(.server), .{});
    defer receiver.deinit();

    const result = try receiver.pump(&reader_io, &out);
    try std.testing.expect(result.stream_complete);
    try std.testing.expectEqual(@as(usize, 1), out.items.len);
    try std.testing.expectEqualStrings("node-a", out.items[0].hello.peer_id);
}

test "control receiver parses frames across partial reads" {
    const allocator = std.testing.allocator;

    const frames = [_]control.Frame{
        .{ .hello = .{
            .peer_id = "server-a",
            .supported_patterns = control.PatternBits.req,
        } },
        .{ .goaway = .{
            .code = 1,
            .reason = "bye",
        } },
    };
    const encoded = try encodeControlStream(allocator, &frames, .{});
    defer allocator.free(encoded);

    var io: FakeStream = .{
        .allocator = allocator,
        .incoming = encoded,
        .readable_len = 1,
        .read_limit = 1,
        .final_size = encoded.len,
    };
    defer io.deinit();

    var receiver = ControlStreamReceiver.init(allocator, peerControlStreamId(.client), .{});
    defer receiver.deinit();

    var out: std.ArrayList(control.Frame) = .empty;
    defer {
        for (out.items) |*frame| frame.deinit();
        out.deinit(allocator);
    }

    var result = try receiver.pump(&io, &out);
    try std.testing.expectEqual(@as(usize, 0), result.frames_read);
    try std.testing.expect(!result.stream_complete);

    io.readable_len = encoded.len;
    result = try receiver.pump(&io, &out);
    try std.testing.expect(result.stream_complete);
    try std.testing.expectEqual(@as(usize, 2), result.frames_read);
    try std.testing.expectEqual(@as(usize, 2), out.items.len);
    try std.testing.expectEqualStrings("server-a", out.items[0].hello.peer_id);
    try std.testing.expectEqualStrings("bye", out.items[1].goaway.reason);
}

test "control receiver rejects bad stream type and truncated final frame" {
    const allocator = std.testing.allocator;

    var bad_type: FakeStream = .{
        .allocator = allocator,
        .incoming = "\x40\x52",
        .readable_len = 2,
        .final_size = 2,
    };
    defer bad_type.deinit();

    var receiver = ControlStreamReceiver.init(allocator, peerControlStreamId(.client), .{});
    defer receiver.deinit();

    var out: std.ArrayList(control.Frame) = .empty;
    defer out.deinit(allocator);

    try std.testing.expectError(error.InvalidControlFrame, receiver.pump(&bad_type, &out));

    const frames = [_]control.Frame{
        .{ .hello = .{
            .peer_id = "server-a",
            .supported_patterns = control.PatternBits.req,
        } },
    };
    const encoded = try encodeControlStream(allocator, &frames, .{});
    defer allocator.free(encoded);

    var truncated: FakeStream = .{
        .allocator = allocator,
        .incoming = encoded[0 .. encoded.len - 1],
        .readable_len = encoded.len - 1,
        .final_size = encoded.len - 1,
    };
    defer truncated.deinit();

    var truncated_receiver = ControlStreamReceiver.init(allocator, peerControlStreamId(.client), .{});
    defer truncated_receiver.deinit();

    try std.testing.expectError(error.MalformedFrame, truncated_receiver.pump(&truncated, &out));
}

test "request correlation rejects mismatched reply metadata" {
    const allocator = std.testing.allocator;

    const outgoing: message.OutgoingMessage = .{
        .subject = "user.get",
        .id = 99,
    };
    const correlation = try requestCorrelation(4, outgoing);
    try std.testing.expectError(error.InvalidMessage, requestCorrelation(4, .{ .subject = "user.get" }));

    var reply = try message.Message.init(allocator, .{
        .subject = "user.get",
        .id = 99,
    });
    defer reply.deinit();

    try correlation.expectReply(4, reply);
    try std.testing.expectError(error.UnexpectedFrame, correlation.expectReply(8, reply));

    reply.id = 100;
    try std.testing.expectError(error.UnexpectedFrame, correlation.expectReply(4, reply));
}
