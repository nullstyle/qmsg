const std = @import("std");

pub const default_wire_version: u64 = 1;

pub const CodecOptions = struct {
    max_frame_size: usize = 64 * 1024,
    max_peer_id_len: usize = 256,
    max_auth_scheme_len: usize = 64,
    max_credential_len: usize = 16 * 1024,
    max_key_id_hint_len: usize = 512,
    max_hello_challenge_len: usize = 128,
    max_filter_len: usize = 512,
    max_goaway_reason_len: usize = 1024,
};

pub const Tag = enum(u64) {
    hello = 1,
    goaway = 2,
    subscribe = 3,
    unsubscribe = 4,
    credit = 5,

    pub fn fromInt(value: u64) !Tag {
        return switch (value) {
            1 => .hello,
            2 => .goaway,
            3 => .subscribe,
            4 => .unsubscribe,
            5 => .credit,
            else => error.UnknownControlFrame,
        };
    }
};

pub const RoleFlags = struct {
    pub const client: u64 = 1 << 0;
    pub const server: u64 = 1 << 1;
    pub const broker: u64 = 1 << 2;
};

pub const PatternBits = struct {
    pub const pair: u64 = 1 << 0;
    pub const req: u64 = 1 << 1;
    pub const rep: u64 = 1 << 2;
    pub const pub_: u64 = 1 << 3;
    pub const sub: u64 = 1 << 4;
    pub const push: u64 = 1 << 5;
    pub const pull: u64 = 1 << 6;

    pub const all: u64 = pair | req | rep | pub_ | sub | push | pull;
};

pub const AuthProperties = struct {
    scheme: []const u8 = "",
    credential: []const u8 = "",
    key_id_hint: ?[]const u8 = null,
    challenge: []const u8 = &.{},

    fn deinit(self: *AuthProperties, allocator: std.mem.Allocator) void {
        allocator.free(@constCast(self.scheme));
        allocator.free(@constCast(self.credential));
        if (self.key_id_hint) |hint| allocator.free(@constCast(hint));
        allocator.free(@constCast(self.challenge));
        self.* = undefined;
    }
};

pub const Hello = struct {
    allocator: ?std.mem.Allocator = null,
    wire_version: u64 = default_wire_version,
    peer_id: []const u8,
    role_flags: u64 = 0,
    supported_patterns: u64 = 0,
    max_message_size: usize = 1024 * 1024,
    max_header_bytes: usize = 16 * 1024,
    max_header_count: usize = 32,
    datagram_enabled: bool = false,
    heartbeat_interval_ms: u64 = 0,
    auth: AuthProperties = .{},

    pub fn deinit(self: *Hello) void {
        const allocator = self.allocator orelse {
            self.* = undefined;
            return;
        };
        allocator.free(@constCast(self.peer_id));
        self.auth.deinit(allocator);
        self.* = undefined;
    }
};

pub const Subscription = struct {
    allocator: ?std.mem.Allocator = null,
    filter: []const u8,
    options: u64 = 0,

    pub fn deinit(self: *Subscription) void {
        const allocator = self.allocator orelse {
            self.* = undefined;
            return;
        };
        allocator.free(@constCast(self.filter));
        self.* = undefined;
    }
};

pub const Unsubscribe = struct {
    allocator: ?std.mem.Allocator = null,
    filter: []const u8,

    pub fn deinit(self: *Unsubscribe) void {
        const allocator = self.allocator orelse {
            self.* = undefined;
            return;
        };
        allocator.free(@constCast(self.filter));
        self.* = undefined;
    }
};

pub const Credit = struct {
    allocator: ?std.mem.Allocator = null,
    subject_filter: []const u8,
    messages: u64 = 0,
    bytes: u64 = 0,

    pub fn deinit(self: *Credit) void {
        const allocator = self.allocator orelse {
            self.* = undefined;
            return;
        };
        allocator.free(@constCast(self.subject_filter));
        self.* = undefined;
    }
};

pub const Goaway = struct {
    allocator: ?std.mem.Allocator = null,
    code: u64 = 0,
    reason: []const u8 = "",

    pub fn deinit(self: *Goaway) void {
        const allocator = self.allocator orelse {
            self.* = undefined;
            return;
        };
        allocator.free(@constCast(self.reason));
        self.* = undefined;
    }
};

pub const Frame = union(Tag) {
    hello: Hello,
    goaway: Goaway,
    subscribe: Subscription,
    unsubscribe: Unsubscribe,
    credit: Credit,

    pub fn deinit(self: *Frame) void {
        switch (self.*) {
            .hello => |*hello| hello.deinit(),
            .goaway => |*goaway| goaway.deinit(),
            .subscribe => |*subscribe| subscribe.deinit(),
            .unsubscribe => |*unsubscribe| unsubscribe.deinit(),
            .credit => |*credit| credit.deinit(),
        }
        self.* = undefined;
    }
};

pub const Sink = struct {
    context: *anyopaque,
    emit: *const fn (context: *anyopaque, frame: Frame) anyerror!void,

    /// Emits a borrowed frame. Implementations must encode or copy any slices
    /// they need before returning.
    pub fn emitFrame(self: Sink, frame: Frame) !void {
        try self.emit(self.context, frame);
    }
};

pub fn encodedSize(frame: Frame, options: CodecOptions) !usize {
    try validateFrame(frame, options);

    var size = try varIntLen(@backingInt(std.meta.activeTag(frame)));
    switch (frame) {
        .hello => |hello| {
            size = try addSize(size, try varIntLen(hello.wire_version));
            size = try addSize(size, try bytesSize(hello.peer_id));
            size = try addSize(size, try varIntLen(hello.role_flags));
            size = try addSize(size, try varIntLen(hello.supported_patterns));
            size = try addSize(size, try varIntLen(toU64(hello.max_message_size)));
            size = try addSize(size, try varIntLen(toU64(hello.max_header_bytes)));
            size = try addSize(size, try varIntLen(toU64(hello.max_header_count)));
            size = try addSize(size, 1);
            size = try addSize(size, try varIntLen(hello.heartbeat_interval_ms));
            size = try addSize(size, try bytesSize(hello.auth.scheme));
            size = try addSize(size, try bytesSize(hello.auth.credential));
            size = try addSize(size, 1);
            if (hello.auth.key_id_hint) |hint| {
                size = try addSize(size, try bytesSize(hint));
            }
            if (hello.auth.challenge.len != 0) {
                size = try addSize(size, 1);
                size = try addSize(size, try bytesSize(hello.auth.challenge));
            }
        },
        .goaway => |goaway| {
            size = try addSize(size, try varIntLen(goaway.code));
            size = try addSize(size, try bytesSize(goaway.reason));
        },
        .subscribe => |subscribe| {
            size = try addSize(size, try bytesSize(subscribe.filter));
            size = try addSize(size, try varIntLen(subscribe.options));
        },
        .unsubscribe => |unsubscribe| {
            size = try addSize(size, try bytesSize(unsubscribe.filter));
        },
        .credit => |credit| {
            size = try addSize(size, try bytesSize(credit.subject_filter));
            size = try addSize(size, try varIntLen(credit.messages));
            size = try addSize(size, try varIntLen(credit.bytes));
        },
    }

    if (size > options.max_frame_size) return error.FrameTooLarge;
    return size;
}

pub fn encode(allocator: std.mem.Allocator, frame: Frame, options: CodecOptions) ![]u8 {
    const expected_size = try encodedSize(frame, options);

    var bytes = try std.ArrayList(u8).initCapacity(allocator, expected_size);
    errdefer bytes.deinit(allocator);

    try appendVarInt(allocator, &bytes, @backingInt(std.meta.activeTag(frame)));
    switch (frame) {
        .hello => |hello| {
            try appendVarInt(allocator, &bytes, hello.wire_version);
            try appendBytes(allocator, &bytes, hello.peer_id);
            try appendVarInt(allocator, &bytes, hello.role_flags);
            try appendVarInt(allocator, &bytes, hello.supported_patterns);
            try appendVarInt(allocator, &bytes, toU64(hello.max_message_size));
            try appendVarInt(allocator, &bytes, toU64(hello.max_header_bytes));
            try appendVarInt(allocator, &bytes, toU64(hello.max_header_count));
            try appendBool(allocator, &bytes, hello.datagram_enabled);
            try appendVarInt(allocator, &bytes, hello.heartbeat_interval_ms);
            try appendBytes(allocator, &bytes, hello.auth.scheme);
            try appendBytes(allocator, &bytes, hello.auth.credential);
            try appendBool(allocator, &bytes, hello.auth.key_id_hint != null);
            if (hello.auth.key_id_hint) |hint| {
                try appendBytes(allocator, &bytes, hint);
            }
            if (hello.auth.challenge.len != 0) {
                try appendBool(allocator, &bytes, true);
                try appendBytes(allocator, &bytes, hello.auth.challenge);
            }
        },
        .goaway => |goaway| {
            try appendVarInt(allocator, &bytes, goaway.code);
            try appendBytes(allocator, &bytes, goaway.reason);
        },
        .subscribe => |subscribe| {
            try appendBytes(allocator, &bytes, subscribe.filter);
            try appendVarInt(allocator, &bytes, subscribe.options);
        },
        .unsubscribe => |unsubscribe| {
            try appendBytes(allocator, &bytes, unsubscribe.filter);
        },
        .credit => |credit| {
            try appendBytes(allocator, &bytes, credit.subject_filter);
            try appendVarInt(allocator, &bytes, credit.messages);
            try appendVarInt(allocator, &bytes, credit.bytes);
        },
    }

    std.debug.assert(bytes.items.len == expected_size);
    return try bytes.toOwnedSlice(allocator);
}

pub fn decode(allocator: std.mem.Allocator, bytes: []const u8, options: CodecOptions) !Frame {
    if (bytes.len > options.max_frame_size) return error.FrameTooLarge;

    var reader: Reader = .{ .bytes = bytes };
    const tag = try Tag.fromInt(try reader.readVarInt());

    var frame: Frame = switch (tag) {
        .hello => .{ .hello = try decodeHello(allocator, &reader, options) },
        .goaway => .{ .goaway = try decodeGoaway(allocator, &reader, options) },
        .subscribe => .{ .subscribe = try decodeSubscribe(allocator, &reader, options) },
        .unsubscribe => .{ .unsubscribe = try decodeUnsubscribe(allocator, &reader, options) },
        .credit => .{ .credit = try decodeCredit(allocator, &reader, options) },
    };
    errdefer frame.deinit();

    if (reader.remaining() != 0) return error.MalformedFrame;
    return frame;
}

fn decodeHello(allocator: std.mem.Allocator, reader: *Reader, options: CodecOptions) !Hello {
    const wire_version = try reader.readVarInt();
    const peer_id = try reader.readBytesLimited(options.max_peer_id_len, error.PeerIdTooLarge);
    const role_flags = try reader.readVarInt();
    const supported_patterns = try reader.readVarInt();
    const max_message_size = try toUsize(try reader.readVarInt());
    const max_header_bytes = try toUsize(try reader.readVarInt());
    const max_header_count = try toUsize(try reader.readVarInt());
    const datagram_enabled = try reader.readBool();
    const heartbeat_interval_ms = try reader.readVarInt();
    const scheme = try reader.readBytesLimited(options.max_auth_scheme_len, error.AuthSchemeTooLarge);
    const credential = try reader.readBytesLimited(options.max_credential_len, error.CredentialTooLarge);
    const has_key_id_hint = try reader.readBool();
    const key_id_hint = if (has_key_id_hint)
        try reader.readBytesLimited(options.max_key_id_hint_len, error.KeyIdHintTooLarge)
    else
        null;
    const challenge = if (reader.remaining() == 0)
        &.{}
    else if (try reader.readBool())
        try reader.readBytesLimited(options.max_hello_challenge_len, error.ChallengeTooLarge)
    else
        &.{};

    var hello: Hello = .{
        .allocator = allocator,
        .wire_version = wire_version,
        .peer_id = try allocator.dupe(u8, peer_id),
        .role_flags = role_flags,
        .supported_patterns = supported_patterns,
        .max_message_size = max_message_size,
        .max_header_bytes = max_header_bytes,
        .max_header_count = max_header_count,
        .datagram_enabled = datagram_enabled,
        .heartbeat_interval_ms = heartbeat_interval_ms,
        .auth = .{},
    };
    errdefer hello.deinit();

    hello.auth.scheme = try allocator.dupe(u8, scheme);
    hello.auth.credential = try allocator.dupe(u8, credential);
    if (key_id_hint) |hint| {
        hello.auth.key_id_hint = try allocator.dupe(u8, hint);
    }
    hello.auth.challenge = try allocator.dupe(u8, challenge);

    return hello;
}

fn decodeSubscribe(allocator: std.mem.Allocator, reader: *Reader, options: CodecOptions) !Subscription {
    const filter = try reader.readBytesLimited(options.max_filter_len, error.SubjectFilterTooLarge);
    try validateFilter(filter);
    const control_options = try reader.readVarInt();

    return .{
        .allocator = allocator,
        .filter = try allocator.dupe(u8, filter),
        .options = control_options,
    };
}

fn decodeUnsubscribe(allocator: std.mem.Allocator, reader: *Reader, options: CodecOptions) !Unsubscribe {
    const filter = try reader.readBytesLimited(options.max_filter_len, error.SubjectFilterTooLarge);
    try validateFilter(filter);

    return .{
        .allocator = allocator,
        .filter = try allocator.dupe(u8, filter),
    };
}

fn decodeCredit(allocator: std.mem.Allocator, reader: *Reader, options: CodecOptions) !Credit {
    const filter = try reader.readBytesLimited(options.max_filter_len, error.SubjectFilterTooLarge);
    try validateFilter(filter);
    const messages = try reader.readVarInt();
    const bytes = try reader.readVarInt();

    return .{
        .allocator = allocator,
        .subject_filter = try allocator.dupe(u8, filter),
        .messages = messages,
        .bytes = bytes,
    };
}

fn decodeGoaway(allocator: std.mem.Allocator, reader: *Reader, options: CodecOptions) !Goaway {
    const code = try reader.readVarInt();
    const reason = try reader.readBytesLimited(options.max_goaway_reason_len, error.GoawayReasonTooLarge);

    return .{
        .allocator = allocator,
        .code = code,
        .reason = try allocator.dupe(u8, reason),
    };
}

fn validateFrame(frame: Frame, options: CodecOptions) !void {
    switch (frame) {
        .hello => |hello| {
            if (hello.peer_id.len == 0 or hello.peer_id.len > options.max_peer_id_len) return error.PeerIdTooLarge;
            if (hello.auth.scheme.len > options.max_auth_scheme_len) return error.AuthSchemeTooLarge;
            if (hello.auth.credential.len > options.max_credential_len) return error.CredentialTooLarge;
            if (hello.auth.key_id_hint) |hint| {
                if (hint.len == 0 or hint.len > options.max_key_id_hint_len) return error.KeyIdHintTooLarge;
            }
            if (hello.auth.challenge.len > options.max_hello_challenge_len) return error.ChallengeTooLarge;

            _ = try varIntLen(hello.wire_version);
            _ = try varIntLen(hello.role_flags);
            _ = try varIntLen(hello.supported_patterns);
            _ = try varIntLen(toU64(hello.max_message_size));
            _ = try varIntLen(toU64(hello.max_header_bytes));
            _ = try varIntLen(toU64(hello.max_header_count));
            _ = try varIntLen(hello.heartbeat_interval_ms);
        },
        .goaway => |goaway| {
            if (goaway.reason.len > options.max_goaway_reason_len) return error.GoawayReasonTooLarge;
            _ = try varIntLen(goaway.code);
        },
        .subscribe => |subscribe| {
            if (subscribe.filter.len > options.max_filter_len) return error.SubjectFilterTooLarge;
            try validateFilter(subscribe.filter);
            _ = try varIntLen(subscribe.options);
        },
        .unsubscribe => |unsubscribe| {
            if (unsubscribe.filter.len > options.max_filter_len) return error.SubjectFilterTooLarge;
            try validateFilter(unsubscribe.filter);
        },
        .credit => |credit| {
            if (credit.subject_filter.len > options.max_filter_len) return error.SubjectFilterTooLarge;
            try validateFilter(credit.subject_filter);
            _ = try varIntLen(credit.messages);
            _ = try varIntLen(credit.bytes);
        },
    }
}

fn validateFilter(filter: []const u8) !void {
    if (filter.len == 0) return error.InvalidSubjectFilter;
    if (filter[0] == '.' or filter[filter.len - 1] == '.') return error.InvalidSubjectFilter;

    var start: usize = 0;
    while (start < filter.len) {
        var end = start;
        while (end < filter.len and filter[end] != '.') : (end += 1) {}

        const segment = filter[start..end];
        if (segment.len == 0) return error.InvalidSubjectFilter;

        const is_last = end == filter.len;
        if (std.mem.eql(u8, segment, ">")) {
            if (!is_last) return error.InvalidSubjectFilter;
        } else if (!std.mem.eql(u8, segment, "*")) {
            if (std.mem.indexOfScalar(u8, segment, '*') != null) return error.InvalidSubjectFilter;
            if (std.mem.indexOfScalar(u8, segment, '>') != null) return error.InvalidSubjectFilter;
        }

        if (is_last) break;
        start = end + 1;
    }
}

fn appendBool(allocator: std.mem.Allocator, bytes: *std.ArrayList(u8), value: bool) !void {
    try bytes.append(allocator, if (value) 1 else 0);
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
    return std.math.add(usize, left, right) catch error.FrameTooLarge;
}

fn varIntLen(value: u64) !usize {
    if (value < (1 << 6)) return 1;
    if (value < (1 << 14)) return 2;
    if (value < (1 << 30)) return 4;
    if (value < (1 << 62)) return 8;
    return error.InvalidControlFrame;
}

fn toU64(value: usize) u64 {
    return @intCast(value);
}

fn toUsize(value: u64) !usize {
    return std.math.cast(usize, value) orelse error.InvalidControlFrame;
}

const Reader = struct {
    bytes: []const u8,
    index: usize = 0,

    fn remaining(self: Reader) usize {
        return self.bytes.len - self.index;
    }

    fn readBool(self: *Reader) !bool {
        if (self.remaining() == 0) return error.MalformedFrame;
        const value = self.bytes[self.index];
        self.index += 1;
        return switch (value) {
            0 => false,
            1 => true,
            else => error.MalformedFrame,
        };
    }

    fn readBytes(self: *Reader) ![]const u8 {
        const len_u64 = try self.readVarInt();
        const len = std.math.cast(usize, len_u64) orelse return error.FrameTooLarge;
        if (len > self.remaining()) return error.MalformedFrame;

        const start = self.index;
        self.index += len;
        return self.bytes[start..self.index];
    }

    fn readBytesLimited(self: *Reader, max_len: usize, comptime err: anyerror) ![]const u8 {
        const value = try self.readBytes();
        if (value.len > max_len) return err;
        return value;
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

test "hello frame round trips all negotiated fields" {
    const allocator = std.testing.allocator;

    const encoded = try encode(allocator, .{ .hello = .{
        .wire_version = 1,
        .peer_id = "node-a",
        .role_flags = RoleFlags.client | RoleFlags.server,
        .supported_patterns = PatternBits.req | PatternBits.rep | PatternBits.pub_ | PatternBits.sub,
        .max_message_size = 128 * 1024,
        .max_header_bytes = 4096,
        .max_header_count = 12,
        .datagram_enabled = true,
        .heartbeat_interval_ms = 30_000,
        .auth = .{
            .scheme = "paseto",
            .credential = "v4.public.token",
            .key_id_hint = "k4.pid.example",
        },
    } }, .{});
    defer allocator.free(encoded);

    var decoded = try decode(allocator, encoded, .{});
    defer decoded.deinit();

    try std.testing.expectEqual(Tag.hello, std.meta.activeTag(decoded));
    const hello = decoded.hello;
    try std.testing.expectEqual(@as(u64, 1), hello.wire_version);
    try std.testing.expectEqualStrings("node-a", hello.peer_id);
    try std.testing.expectEqual(RoleFlags.client | RoleFlags.server, hello.role_flags);
    try std.testing.expectEqual(PatternBits.req | PatternBits.rep | PatternBits.pub_ | PatternBits.sub, hello.supported_patterns);
    try std.testing.expectEqual(@as(usize, 128 * 1024), hello.max_message_size);
    try std.testing.expectEqual(@as(usize, 4096), hello.max_header_bytes);
    try std.testing.expectEqual(@as(usize, 12), hello.max_header_count);
    try std.testing.expect(hello.datagram_enabled);
    try std.testing.expectEqual(@as(u64, 30_000), hello.heartbeat_interval_ms);
    try std.testing.expectEqualStrings("paseto", hello.auth.scheme);
    try std.testing.expectEqualStrings("v4.public.token", hello.auth.credential);
    try std.testing.expectEqualStrings("k4.pid.example", hello.auth.key_id_hint.?);
    try std.testing.expectEqual(@as(usize, 0), hello.auth.challenge.len);
}

test "hello supports absent auth key hint" {
    const allocator = std.testing.allocator;

    const encoded = try encode(allocator, .{ .hello = .{
        .peer_id = "anon",
        .auth = .{
            .scheme = "",
            .credential = "",
            .key_id_hint = null,
        },
    } }, .{});
    defer allocator.free(encoded);

    var decoded = try decode(allocator, encoded, .{});
    defer decoded.deinit();

    try std.testing.expect(decoded.hello.auth.key_id_hint == null);
    try std.testing.expectEqual(@as(usize, 0), decoded.hello.auth.challenge.len);
}

test "hello auth challenge extension round trips and enforces bounds" {
    const allocator = std.testing.allocator;

    const encoded = try encode(allocator, .{ .hello = .{
        .peer_id = "node-a",
        .auth = .{
            .scheme = "paseto",
            .credential = "v4.public.token",
            .challenge = &.{ 0, 1, 2, 3, 4 },
        },
    } }, .{});
    defer allocator.free(encoded);

    var decoded = try decode(allocator, encoded, .{});
    defer decoded.deinit();

    try std.testing.expectEqualStrings("node-a", decoded.hello.peer_id);
    try std.testing.expectEqualSlices(u8, &.{ 0, 1, 2, 3, 4 }, decoded.hello.auth.challenge);

    try std.testing.expectError(error.ChallengeTooLarge, encode(allocator, .{ .hello = .{
        .peer_id = "node-a",
        .auth = .{ .challenge = "12345" },
    } }, .{ .max_hello_challenge_len = 4 }));

    try std.testing.expectError(error.ChallengeTooLarge, decode(
        allocator,
        encoded,
        .{ .max_hello_challenge_len = 4 },
    ));
}

test "subscribe and unsubscribe validate filters" {
    const allocator = std.testing.allocator;

    const subscribe_bytes = try encode(allocator, .{ .subscribe = .{
        .filter = "metrics.*",
        .options = 7,
    } }, .{});
    defer allocator.free(subscribe_bytes);

    var subscribe = try decode(allocator, subscribe_bytes, .{});
    defer subscribe.deinit();
    try std.testing.expectEqual(Tag.subscribe, std.meta.activeTag(subscribe));
    try std.testing.expectEqualStrings("metrics.*", subscribe.subscribe.filter);
    try std.testing.expectEqual(@as(u64, 7), subscribe.subscribe.options);

    const unsubscribe_bytes = try encode(allocator, .{ .unsubscribe = .{
        .filter = "metrics.>",
    } }, .{});
    defer allocator.free(unsubscribe_bytes);

    var unsubscribe = try decode(allocator, unsubscribe_bytes, .{});
    defer unsubscribe.deinit();
    try std.testing.expectEqual(Tag.unsubscribe, std.meta.activeTag(unsubscribe));
    try std.testing.expectEqualStrings("metrics.>", unsubscribe.unsubscribe.filter);

    try std.testing.expectError(error.InvalidSubjectFilter, encode(allocator, .{ .subscribe = .{
        .filter = "metrics.>.cpu",
    } }, .{}));
}

test "credit round trips filter and limits" {
    const allocator = std.testing.allocator;

    const encoded = try encode(allocator, .{ .credit = .{
        .subject_filter = "jobs.*",
        .messages = 32,
        .bytes = 65536,
    } }, .{});
    defer allocator.free(encoded);

    var decoded = try decode(allocator, encoded, .{});
    defer decoded.deinit();

    try std.testing.expectEqual(Tag.credit, std.meta.activeTag(decoded));
    try std.testing.expectEqualStrings("jobs.*", decoded.credit.subject_filter);
    try std.testing.expectEqual(@as(u64, 32), decoded.credit.messages);
    try std.testing.expectEqual(@as(u64, 65536), decoded.credit.bytes);
}

test "goaway round trips code and reason" {
    const allocator = std.testing.allocator;

    const encoded = try encode(allocator, .{ .goaway = .{
        .code = 42,
        .reason = "draining",
    } }, .{});
    defer allocator.free(encoded);

    var decoded = try decode(allocator, encoded, .{});
    defer decoded.deinit();

    try std.testing.expectEqual(Tag.goaway, std.meta.activeTag(decoded));
    try std.testing.expectEqual(@as(u64, 42), decoded.goaway.code);
    try std.testing.expectEqualStrings("draining", decoded.goaway.reason);
}

test "codec enforces frame and field caps" {
    const allocator = std.testing.allocator;

    try std.testing.expectError(error.PeerIdTooLarge, encode(allocator, .{ .hello = .{
        .peer_id = "node-a",
    } }, .{ .max_peer_id_len = 4 }));

    try std.testing.expectError(error.CredentialTooLarge, encode(allocator, .{ .hello = .{
        .peer_id = "node-a",
        .auth = .{ .credential = "abcdef" },
    } }, .{ .max_credential_len = 5 }));

    try std.testing.expectError(error.SubjectFilterTooLarge, encode(allocator, .{ .credit = .{
        .subject_filter = "metrics.cpu",
    } }, .{ .max_filter_len = 4 }));

    try std.testing.expectError(error.FrameTooLarge, encode(allocator, .{ .goaway = .{
        .reason = "too long",
    } }, .{ .max_frame_size = 2 }));
}

test "decode rejects malformed, unknown, and non-canonical frames" {
    const allocator = std.testing.allocator;

    try std.testing.expectError(error.MalformedFrame, decode(allocator, &.{}, .{}));
    try std.testing.expectError(error.UnknownControlFrame, decode(allocator, &.{63}, .{}));
    try std.testing.expectError(error.MalformedFrame, decode(allocator, &.{ 0x40, 0x01 }, .{}));

    const encoded = try encode(allocator, .{ .goaway = .{ .code = 1, .reason = "x" } }, .{});
    defer allocator.free(encoded);
    try std.testing.expectError(error.MalformedFrame, decode(allocator, encoded[0 .. encoded.len - 1], .{}));
}

test "bool fields reject values other than zero or one" {
    const allocator = std.testing.allocator;

    const encoded = try encode(allocator, .{ .hello = .{
        .peer_id = "node-a",
        .datagram_enabled = true,
    } }, .{});
    defer allocator.free(encoded);

    const tampered = try allocator.dupe(u8, encoded);
    defer allocator.free(tampered);

    // tag, version, peer_id length, peer_id bytes, role flags, supported patterns,
    // max message size, max header bytes, max header count, then datagram bool.
    const datagram_bool_index = 1 + 1 + 1 + "node-a".len + 1 + 1 + 4 + 4 + 1;
    tampered[datagram_bool_index] = 2;

    try std.testing.expectError(error.MalformedFrame, decode(allocator, tampered, .{}));
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
