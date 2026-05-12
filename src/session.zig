const std = @import("std");
const auth = @import("auth.zig");

pub const SessionId = u64;

pub const TransportKind = enum {
    inproc,
    quic,
};

pub const AuthState = enum {
    anonymous,
    authenticated,
};

pub const Session = struct {
    id: SessionId,
    transport: TransportKind,
    peer_id: []const u8 = "",
    auth_state: AuthState = .anonymous,
    authorization: ?auth.Authorization = null,
    datagram_enabled: bool = false,
    max_message_size: usize = 1024 * 1024,
    user_data: ?*anyopaque = null,

    pub fn isAuthenticated(self: Session) bool {
        return self.auth_state == .authenticated and self.authorization != null;
    }

    pub fn isAnonymous(self: Session) bool {
        return !self.isAuthenticated();
    }

    pub fn setAnonymous(self: *Session) void {
        self.auth_state = .anonymous;
        self.authorization = null;
    }

    pub fn clearAuthorization(self: *Session, allocator: std.mem.Allocator) void {
        if (self.authorization) |*authorization| authorization.deinit(allocator);
        self.setAnonymous();
    }

    pub fn setAuthorization(self: *Session, authorization: auth.Authorization) void {
        self.auth_state = .authenticated;
        self.authorization = authorization;
    }

    pub fn replaceAuthorization(
        self: *Session,
        allocator: std.mem.Allocator,
        authorization: auth.Authorization,
    ) !void {
        var owned = try authorization.clone(allocator);
        errdefer owned.deinit(allocator);
        self.clearAuthorization(allocator);
        self.setAuthorization(owned);
    }

    pub fn authorizationCache(self: Session) ?auth.Authorization {
        return self.authorization;
    }

    pub fn requireAuthenticated(self: Session) auth.Error!void {
        if (!self.isAuthenticated()) return auth.Error.AuthenticationRequired;
    }

    pub fn allowsPattern(self: Session, pattern: auth.Pattern) bool {
        const authorization = self.authorization orelse return false;
        return authorization.allowsPattern(pattern);
    }

    pub fn requirePattern(self: Session, pattern: auth.Pattern) auth.Error!void {
        try self.requireAuthenticated();
        if (!self.allowsPattern(pattern)) return auth.Error.Unauthorized;
    }

    pub fn allowsSubject(self: Session, subject: []const u8) bool {
        const authorization = self.authorization orelse return false;
        return authorization.allowsSubject(subject);
    }

    pub fn requireSubject(self: Session, subject: []const u8) auth.Error!void {
        try self.requireAuthenticated();
        if (!self.allowsSubject(subject)) return auth.Error.Unauthorized;
    }

    pub fn allowsDatagram(self: Session) bool {
        const authorization = self.authorization orelse return false;
        return self.datagram_enabled and authorization.datagram_allowed;
    }

    pub fn effectiveMaxMessageSize(self: Session) usize {
        const authorization = self.authorization orelse return self.max_message_size;
        const auth_max = authorization.max_message_size orelse return self.max_message_size;
        return @min(self.max_message_size, auth_max);
    }

    pub fn check(self: Session, request: auth.Authorization.Check) auth.Error!void {
        try self.requireAuthenticated();
        const authorization = self.authorization.?;
        try authorization.check(request);

        if (request.datagram and !self.datagram_enabled) return auth.Error.Unauthorized;
        if (request.message_size) |message_size| {
            if (message_size > self.max_message_size) return auth.Error.MessageTooLarge;
        }
    }
};

test "Session defaults to anonymous and can cache authorization" {
    var session = Session{
        .id = 1,
        .transport = .inproc,
    };

    try std.testing.expect(session.isAnonymous());
    try std.testing.expect(!session.isAuthenticated());
    try std.testing.expectError(auth.Error.AuthenticationRequired, session.requireAuthenticated());

    session.setAuthorization(.{
        .subject = "service:image-worker",
        .issuer = "auth.example",
        .allowed_patterns = auth.PatternSet.init(&.{ .rep, .pull }),
        .allowed_subjects = .{ .filters = &.{"jobs.*"} },
        .datagram_allowed = true,
        .max_message_size = 8,
    });

    try std.testing.expect(session.isAuthenticated());
    try session.requirePattern(.rep);
    try session.requireSubject("jobs.resize");
    try std.testing.expectError(auth.Error.Unauthorized, session.requirePattern(.@"pub"));
    try std.testing.expectEqual(@as(usize, 8), session.effectiveMaxMessageSize());

    session.setAnonymous();
    try std.testing.expect(session.isAnonymous());
    try std.testing.expect(session.authorizationCache() == null);
}

test "Session can replace and clear owned authorization" {
    const allocator = std.testing.allocator;
    const borrowed = auth.Authorization{
        .subject = "service:jobs",
        .issuer = "auth.example",
        .token_id = "token-1",
        .allowed_patterns = auth.PatternSet.init(&.{.pull}),
        .allowed_subjects = .{ .filters = &.{"jobs.*"} },
    };

    var session = Session{
        .id = 1,
        .transport = .inproc,
    };
    try session.replaceAuthorization(allocator, borrowed);
    defer session.clearAuthorization(allocator);

    try session.requirePattern(.pull);
    try session.requireSubject("jobs.resize");

    try session.replaceAuthorization(allocator, .{
        .subject = "service:metrics",
        .issuer = "auth.example",
        .allowed_patterns = auth.PatternSet.init(&.{.@"pub"}),
        .allowed_subjects = .allow_all,
    });
    try std.testing.expectError(auth.Error.Unauthorized, session.requirePattern(.pull));
    try session.requirePattern(.@"pub");

    session.clearAuthorization(allocator);
    try std.testing.expect(session.isAnonymous());
}

test "Session check combines session and authorization limits" {
    var session = Session{
        .id = 1,
        .transport = .inproc,
        .datagram_enabled = false,
        .max_message_size = 16,
    };
    session.setAuthorization(.{
        .subject = "service:metrics",
        .issuer = "auth.example",
        .allowed_patterns = auth.PatternSet.init(&.{.@"pub"}),
        .allowed_subjects = .allow_all,
        .datagram_allowed = true,
        .max_message_size = 32,
    });

    try session.check(.{
        .pattern = .@"pub",
        .subject = "metrics.cpu",
        .message_size = 16,
    });
    try std.testing.expectError(auth.Error.MessageTooLarge, session.check(.{ .message_size = 17 }));
    try std.testing.expectError(auth.Error.Unauthorized, session.check(.{ .datagram = true }));
}

test {
    std.testing.refAllDecls(@This());
}
