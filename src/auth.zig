const std = @import("std");
const subject = @import("subject.zig");

pub const Pattern = enum {
    pair,
    req,
    rep,
    @"pub",
    sub,
    push,
    pull,
};

pub const Error = error{
    AuthenticationRequired,
    Unauthorized,
    TokenTooLarge,
    UnsupportedCredential,
    UnknownKey,
    ReplayedCredential,
    CredentialExpired,
    CredentialNotYetValid,
    MessageTooLarge,
};

pub const PatternSet = packed struct(u8) {
    pair: bool = false,
    req: bool = false,
    rep: bool = false,
    @"pub": bool = false,
    sub: bool = false,
    push: bool = false,
    pull: bool = false,
    _reserved: bool = false,

    pub const none: PatternSet = .{};
    pub const all: PatternSet = .{
        .pair = true,
        .req = true,
        .rep = true,
        .@"pub" = true,
        .sub = true,
        .push = true,
        .pull = true,
    };

    pub fn init(patterns: []const Pattern) PatternSet {
        var set: PatternSet = .{};
        for (patterns) |pattern| set.allow(pattern);
        return set;
    }

    pub fn allow(self: *PatternSet, pattern: anytype) void {
        switch (normalizePattern(pattern)) {
            .pair => self.pair = true,
            .req => self.req = true,
            .rep => self.rep = true,
            .@"pub" => self.@"pub" = true,
            .sub => self.sub = true,
            .push => self.push = true,
            .pull => self.pull = true,
        }
    }

    pub fn withAllowed(self: PatternSet, pattern: anytype) PatternSet {
        var next = self;
        next.allow(pattern);
        return next;
    }

    pub fn contains(self: PatternSet, pattern: anytype) bool {
        return switch (normalizePattern(pattern)) {
            .pair => self.pair,
            .req => self.req,
            .rep => self.rep,
            .@"pub" => self.@"pub",
            .sub => self.sub,
            .push => self.push,
            .pull => self.pull,
        };
    }

    pub fn isEmpty(self: PatternSet) bool {
        return @as(u8, @bitCast(self)) == 0;
    }
};

pub const SubjectPolicy = union(enum) {
    allow_all,
    deny_all,
    filters: []const []const u8,

    pub fn allows(self: SubjectPolicy, candidate: []const u8) bool {
        return switch (self) {
            .allow_all => true,
            .deny_all => false,
            .filters => |filters| {
                for (filters) |filter| {
                    if (subjectFilterMatches(filter, candidate)) return true;
                }
                return false;
            },
        };
    }

    pub fn clone(self: SubjectPolicy, allocator: std.mem.Allocator) !SubjectPolicy {
        return switch (self) {
            .allow_all => .allow_all,
            .deny_all => .deny_all,
            .filters => |filters| blk: {
                const copied_filters = try allocator.alloc([]const u8, filters.len);
                errdefer allocator.free(copied_filters);

                var copied_count: usize = 0;
                errdefer {
                    for (copied_filters[0..copied_count]) |filter| allocator.free(filter);
                }

                for (filters, 0..) |filter, index| {
                    copied_filters[index] = try allocator.dupe(u8, filter);
                    copied_count += 1;
                }

                break :blk .{ .filters = copied_filters };
            },
        };
    }

    pub fn deinit(self: *SubjectPolicy, allocator: std.mem.Allocator) void {
        switch (self.*) {
            .allow_all, .deny_all => {},
            .filters => |filters| {
                for (filters) |filter| allocator.free(filter);
                allocator.free(filters);
            },
        }
        self.* = .deny_all;
    }
};

pub const Authorization = struct {
    subject: []const u8,
    issuer: []const u8,
    token_id: ?[]const u8 = null,
    allowed_patterns: PatternSet = .{},
    allowed_subjects: SubjectPolicy = .allow_all,
    datagram_allowed: bool = false,
    max_message_size: ?usize = null,
    expires_at_unix_ms: ?i64 = null,

    pub const Check = struct {
        pattern: ?Pattern = null,
        subject: ?[]const u8 = null,
        datagram: bool = false,
        message_size: ?usize = null,
        now_unix_ms: ?i64 = null,
        clock_skew_ms: u64 = 0,
    };

    pub fn clone(self: Authorization, allocator: std.mem.Allocator) !Authorization {
        const subject_copy = try allocator.dupe(u8, self.subject);
        errdefer allocator.free(subject_copy);

        const issuer_copy = try allocator.dupe(u8, self.issuer);
        errdefer allocator.free(issuer_copy);

        const token_id_copy = if (self.token_id) |token_id|
            try allocator.dupe(u8, token_id)
        else
            null;
        errdefer if (token_id_copy) |token_id| allocator.free(token_id);

        var subject_policy_copy = try self.allowed_subjects.clone(allocator);
        errdefer subject_policy_copy.deinit(allocator);

        return .{
            .subject = subject_copy,
            .issuer = issuer_copy,
            .token_id = token_id_copy,
            .allowed_patterns = self.allowed_patterns,
            .allowed_subjects = subject_policy_copy,
            .datagram_allowed = self.datagram_allowed,
            .max_message_size = self.max_message_size,
            .expires_at_unix_ms = self.expires_at_unix_ms,
        };
    }

    pub fn deinit(self: *Authorization, allocator: std.mem.Allocator) void {
        allocator.free(self.subject);
        allocator.free(self.issuer);
        if (self.token_id) |token_id| allocator.free(token_id);
        self.allowed_subjects.deinit(allocator);
        self.* = .{
            .subject = "",
            .issuer = "",
            .allowed_subjects = .deny_all,
        };
    }

    pub fn allowsPattern(self: Authorization, pattern: Pattern) bool {
        return self.allowed_patterns.contains(pattern);
    }

    pub fn allowsSubject(self: Authorization, candidate: []const u8) bool {
        return self.allowed_subjects.allows(candidate);
    }

    pub fn isExpired(self: Authorization, now_unix_ms: i64, clock_skew_ms: u64) bool {
        const expires_at = self.expires_at_unix_ms orelse return false;
        return @as(i128, now_unix_ms) > @as(i128, expires_at) + @as(i128, @intCast(clock_skew_ms));
    }

    pub fn check(self: Authorization, request: Check) Error!void {
        if (request.now_unix_ms) |now| {
            if (self.isExpired(now, request.clock_skew_ms)) return Error.CredentialExpired;
        }

        if (request.pattern) |pattern| {
            if (!self.allowsPattern(pattern)) return Error.Unauthorized;
        }

        if (request.subject) |candidate| {
            if (!self.allowsSubject(candidate)) return Error.Unauthorized;
        }

        if (request.datagram and !self.datagram_allowed) return Error.Unauthorized;

        if (request.message_size) |message_size| {
            if (self.max_message_size) |max_message_size| {
                if (message_size > max_message_size) return Error.MessageTooLarge;
            }
        }
    }
};

pub const PasetoVersion = enum {
    v4,
};

pub const PasetoPurpose = enum {
    public,
    local,
};

pub const PasetoOptions = struct {
    allowed_versions: []const PasetoVersion = &.{.v4},
    allowed_purposes: []const PasetoPurpose = &.{.public},
};

pub const Credential = struct {
    token: []const u8,
    key_id_hint: ?[]const u8 = null,
    implicit_assertion: []const u8 = &.{},
};

pub const Authenticator = struct {
    ptr: ?*anyopaque = null,
    authenticate_fn: *const fn (?*anyopaque, std.mem.Allocator, Credential) anyerror!Authorization,

    pub fn authenticate(
        self: Authenticator,
        allocator: std.mem.Allocator,
        credential: Credential,
    ) !Authorization {
        return try self.authenticate_fn(self.ptr, allocator, credential);
    }
};

pub const ReplayEntry = struct {
    issuer: []const u8,
    token_id: []const u8,
    expires_at_unix_ms: ?i64 = null,
};

pub const ReplayCache = struct {
    ptr: ?*anyopaque = null,
    check_and_store_fn: *const fn (?*anyopaque, ReplayEntry) anyerror!void,

    pub fn checkAndStore(self: ReplayCache, entry: ReplayEntry) !void {
        try self.check_and_store_fn(self.ptr, entry);
    }
};

pub const AuthConfig = struct {
    paseto: PasetoOptions = .{},
    required: bool = false,
    max_token_bytes: usize = 4096,
    max_clock_skew_ms: u64 = 30_000,
    authenticator: ?Authenticator = null,
    replay_cache: ?ReplayCache = null,
    allow_anonymous_subjects: []const []const u8 = &.{},

    pub fn validateCredentialSize(self: AuthConfig, credential: Credential) Error!void {
        if (credential.token.len > self.max_token_bytes) return Error.TokenTooLarge;
    }

    pub fn allowsAnonymousSubject(self: AuthConfig, candidate: []const u8) bool {
        if (self.allow_anonymous_subjects.len == 0) return !self.required;
        return (SubjectPolicy{ .filters = self.allow_anonymous_subjects }).allows(candidate);
    }
};

pub fn PasetoAuth(comptime paseto: type) type {
    return struct {
        pub const KeyId = PaserkIdType(paseto);

        pub const TokenCredential = struct {
            token: []const u8,
            key_id_hint: ?KeyId = null,
            implicit_assertion: []const u8 = &.{},
        };
        pub const Credential = TokenCredential;

        pub const KeyStore = struct {
            ptr: ?*anyopaque = null,
            find_v4_public_fn: ?*const fn (?*anyopaque, KeyId) ?paseto.v4.Public = null,
            find_v4_local_fn: ?*const fn (?*anyopaque, KeyId) ?paseto.v4.Local = null,

            pub fn findV4Public(self: KeyStore, key_id: KeyId) ?paseto.v4.Public {
                const find_fn = self.find_v4_public_fn orelse return null;
                return find_fn(self.ptr, key_id);
            }

            pub fn findV4Local(self: KeyStore, key_id: KeyId) ?paseto.v4.Local {
                const find_fn = self.find_v4_local_fn orelse return null;
                return find_fn(self.ptr, key_id);
            }
        };

        pub const TokenAuthenticator = struct {
            ptr: ?*anyopaque = null,
            authenticate_fn: *const fn (?*anyopaque, std.mem.Allocator, TokenCredential, AuthConfig) anyerror!Authorization,

            pub fn authenticate(
                self: TokenAuthenticator,
                allocator: std.mem.Allocator,
                credential: TokenCredential,
                config: AuthConfig,
            ) !Authorization {
                return try self.authenticate_fn(self.ptr, allocator, credential, config);
            }
        };
        pub const Authenticator = TokenAuthenticator;

        pub fn parseKeyId(raw: []const u8) !KeyId {
            if (comptime @hasDecl(KeyId, "parse")) {
                return try KeyId.parse(raw);
            }

            if (comptime @hasDecl(paseto, "paserk")) {
                if (comptime @hasDecl(paseto.paserk, "id")) {
                    if (comptime @hasDecl(paseto.paserk.id, "parse")) {
                        return try paseto.paserk.id.parse(raw);
                    }
                }
            }

            return Error.UnsupportedCredential;
        }
    };
}

fn PaserkIdType(comptime paseto: type) type {
    if (comptime @hasDecl(paseto, "PaserkId")) return paseto.PaserkId;
    return paseto.paserk.Id;
}

fn normalizePattern(pattern: anytype) Pattern {
    const tag = @tagName(pattern);
    if (std.mem.eql(u8, tag, "pair")) return .pair;
    if (std.mem.eql(u8, tag, "req")) return .req;
    if (std.mem.eql(u8, tag, "rep")) return .rep;
    if (std.mem.eql(u8, tag, "pub")) return .@"pub";
    if (std.mem.eql(u8, tag, "sub")) return .sub;
    if (std.mem.eql(u8, tag, "push")) return .push;
    if (std.mem.eql(u8, tag, "pull")) return .pull;
    unreachable;
}

fn subjectFilterMatches(filter: []const u8, candidate: []const u8) bool {
    const Filter = subject.Filter;

    if (comptime @hasDecl(Filter, "init") and @hasDecl(Filter, "matches")) {
        const init_params = @typeInfo(@TypeOf(Filter.init)).@"fn".params.len;
        var buffer: [1024]u8 = undefined;
        var fixed = std.heap.FixedBufferAllocator.init(&buffer);

        var compiled = if (comptime init_params == 2)
            Filter.init(fixed.allocator(), filter) catch return fallbackSubjectFilterMatches(filter, candidate)
        else if (comptime init_params == 1)
            Filter.init(filter) catch return fallbackSubjectFilterMatches(filter, candidate)
        else
            return fallbackSubjectFilterMatches(filter, candidate);

        const has_deinit = comptime @hasDecl(Filter, "deinit");
        defer if (has_deinit) compiled.deinit();
        return compiled.matches(candidate) catch false;
    }

    return fallbackSubjectFilterMatches(filter, candidate);
}

fn fallbackSubjectFilterMatches(filter: []const u8, candidate: []const u8) bool {
    if (std.mem.eql(u8, filter, candidate)) return true;
    if (std.mem.eql(u8, filter, ">")) return true;

    if (std.mem.endsWith(u8, filter, ".>")) {
        const prefix = filter[0 .. filter.len - 1];
        return std.mem.startsWith(u8, candidate, prefix);
    }

    var filter_it = std.mem.splitScalar(u8, filter, '.');
    var candidate_it = std.mem.splitScalar(u8, candidate, '.');
    while (true) {
        const filter_part = filter_it.next();
        const candidate_part = candidate_it.next();
        if (filter_part == null or candidate_part == null) return filter_part == null and candidate_part == null;
        if (std.mem.eql(u8, filter_part.?, "*")) continue;
        if (!std.mem.eql(u8, filter_part.?, candidate_part.?)) return false;
    }
}

test "PatternSet allows and contains socket patterns" {
    var set = PatternSet.init(&.{ .req, .rep });
    try std.testing.expect(set.contains(.req));
    try std.testing.expect(set.contains(.rep));
    try std.testing.expect(!set.contains(.@"pub"));

    set.allow(.@"pub");
    try std.testing.expect(set.contains(.@"pub"));
    try std.testing.expect(!PatternSet.none.contains(.pair));
    try std.testing.expect(PatternSet.all.contains(.pull));
}

test "SubjectPolicy supports allow deny and filters" {
    const filters = [_][]const u8{ "jobs.image.*", "presence.>" };
    const policy = SubjectPolicy{ .filters = &filters };
    const allow_all: SubjectPolicy = .allow_all;
    const deny_all: SubjectPolicy = .deny_all;

    try std.testing.expect(allow_all.allows("anything"));
    try std.testing.expect(!deny_all.allows("anything"));
    try std.testing.expect(policy.allows("jobs.image.resize"));
    try std.testing.expect(!policy.allows("jobs.image.resize.thumbnail"));
    try std.testing.expect(policy.allows("presence.user.123"));
    try std.testing.expect(!policy.allows("metrics.cpu"));
}

test "Authorization clone owns copied slices and enforces scope" {
    const allocator = std.testing.allocator;
    const filters = [_][]const u8{"jobs.*"};

    const borrowed = Authorization{
        .subject = "service:image-worker",
        .issuer = "auth.example",
        .token_id = "token-1",
        .allowed_patterns = PatternSet.init(&.{.pull}),
        .allowed_subjects = .{ .filters = &filters },
        .datagram_allowed = false,
        .max_message_size = 4,
        .expires_at_unix_ms = 1_000,
    };

    var owned = try borrowed.clone(allocator);
    defer owned.deinit(allocator);

    try owned.check(.{
        .pattern = .pull,
        .subject = "jobs.resize",
        .message_size = 4,
        .now_unix_ms = 1_000,
    });
    try std.testing.expectError(Error.Unauthorized, owned.check(.{ .pattern = .push }));
    try std.testing.expectError(Error.MessageTooLarge, owned.check(.{ .message_size = 5 }));
    try std.testing.expectError(Error.CredentialExpired, owned.check(.{ .now_unix_ms = 1_001 }));
}

test "AuthConfig bounds token size and anonymous subject filters" {
    const config = AuthConfig{
        .required = true,
        .max_token_bytes = 4,
        .allow_anonymous_subjects = &.{"health.*"},
    };

    try config.validateCredentialSize(.{ .token = "1234" });
    try std.testing.expectError(Error.TokenTooLarge, config.validateCredentialSize(.{ .token = "12345" }));
    try std.testing.expect(config.allowsAnonymousSubject("health.ping"));
    try std.testing.expect(!config.allowsAnonymousSubject("admin.delete"));
}

test "PasetoAuth uses paseto PaserkId alias when present" {
    const fake_paseto = struct {
        pub const PaserkId = struct {
            raw: []const u8,

            pub fn parse(raw: []const u8) !@This() {
                return .{ .raw = raw };
            }
        };

        pub const v4 = struct {
            pub const Public = struct {};
            pub const Local = struct {};
        };
    };

    const Paseto = PasetoAuth(fake_paseto);
    const key_id = try Paseto.parseKeyId("k4.pid.fake");
    const credential = Paseto.Credential{
        .token = "v4.public.fake",
        .key_id_hint = key_id,
    };

    try std.testing.expectEqualStrings("k4.pid.fake", credential.key_id_hint.?.raw);
    try std.testing.expect(@TypeOf(credential.key_id_hint.?) == fake_paseto.PaserkId);
}

test "PasetoAuth falls back to paseto.paserk.Id" {
    const fake_paseto = struct {
        pub const paserk = struct {
            pub const Id = struct {
                raw: []const u8,

                pub fn parse(raw: []const u8) !@This() {
                    return .{ .raw = raw };
                }
            };
        };

        pub const v4 = struct {
            pub const Public = struct {};
            pub const Local = struct {};
        };
    };

    const Paseto = PasetoAuth(fake_paseto);
    const key_id = try Paseto.parseKeyId("k4.pid.fake");
    try std.testing.expectEqualStrings("k4.pid.fake", key_id.raw);
    try std.testing.expect(@TypeOf(key_id) == fake_paseto.paserk.Id);
}

test {
    std.testing.refAllDecls(@This());
}
