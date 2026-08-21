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
    ImplicitAssertionTooLarge,
    ChallengeRequired,
    ChallengeTooLarge,
    UnsupportedCredential,
    UnknownKey,
    ReplayedCredential,
    CredentialExpired,
    CredentialNotYetValid,
    InvalidClaims,
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
    audience: ?[]const u8 = null,
    purpose: ?[]const u8 = null,
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

    pub const ClaimParseOptions = struct {
        require_qmsg_claim: bool = true,
        max_subject_filters: usize = 64,
        expected_audiences: []const []const u8 = &.{},
        require_audience: bool = false,
        expected_purposes: []const []const u8 = &.{},
        require_purpose: bool = false,
    };

    pub fn fromClaimsJson(
        allocator: std.mem.Allocator,
        claims_json: []const u8,
        options: ClaimParseOptions,
    ) (Error || error{OutOfMemory})!Authorization {
        var parsed = std.json.parseFromSlice(std.json.Value, allocator, claims_json, .{}) catch {
            return Error.InvalidClaims;
        };
        defer parsed.deinit();

        if (parsed.value != .object) return Error.InvalidClaims;
        const obj = parsed.value.object;

        const subject_value = requiredString(obj, "sub") catch return Error.InvalidClaims;
        const issuer_value = requiredString(obj, "iss") catch return Error.InvalidClaims;
        const audience_value = optionalString(obj, "aud") catch return Error.InvalidClaims;
        const token_id_value = optionalString(obj, "jti") catch return Error.InvalidClaims;
        const expires_at = if (obj.get("exp")) |exp|
            parseUnixMs(exp) catch return Error.InvalidClaims
        else
            null;
        try validateExpectedOptionalString(audience_value, options.expected_audiences, options.require_audience);

        const qmsg_value = obj.get("qmsg") orelse {
            if (options.require_qmsg_claim) return Error.InvalidClaims;
            try validateExpectedOptionalString(null, options.expected_purposes, options.require_purpose);
            return try (Authorization{
                .subject = subject_value,
                .issuer = issuer_value,
                .audience = audience_value,
                .token_id = token_id_value,
                .expires_at_unix_ms = expires_at,
            }).clone(allocator);
        };
        if (qmsg_value != .object) return Error.InvalidClaims;
        const qmsg_obj = qmsg_value.object;
        const purpose_value = optionalString(qmsg_obj, "purpose") catch return Error.InvalidClaims;
        try validateExpectedOptionalString(purpose_value, options.expected_purposes, options.require_purpose);

        const subject_copy = try allocator.dupe(u8, subject_value);
        errdefer allocator.free(subject_copy);
        const issuer_copy = try allocator.dupe(u8, issuer_value);
        errdefer allocator.free(issuer_copy);
        const audience_copy = if (audience_value) |audience|
            try allocator.dupe(u8, audience)
        else
            null;
        errdefer if (audience_copy) |audience| allocator.free(audience);
        const purpose_copy = if (purpose_value) |purpose|
            try allocator.dupe(u8, purpose)
        else
            null;
        errdefer if (purpose_copy) |purpose| allocator.free(purpose);
        const token_id_copy = if (token_id_value) |token_id|
            try allocator.dupe(u8, token_id)
        else
            null;
        errdefer if (token_id_copy) |token_id| allocator.free(token_id);
        var subject_policy = if (qmsg_obj.get("subjects")) |subjects|
            try parseSubjects(allocator, subjects, options.max_subject_filters)
        else
            @as(SubjectPolicy, .allow_all);
        errdefer subject_policy.deinit(allocator);

        var authz = Authorization{
            .subject = subject_copy,
            .issuer = issuer_copy,
            .audience = audience_copy,
            .purpose = purpose_copy,
            .token_id = token_id_copy,
            .allowed_patterns = try parsePatterns(qmsg_obj.get("patterns") orelse return Error.InvalidClaims),
            .allowed_subjects = subject_policy,
            .datagram_allowed = try parseOptionalBool(qmsg_obj.get("datagram")) orelse false,
            .max_message_size = try parseOptionalUsize(qmsg_obj.get("max_message_size")),
            .expires_at_unix_ms = expires_at,
        };
        errdefer authz.deinit(allocator);

        return authz;
    }

    pub fn clone(self: Authorization, allocator: std.mem.Allocator) !Authorization {
        const subject_copy = try allocator.dupe(u8, self.subject);
        errdefer allocator.free(subject_copy);

        const issuer_copy = try allocator.dupe(u8, self.issuer);
        errdefer allocator.free(issuer_copy);

        const audience_copy = if (self.audience) |audience|
            try allocator.dupe(u8, audience)
        else
            null;
        errdefer if (audience_copy) |audience| allocator.free(audience);

        const purpose_copy = if (self.purpose) |purpose|
            try allocator.dupe(u8, purpose)
        else
            null;
        errdefer if (purpose_copy) |purpose| allocator.free(purpose);

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
            .audience = audience_copy,
            .purpose = purpose_copy,
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
        if (self.audience) |audience| allocator.free(audience);
        if (self.purpose) |purpose| allocator.free(purpose);
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

pub const hello_auth_scheme_paseto = "paseto";
pub const hello_auth_purpose = "hello";
pub const hello_implicit_assertion_prefix = "qmsg/hello-auth/v1";
pub const default_hello_challenge_bytes: usize = 32;
pub const max_hello_challenge_bytes: usize = 128;

pub const HelloBindingError = error{
    ChallengeRequired,
    ChallengeTooLarge,
};

pub const HelloChallengeError = HelloBindingError || error{
    OutOfMemory,
};

pub const HelloChallengeOptions = struct {
    required: bool = false,
    max_bytes: usize = max_hello_challenge_bytes,
};

fn validateHelloChallengeLen(len: usize, options: HelloChallengeOptions) HelloBindingError!void {
    if (len == 0) {
        if (options.required) return error.ChallengeRequired;
        return;
    }
    if (len > options.max_bytes) return error.ChallengeTooLarge;
}

pub fn validateHelloChallenge(challenge: []const u8, options: HelloChallengeOptions) HelloBindingError!void {
    try validateHelloChallengeLen(challenge.len, options);
}

pub fn fillHelloChallenge(random: std.Random, challenge: []u8, options: HelloChallengeOptions) HelloBindingError!void {
    try validateHelloChallenge(challenge, .{
        .required = true,
        .max_bytes = options.max_bytes,
    });
    random.bytes(challenge);
}

pub fn allocHelloChallenge(
    allocator: std.mem.Allocator,
    random: std.Random,
    len: usize,
    options: HelloChallengeOptions,
) HelloChallengeError![]u8 {
    try validateHelloChallengeLen(len, .{
        .required = true,
        .max_bytes = options.max_bytes,
    });

    const challenge = try allocator.alloc(u8, len);
    errdefer allocator.free(challenge);
    random.bytes(challenge);
    return challenge;
}

pub fn helloChallengeMatches(expected: []const u8, actual: []const u8) bool {
    if (expected.len == 0 or expected.len != actual.len) return false;
    var diff: u8 = 0;
    for (expected, actual) |left, right| diff |= left ^ right;
    return diff == 0;
}

pub const HelloAuthContext = struct {
    protocol: []const u8 = "qmsg/1",
    purpose: []const u8 = hello_auth_purpose,
    audience: []const u8 = "",
    listener_id: []const u8 = "",
    authority: []const u8 = "",
    challenge: []const u8 = &.{},
};

pub const HelloBindingPolicy = struct {
    context: ?HelloAuthContext = null,
    require_challenge: bool = false,
    max_challenge_bytes: usize = max_hello_challenge_bytes,

    pub fn validate(self: HelloBindingPolicy) HelloBindingError!void {
        const context = self.context orelse {
            if (self.require_challenge) return error.ChallengeRequired;
            return;
        };
        try validateHelloChallenge(context.challenge, .{
            .required = self.require_challenge,
            .max_bytes = self.max_challenge_bytes,
        });
    }
};

pub const HelloChallengeState = struct {
    context: HelloAuthContext = .{},
    challenge_bytes: ?[]u8 = null,
    max_challenge_bytes: usize = max_hello_challenge_bytes,

    pub fn mint(
        allocator: std.mem.Allocator,
        random: std.Random,
        context: HelloAuthContext,
        len: usize,
        options: HelloChallengeOptions,
    ) HelloChallengeError!HelloChallengeState {
        const owned_challenge = try allocHelloChallenge(allocator, random, len, options);
        var bound_context = context;
        bound_context.challenge = owned_challenge;
        return .{
            .context = bound_context,
            .challenge_bytes = owned_challenge,
            .max_challenge_bytes = options.max_bytes,
        };
    }

    pub fn mintDefault(
        allocator: std.mem.Allocator,
        random: std.Random,
        context: HelloAuthContext,
        options: HelloChallengeOptions,
    ) HelloChallengeError!HelloChallengeState {
        return mint(allocator, random, context, default_hello_challenge_bytes, options);
    }

    pub fn deinit(self: *HelloChallengeState, allocator: std.mem.Allocator) void {
        self.discard(allocator);
    }

    pub fn isActive(self: HelloChallengeState) bool {
        return self.challenge_bytes != null;
    }

    pub fn challenge(self: HelloChallengeState) []const u8 {
        return self.challenge_bytes orelse &.{};
    }

    pub fn bindingPolicy(self: HelloChallengeState) HelloBindingError!HelloBindingPolicy {
        const challenge_bytes = self.challenge_bytes orelse return error.ChallengeRequired;
        var bound_context = self.context;
        bound_context.challenge = challenge_bytes;

        const policy = HelloBindingPolicy{
            .context = bound_context,
            .require_challenge = true,
            .max_challenge_bytes = self.max_challenge_bytes,
        };
        try policy.validate();
        return policy;
    }

    pub fn install(self: HelloChallengeState, config: *AuthConfig) HelloBindingError!void {
        const policy = try self.bindingPolicy();
        config.hello_binding = policy;
    }

    pub fn installedConfig(self: HelloChallengeState, base: AuthConfig) HelloBindingError!AuthConfig {
        var config = base;
        try self.install(&config);
        return config;
    }

    pub fn consume(self: *HelloChallengeState, allocator: std.mem.Allocator) void {
        self.discard(allocator);
    }

    pub fn discard(self: *HelloChallengeState, allocator: std.mem.Allocator) void {
        if (self.challenge_bytes) |challenge_bytes| {
            allocator.free(challenge_bytes);
        }
        self.challenge_bytes = null;
        self.context.challenge = &.{};
    }
};

pub const HelloChallengeConfig = struct {
    context: HelloAuthContext = .{},
    bytes: usize = default_hello_challenge_bytes,
    max_bytes: usize = max_hello_challenge_bytes,

    pub fn validate(self: HelloChallengeConfig) HelloBindingError!void {
        if (self.max_bytes > max_hello_challenge_bytes) return error.ChallengeTooLarge;
        try validateHelloChallengeLen(self.bytes, .{
            .required = true,
            .max_bytes = self.max_bytes,
        });
    }

    pub fn mintState(
        self: HelloChallengeConfig,
        allocator: std.mem.Allocator,
        random: std.Random,
    ) HelloChallengeError!HelloChallengeState {
        try self.validate();
        return HelloChallengeState.mint(allocator, random, self.context, self.bytes, .{
            .required = true,
            .max_bytes = self.max_bytes,
        });
    }

    pub fn mintBinding(
        self: HelloChallengeConfig,
        allocator: std.mem.Allocator,
        random: std.Random,
        base_config: AuthConfig,
    ) HelloChallengeError!HelloChallengeBinding {
        var state = try self.mintState(allocator, random);
        errdefer state.deinit(allocator);
        return try HelloChallengeBinding.init(state, base_config);
    }
};

pub const HelloChallengeBinding = struct {
    state: HelloChallengeState,
    auth_config: AuthConfig,

    pub fn init(
        state: HelloChallengeState,
        base_config: AuthConfig,
    ) HelloBindingError!HelloChallengeBinding {
        return .{
            .state = state,
            .auth_config = try state.installedConfig(base_config),
        };
    }

    pub fn deinit(self: *HelloChallengeBinding, allocator: std.mem.Allocator) void {
        self.discard(allocator);
    }

    pub fn isActive(self: HelloChallengeBinding) bool {
        return self.state.isActive();
    }

    pub fn challenge(self: HelloChallengeBinding) []const u8 {
        return self.state.challenge();
    }

    pub fn authConfig(self: HelloChallengeBinding) HelloBindingError!AuthConfig {
        try self.auth_config.hello_binding.validate();
        return self.auth_config;
    }

    pub fn consume(self: *HelloChallengeBinding, allocator: std.mem.Allocator) void {
        self.state.consume(allocator);
        self.auth_config.hello_binding = failClosedHelloBinding(self.state.max_challenge_bytes);
    }

    pub fn discard(self: *HelloChallengeBinding, allocator: std.mem.Allocator) void {
        self.state.discard(allocator);
        self.auth_config.hello_binding = failClosedHelloBinding(self.state.max_challenge_bytes);
    }
};

fn failClosedHelloBinding(max_challenge_bytes: usize) HelloBindingPolicy {
    return .{
        .require_challenge = true,
        .max_challenge_bytes = max_challenge_bytes,
    };
}

pub const HelloCredentials = struct {
    peer_id: []const u8 = "",
    scheme: []const u8 = "",
    credential: []const u8 = "",
    key_id_hint: ?[]const u8 = null,
    challenge: []const u8 = &.{},
    implicit_assertion: []const u8 = &.{},

    pub fn isEmpty(self: HelloCredentials) bool {
        return self.scheme.len == 0 and
            self.credential.len == 0 and
            self.key_id_hint == null;
    }

    pub fn toCredential(self: HelloCredentials) Credential {
        return .{
            .token = self.credential,
            .key_id_hint = self.key_id_hint,
            .implicit_assertion = self.implicit_assertion,
        };
    }
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

pub fn credentialFromHello(
    config: AuthConfig,
    hello: HelloCredentials,
) Error!?Credential {
    if (hello.isEmpty()) return null;
    if (!std.mem.eql(u8, hello.scheme, hello_auth_scheme_paseto)) return Error.UnsupportedCredential;
    if (hello.credential.len == 0) return Error.AuthenticationRequired;

    const credential = hello.toCredential();
    try config.validateCredentialSize(credential);
    return credential;
}

pub fn allocHelloImplicitAssertion(
    allocator: std.mem.Allocator,
    context: HelloAuthContext,
) ![]u8 {
    var bytes = std.ArrayList(u8).empty;
    errdefer bytes.deinit(allocator);

    try appendAssertionPart(allocator, &bytes, "format", hello_implicit_assertion_prefix);
    try appendAssertionPart(allocator, &bytes, "protocol", context.protocol);
    try appendAssertionPart(allocator, &bytes, "purpose", context.purpose);
    try appendAssertionPart(allocator, &bytes, "audience", context.audience);
    try appendAssertionPart(allocator, &bytes, "listener", context.listener_id);
    try appendAssertionPart(allocator, &bytes, "authority", context.authority);
    try appendAssertionPart(allocator, &bytes, "challenge", context.challenge);
    return try bytes.toOwnedSlice(allocator);
}

fn appendAssertionPart(
    allocator: std.mem.Allocator,
    bytes: *std.ArrayList(u8),
    label: []const u8,
    value: []const u8,
) !void {
    try appendAssertionLen(allocator, bytes, label.len);
    try bytes.appendSlice(allocator, label);
    try appendAssertionLen(allocator, bytes, value.len);
    try bytes.appendSlice(allocator, value);
}

fn appendAssertionLen(
    allocator: std.mem.Allocator,
    bytes: *std.ArrayList(u8),
    len: usize,
) !void {
    const as_u32 = std.math.cast(u32, len) orelse return Error.InvalidClaims;
    try bytes.append(allocator, @intCast((as_u32 >> 24) & 0xff));
    try bytes.append(allocator, @intCast((as_u32 >> 16) & 0xff));
    try bytes.append(allocator, @intCast((as_u32 >> 8) & 0xff));
    try bytes.append(allocator, @intCast(as_u32 & 0xff));
}

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

pub const ReplayPolicy = struct {
    require_expiration: bool = true,
    now_unix_ms: ?i64 = null,
    clock_skew_ms: u64 = 0,

    pub fn validate(self: ReplayPolicy, authorization: Authorization) Error!void {
        if (authorization.token_id == null) return Error.InvalidClaims;
        if (authorization.expires_at_unix_ms == null and self.require_expiration) return Error.InvalidClaims;
        if (self.now_unix_ms) |now| {
            if (authorization.isExpired(now, self.clock_skew_ms)) return Error.CredentialExpired;
        }
    }
};

pub const AuthConfig = struct {
    paseto: PasetoOptions = .{},
    required: bool = false,
    max_token_bytes: usize = 4096,
    max_implicit_assertion_bytes: usize = 1024,
    max_clock_skew_ms: u64 = 30_000,
    authenticator: ?Authenticator = null,
    replay_cache: ?ReplayCache = null,
    allow_anonymous_subjects: []const []const u8 = &.{},
    hello_binding: HelloBindingPolicy = .{},
    expected_audiences: []const []const u8 = &.{},
    require_audience: bool = false,
    expected_purposes: []const []const u8 = &.{},
    require_purpose: bool = false,

    pub fn validateCredentialSize(self: AuthConfig, credential: Credential) Error!void {
        if (credential.token.len > self.max_token_bytes) return Error.TokenTooLarge;
        if (credential.implicit_assertion.len > self.max_implicit_assertion_bytes) {
            return Error.ImplicitAssertionTooLarge;
        }
    }

    pub fn allowsAnonymousSubject(self: AuthConfig, candidate: []const u8) bool {
        if (self.allow_anonymous_subjects.len == 0) return !self.required;
        return (SubjectPolicy{ .filters = self.allow_anonymous_subjects }).allows(candidate);
    }

    pub fn validateAuthorization(self: AuthConfig, authorization: Authorization) Error!void {
        try validateExpectedOptionalString(authorization.audience, self.expected_audiences, self.require_audience);
        try validateExpectedOptionalString(authorization.purpose, self.expected_purposes, self.require_purpose);
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

fn requiredString(obj: std.json.ObjectMap, name: []const u8) ![]const u8 {
    const value = obj.get(name) orelse return Error.InvalidClaims;
    if (value != .string) return Error.InvalidClaims;
    return value.string;
}

fn optionalString(obj: std.json.ObjectMap, name: []const u8) !?[]const u8 {
    const value = obj.get(name) orelse return null;
    if (value == .null) return null;
    if (value != .string) return Error.InvalidClaims;
    return value.string;
}

fn validateExpectedOptionalString(
    actual: ?[]const u8,
    expected: []const []const u8,
    required: bool,
) Error!void {
    if (actual == null) {
        if (required or expected.len != 0) return Error.InvalidClaims;
        return;
    }

    if (expected.len == 0) return;
    for (expected) |candidate| {
        if (std.mem.eql(u8, actual.?, candidate)) return;
    }
    return Error.InvalidClaims;
}

fn parsePatterns(value: std.json.Value) !PatternSet {
    if (value != .array) return Error.InvalidClaims;
    var patterns = PatternSet.none;
    for (value.array.items) |item| {
        if (item != .string) return Error.InvalidClaims;
        patterns.allow(parsePatternString(item.string) orelse return Error.InvalidClaims);
    }
    if (patterns.isEmpty()) return Error.InvalidClaims;
    return patterns;
}

fn parsePatternString(raw: []const u8) ?Pattern {
    if (std.mem.eql(u8, raw, "pair")) return .pair;
    if (std.mem.eql(u8, raw, "req")) return .req;
    if (std.mem.eql(u8, raw, "rep")) return .rep;
    if (std.mem.eql(u8, raw, "pub")) return .@"pub";
    if (std.mem.eql(u8, raw, "sub")) return .sub;
    if (std.mem.eql(u8, raw, "push")) return .push;
    if (std.mem.eql(u8, raw, "pull")) return .pull;
    return null;
}

fn parseSubjects(
    allocator: std.mem.Allocator,
    value: std.json.Value,
    max_subject_filters: usize,
) !SubjectPolicy {
    if (value == .string) {
        if (std.mem.eql(u8, value.string, ">")) return .allow_all;
        if (std.mem.eql(u8, value.string, "")) return .deny_all;

        const filter = try allocator.dupe(u8, value.string);
        errdefer allocator.free(filter);
        const filters = try allocator.alloc([]const u8, 1);
        filters[0] = filter;
        return .{ .filters = filters };
    }

    if (value != .array) return Error.InvalidClaims;
    if (value.array.items.len == 0) return .deny_all;
    if (value.array.items.len > max_subject_filters) return Error.InvalidClaims;

    const filters = try allocator.alloc([]const u8, value.array.items.len);
    errdefer allocator.free(filters);

    var copied: usize = 0;
    errdefer {
        for (filters[0..copied]) |filter| allocator.free(filter);
    }

    for (value.array.items, 0..) |item, index| {
        if (item != .string) return Error.InvalidClaims;
        filters[index] = try allocator.dupe(u8, item.string);
        copied += 1;
    }

    return .{ .filters = filters };
}

fn parseOptionalBool(value: ?std.json.Value) !?bool {
    const actual = value orelse return null;
    if (actual == .null) return null;
    if (actual != .bool) return Error.InvalidClaims;
    return actual.bool;
}

fn parseOptionalUsize(value: ?std.json.Value) !?usize {
    const actual = value orelse return null;
    if (actual == .null) return null;
    if (actual != .integer) return Error.InvalidClaims;
    if (actual.integer < 0) return Error.InvalidClaims;
    return std.math.cast(usize, actual.integer) orelse return Error.InvalidClaims;
}

fn parseUnixMs(value: std.json.Value) !i64 {
    return switch (value) {
        .integer => |seconds| try secondsToMs(seconds),
        .string => |timestamp| try secondsToMs(try parseIsoTimestampSeconds(timestamp)),
        else => return Error.InvalidClaims,
    };
}

fn secondsToMs(seconds: i64) !i64 {
    return std.math.mul(i64, seconds, 1000) catch Error.InvalidClaims;
}

fn parseIsoTimestampSeconds(s: []const u8) !i64 {
    if (s.len < 20) return Error.InvalidClaims;

    var idx: usize = 0;
    const year = try parseFixedDecimal(i32, s, &idx, 4);
    if (idx >= s.len or s[idx] != '-') return Error.InvalidClaims;
    idx += 1;
    const month = try parseFixedDecimal(u8, s, &idx, 2);
    if (month < 1 or month > 12) return Error.InvalidClaims;
    if (idx >= s.len or s[idx] != '-') return Error.InvalidClaims;
    idx += 1;
    const day = try parseFixedDecimal(u8, s, &idx, 2);
    if (day < 1 or day > maxDayInMonth(year, month)) return Error.InvalidClaims;
    if (idx >= s.len or (s[idx] != 'T' and s[idx] != ' ')) return Error.InvalidClaims;
    idx += 1;
    const hour = try parseFixedDecimal(u8, s, &idx, 2);
    if (hour >= 24) return Error.InvalidClaims;
    if (idx >= s.len or s[idx] != ':') return Error.InvalidClaims;
    idx += 1;
    const minute = try parseFixedDecimal(u8, s, &idx, 2);
    if (minute >= 60) return Error.InvalidClaims;
    if (idx >= s.len or s[idx] != ':') return Error.InvalidClaims;
    idx += 1;
    const second = try parseFixedDecimal(u8, s, &idx, 2);
    if (second >= 60) return Error.InvalidClaims;

    if (idx < s.len and s[idx] == '.') {
        idx += 1;
        while (idx < s.len and s[idx] >= '0' and s[idx] <= '9') : (idx += 1) {}
    }

    var offset_seconds: i32 = 0;
    if (idx >= s.len) return Error.InvalidClaims;
    if (s[idx] == 'Z' or s[idx] == 'z') {
        idx += 1;
    } else if (s[idx] == '+' or s[idx] == '-') {
        const sign: i32 = if (s[idx] == '+') 1 else -1;
        idx += 1;
        const offset_hour = try parseFixedDecimal(u8, s, &idx, 2);
        if (idx < s.len and s[idx] == ':') idx += 1;
        const offset_minute = try parseFixedDecimal(u8, s, &idx, 2);
        if (offset_hour > 23 or offset_minute > 59) return Error.InvalidClaims;
        offset_seconds = sign * (@as(i32, offset_hour) * 3600 + @as(i32, offset_minute) * 60);
    } else {
        return Error.InvalidClaims;
    }
    if (idx != s.len) return Error.InvalidClaims;

    const days = daysFromCivil(year, month, day);
    const naive_seconds = @as(i64, days) * 86400 +
        @as(i64, hour) * 3600 +
        @as(i64, minute) * 60 +
        @as(i64, second);
    return naive_seconds - @as(i64, offset_seconds);
}

fn parseFixedDecimal(comptime T: type, s: []const u8, idx: *usize, width: usize) !T {
    if (idx.* + width > s.len) return Error.InvalidClaims;
    const chunk = s[idx.* .. idx.* + width];
    var acc: T = 0;
    for (chunk) |c| {
        if (c < '0' or c > '9') return Error.InvalidClaims;
        acc = acc * 10 + @as(T, @intCast(c - '0'));
    }
    idx.* += width;
    return acc;
}

fn isLeapYear(year: i32) bool {
    return (@mod(year, 4) == 0 and @mod(year, 100) != 0) or @mod(year, 400) == 0;
}

fn maxDayInMonth(year: i32, month: u8) u8 {
    return switch (month) {
        1, 3, 5, 7, 8, 10, 12 => 31,
        4, 6, 9, 11 => 30,
        2 => if (isLeapYear(year)) 29 else 28,
        else => 0,
    };
}

fn daysFromCivil(year_input: i32, month: u8, day: u8) i32 {
    const year = if (month <= 2) year_input - 1 else year_input;
    const era = @divFloor(year, 400);
    const yoe: u32 = @intCast(year - era * 400);
    const mp: u32 = @intCast(if (month > 2) month - 3 else month + 9);
    const doy: u32 = (153 * mp + 2) / 5 + @as(u32, day) - 1;
    const doe: u32 = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    return era * 146097 + @as(i32, @intCast(doe)) - 719468;
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
        const init_params = @typeInfo(@TypeOf(Filter.init)).@"fn".param_types.len;
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

test "Authorization parses qmsg claim block" {
    const allocator = std.testing.allocator;
    const claims =
        \\{
        \\  "iss":"auth.example",
        \\  "sub":"service:image-worker",
        \\  "aud":"qmsg://jobs.example",
        \\  "exp":"2026-06-01T00:00:00Z",
        \\  "jti":"token-1",
        \\  "qmsg":{
        \\    "purpose":"hello",
        \\    "patterns":["rep","pull"],
        \\    "subjects":["jobs.image.*","presence.>"],
        \\    "datagram":true,
        \\    "max_message_size":1048576
        \\  }
        \\}
    ;

    var authorization = try Authorization.fromClaimsJson(allocator, claims, .{});
    defer authorization.deinit(allocator);

    try std.testing.expectEqualStrings("service:image-worker", authorization.subject);
    try std.testing.expectEqualStrings("auth.example", authorization.issuer);
    try std.testing.expectEqualStrings("qmsg://jobs.example", authorization.audience.?);
    try std.testing.expectEqualStrings(hello_auth_purpose, authorization.purpose.?);
    try std.testing.expectEqualStrings("token-1", authorization.token_id.?);
    try std.testing.expect(authorization.allowsPattern(.rep));
    try std.testing.expect(!authorization.allowsPattern(.@"pub"));
    try std.testing.expect(authorization.allowsSubject("jobs.image.resize"));
    try std.testing.expect(authorization.allowsSubject("presence.user.1"));
    try std.testing.expect(!authorization.allowsSubject("jobs.video.resize"));
    try std.testing.expect(authorization.datagram_allowed);
    try std.testing.expectEqual(@as(?usize, 1_048_576), authorization.max_message_size);
    try std.testing.expectEqual(@as(?i64, 1_780_272_000_000), authorization.expires_at_unix_ms);
}

test "Authorization rejects malformed qmsg claims" {
    const allocator = std.testing.allocator;
    try std.testing.expectError(
        Error.InvalidClaims,
        Authorization.fromClaimsJson(allocator, "{\"iss\":\"auth\",\"sub\":\"s\"}", .{}),
    );
    try std.testing.expectError(
        Error.InvalidClaims,
        Authorization.fromClaimsJson(
            allocator,
            "{\"iss\":\"auth\",\"sub\":\"s\",\"qmsg\":{\"patterns\":[\"bogus\"]}}",
            .{},
        ),
    );
}

test "Authorization enforces configured audience and purpose policy" {
    const allocator = std.testing.allocator;
    const claims =
        \\{
        \\  "iss":"auth",
        \\  "sub":"service",
        \\  "aud":"qmsg://jobs.example",
        \\  "qmsg":{"purpose":"hello","patterns":["pair"]}
        \\}
    ;
    const audiences = [_][]const u8{"qmsg://jobs.example"};
    const purposes = [_][]const u8{hello_auth_purpose};

    var authorization = try Authorization.fromClaimsJson(allocator, claims, .{
        .expected_audiences = &audiences,
        .expected_purposes = &purposes,
    });
    defer authorization.deinit(allocator);

    const wrong_audiences = [_][]const u8{"qmsg://other.example"};
    try std.testing.expectError(
        Error.InvalidClaims,
        Authorization.fromClaimsJson(allocator, claims, .{ .expected_audiences = &wrong_audiences }),
    );
    try std.testing.expectError(
        Error.InvalidClaims,
        Authorization.fromClaimsJson(
            allocator,
            "{\"iss\":\"auth\",\"sub\":\"service\",\"qmsg\":{\"patterns\":[\"pair\"]}}",
            .{ .require_audience = true, .require_purpose = true },
        ),
    );
}

test "AuthConfig bounds token size and anonymous subject filters" {
    const config = AuthConfig{
        .required = true,
        .max_token_bytes = 4,
        .max_implicit_assertion_bytes = 4,
        .allow_anonymous_subjects = &.{"health.*"},
    };

    try config.validateCredentialSize(.{ .token = "1234" });
    try std.testing.expectError(Error.TokenTooLarge, config.validateCredentialSize(.{ .token = "12345" }));
    try std.testing.expectError(
        Error.ImplicitAssertionTooLarge,
        config.validateCredentialSize(.{ .token = "1234", .implicit_assertion = "12345" }),
    );
    try std.testing.expect(config.allowsAnonymousSubject("health.ping"));
    try std.testing.expect(!config.allowsAnonymousSubject("admin.delete"));
}

test "HELLO challenge helpers validate, mint, and compare bounded bytes" {
    const allocator = std.testing.allocator;

    var prng = std.Random.DefaultPrng.init(0x51525354);
    const challenge = try allocHelloChallenge(
        allocator,
        prng.random(),
        default_hello_challenge_bytes,
        .{},
    );
    defer allocator.free(challenge);

    try std.testing.expectEqual(default_hello_challenge_bytes, challenge.len);
    try validateHelloChallenge(challenge, .{ .required = true });

    const copied = try allocator.dupe(u8, challenge);
    defer allocator.free(copied);
    try std.testing.expect(helloChallengeMatches(challenge, copied));

    copied[0] ^= 0xff;
    try std.testing.expect(!helloChallengeMatches(challenge, copied));
    try std.testing.expect(!helloChallengeMatches(challenge, challenge[0 .. challenge.len - 1]));

    try std.testing.expectError(Error.ChallengeRequired, validateHelloChallenge(&.{}, .{ .required = true }));
    try std.testing.expectError(Error.ChallengeTooLarge, validateHelloChallenge("12345", .{ .max_bytes = 4 }));
    try std.testing.expectError(Error.ChallengeRequired, allocHelloChallenge(allocator, prng.random(), 0, .{}));
    try std.testing.expectError(Error.ChallengeTooLarge, allocHelloChallenge(allocator, prng.random(), 5, .{ .max_bytes = 4 }));
}

test "HELLO challenge state mints owns and installs binding config" {
    const allocator = std.testing.allocator;

    var prng = std.Random.DefaultPrng.init(0x51525354);
    var state = try HelloChallengeState.mint(allocator, prng.random(), .{
        .audience = "qmsg://jobs.example",
        .authority = "jobs.example:443",
        .listener_id = "listener-a",
    }, 16, .{ .max_bytes = 32 });
    defer state.deinit(allocator);

    try std.testing.expect(state.isActive());
    try std.testing.expectEqual(@as(usize, 16), state.challenge().len);
    try std.testing.expectEqual(state.challenge().ptr, state.context.challenge.ptr);
    try validateHelloChallenge(state.challenge(), .{ .required = true, .max_bytes = 32 });

    var config = AuthConfig{ .required = true };
    try state.install(&config);
    try std.testing.expect(config.hello_binding.require_challenge);
    try std.testing.expectEqual(@as(usize, 32), config.hello_binding.max_challenge_bytes);

    const context = config.hello_binding.context.?;
    try std.testing.expectEqualStrings("qmsg://jobs.example", context.audience);
    try std.testing.expectEqualStrings("jobs.example:443", context.authority);
    try std.testing.expectEqualStrings("listener-a", context.listener_id);
    try std.testing.expect(helloChallengeMatches(state.challenge(), context.challenge));
    try config.hello_binding.validate();
}

test "HELLO challenge state consume and discard fail closed" {
    const allocator = std.testing.allocator;

    var prng = std.Random.DefaultPrng.init(0x51525354);
    var consumed = try HelloChallengeState.mintDefault(allocator, prng.random(), .{}, .{});
    try std.testing.expect(consumed.isActive());
    consumed.consume(allocator);
    try std.testing.expect(!consumed.isActive());
    try std.testing.expectEqual(@as(usize, 0), consumed.challenge().len);
    try std.testing.expectEqual(@as(usize, 0), consumed.context.challenge.len);
    consumed.consume(allocator);

    var config = AuthConfig{ .hello_binding = .{ .context = .{ .challenge = "old" } } };
    try std.testing.expectError(Error.ChallengeRequired, consumed.install(&config));
    try std.testing.expect(config.hello_binding.context != null);
    try std.testing.expectEqualStrings("old", config.hello_binding.context.?.challenge);

    var discarded = try HelloChallengeState.mint(allocator, prng.random(), .{}, 8, .{ .max_bytes = 8 });
    discarded.discard(allocator);
    try std.testing.expect(!discarded.isActive());
    try std.testing.expectError(Error.ChallengeRequired, discarded.bindingPolicy());
    discarded.deinit(allocator);
}

test "HELLO challenge config enforces listener mint limits" {
    const allocator = std.testing.allocator;

    try std.testing.expectError(Error.ChallengeRequired, (HelloChallengeConfig{ .bytes = 0 }).validate());
    try std.testing.expectError(
        Error.ChallengeTooLarge,
        (HelloChallengeConfig{ .bytes = 17, .max_bytes = 16 }).validate(),
    );
    try std.testing.expectError(
        Error.ChallengeTooLarge,
        (HelloChallengeConfig{ .max_bytes = max_hello_challenge_bytes + 1 }).validate(),
    );

    var prng = std.Random.DefaultPrng.init(0x51525354);
    var state = try (HelloChallengeConfig{
        .context = .{ .listener_id = "listener-a" },
        .bytes = 8,
        .max_bytes = 16,
    }).mintState(allocator, prng.random());
    defer state.deinit(allocator);

    try std.testing.expectEqual(@as(usize, 8), state.challenge().len);
    try std.testing.expectEqual(@as(usize, 16), state.max_challenge_bytes);
    try std.testing.expectEqualStrings("listener-a", state.context.listener_id);
}

test "HELLO challenge binding installs AuthConfig and preserves base policy" {
    const allocator = std.testing.allocator;

    const audiences = [_][]const u8{"qmsg://jobs.example"};
    const purposes = [_][]const u8{hello_auth_purpose};
    const base_config = AuthConfig{
        .required = true,
        .max_token_bytes = 12,
        .expected_audiences = &audiences,
        .expected_purposes = &purposes,
        .hello_binding = .{ .context = .{ .challenge = "old" } },
    };

    var prng = std.Random.DefaultPrng.init(0x51525354);
    var binding = try (HelloChallengeConfig{
        .context = .{
            .audience = "qmsg://jobs.example",
            .authority = "jobs.example:443",
            .listener_id = "listener-a",
        },
        .bytes = 12,
        .max_bytes = 32,
    }).mintBinding(allocator, prng.random(), base_config);
    defer binding.deinit(allocator);

    const installed = try binding.authConfig();
    try std.testing.expect(installed.required);
    try std.testing.expectEqual(@as(usize, 12), installed.max_token_bytes);
    try std.testing.expectEqualStrings("qmsg://jobs.example", installed.expected_audiences[0]);
    try std.testing.expectEqualStrings(hello_auth_purpose, installed.expected_purposes[0]);
    try std.testing.expect(installed.hello_binding.require_challenge);
    try std.testing.expectEqual(@as(usize, 32), installed.hello_binding.max_challenge_bytes);

    const context = installed.hello_binding.context.?;
    try std.testing.expectEqualStrings("qmsg://jobs.example", context.audience);
    try std.testing.expectEqualStrings("jobs.example:443", context.authority);
    try std.testing.expectEqualStrings("listener-a", context.listener_id);
    try std.testing.expect(helloChallengeMatches(binding.challenge(), context.challenge));
    try installed.hello_binding.validate();
}

test "HELLO challenge binding consume and discard invalidate installed config" {
    const allocator = std.testing.allocator;

    var prng = std.Random.DefaultPrng.init(0x51525354);
    var consumed = try (HelloChallengeConfig{ .bytes = 8, .max_bytes = 16 }).mintBinding(
        allocator,
        prng.random(),
        .{ .required = true },
    );
    try std.testing.expect(consumed.isActive());
    try consumed.auth_config.hello_binding.validate();
    consumed.consume(allocator);
    try std.testing.expect(!consumed.isActive());
    try std.testing.expect(consumed.auth_config.hello_binding.context == null);
    try std.testing.expectError(Error.ChallengeRequired, consumed.authConfig());
    try std.testing.expectError(Error.ChallengeRequired, consumed.auth_config.hello_binding.validate());
    consumed.consume(allocator);
    consumed.deinit(allocator);

    var discarded = try (HelloChallengeConfig{ .bytes = 8, .max_bytes = 16 }).mintBinding(
        allocator,
        prng.random(),
        .{ .required = true },
    );
    discarded.discard(allocator);
    try std.testing.expect(!discarded.isActive());
    try std.testing.expect(discarded.auth_config.hello_binding.context == null);
    try std.testing.expectError(Error.ChallengeRequired, discarded.authConfig());
    try std.testing.expectError(Error.ChallengeRequired, discarded.auth_config.hello_binding.validate());
    discarded.deinit(allocator);
}

test "HELLO implicit assertion encodes challenge-bound context" {
    const allocator = std.testing.allocator;

    const first = try allocHelloImplicitAssertion(allocator, .{
        .audience = "qmsg://jobs.example",
        .authority = "jobs.example:443",
        .listener_id = "listener-a",
        .challenge = "nonce-1",
    });
    defer allocator.free(first);

    const second = try allocHelloImplicitAssertion(allocator, .{
        .audience = "qmsg://jobs.example",
        .authority = "jobs.example:443",
        .listener_id = "listener-a",
        .challenge = "nonce-2",
    });
    defer allocator.free(second);

    try std.testing.expect(!std.mem.eql(u8, first, second));
    try std.testing.expect(std.mem.indexOf(u8, first, hello_implicit_assertion_prefix) != null);

    try (HelloBindingPolicy{
        .context = .{ .challenge = "nonce-1" },
        .require_challenge = true,
    }).validate();
    try std.testing.expectError(Error.ChallengeRequired, (HelloBindingPolicy{ .require_challenge = true }).validate());
    try std.testing.expectError(
        Error.ChallengeTooLarge,
        (HelloBindingPolicy{
            .context = .{ .challenge = "12345" },
            .max_challenge_bytes = 4,
        }).validate(),
    );
}

test "Hello credentials map to generic credentials and fail closed" {
    const config = AuthConfig{ .required = true, .max_token_bytes = 4 };

    try std.testing.expect(try credentialFromHello(config, .{}) == null);
    try std.testing.expectError(
        Error.UnsupportedCredential,
        credentialFromHello(config, .{ .scheme = "bearer", .credential = "1234" }),
    );
    try std.testing.expectError(
        Error.AuthenticationRequired,
        credentialFromHello(config, .{ .scheme = hello_auth_scheme_paseto }),
    );
    try std.testing.expectError(
        Error.TokenTooLarge,
        credentialFromHello(config, .{ .scheme = hello_auth_scheme_paseto, .credential = "12345" }),
    );

    const credential = (try credentialFromHello(config, .{
        .scheme = hello_auth_scheme_paseto,
        .credential = "1234",
        .key_id_hint = "k4.pid.example",
    })).?;
    try std.testing.expectEqualStrings("1234", credential.token);
    try std.testing.expectEqualStrings("k4.pid.example", credential.key_id_hint.?);
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
