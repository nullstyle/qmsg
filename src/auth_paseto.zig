const std = @import("std");
const auth = @import("auth.zig");
const paseto = @import("paseto");

pub const PaserkId = paseto.PaserkId;
pub const V4Public = paseto.v4.Public;
pub const V4Local = paseto.v4.Local;

pub const paserk_id_bytes = paseto.paserk.id.string_bytes;

const v4_public_signature_bytes: usize = 64;

pub const Error = error{
    TokenTooLarge,
    FooterTooLarge,
    ClaimsTooLarge,
    ImplicitAssertionTooLarge,
    MissingKeyId,
    InvalidKeyId,
    KeyIdMismatch,
    UnknownKey,
    UnsupportedCredential,
    InvalidToken,
    InvalidSignature,
    InvalidClaims,
    CredentialExpired,
    CredentialNotYetValid,
};

pub const VerifyError = Error || error{OutOfMemory};

pub const V4PublicCredential = struct {
    token: []const u8,
    key_id_hint: ?PaserkId = null,
    implicit_assertion: []const u8 = &.{},
};

pub const VerifyOptions = struct {
    max_token_bytes: usize = 4096,
    max_footer_bytes: usize = 512,
    max_claims_bytes: usize = 16 * 1024,
    max_implicit_assertion_bytes: usize = 1024,
    require_footer_key_id: bool = true,
    require_hint_match: bool = true,
    validator: ?paseto.Validator = null,
};

pub const AuthOptions = struct {
    verify: VerifyOptions = .{},
    claims: auth.Authorization.ClaimParseOptions = .{},
    replay_cache: ?auth.ReplayCache = null,
    replay: auth.ReplayPolicy = .{},
};

pub const V4PublicAuthenticator = struct {
    keys: KeyStore,
    options: AuthOptions = .{},

    pub fn authenticator(self: *V4PublicAuthenticator) auth.Authenticator {
        return .{
            .ptr = self,
            .authenticate_fn = authenticate,
        };
    }

    fn authenticate(
        ptr: ?*anyopaque,
        allocator: std.mem.Allocator,
        credential: auth.Credential,
    ) !auth.Authorization {
        const self: *V4PublicAuthenticator = @ptrCast(@alignCast(ptr.?));
        const key_id_hint = if (credential.key_id_hint) |hint|
            try parseV4PublicKeyId(hint)
        else
            null;

        return try authenticateV4Public(
            allocator,
            self.keys,
            .{
                .token = credential.token,
                .key_id_hint = key_id_hint,
                .implicit_assertion = credential.implicit_assertion,
            },
            self.options,
        );
    }
};

pub const VerifiedV4Public = struct {
    key_id: PaserkId,
    claims: []u8,
    footer: []u8,
    allocator: std.mem.Allocator,

    pub fn deinit(self: *VerifiedV4Public) void {
        self.allocator.free(self.claims);
        self.allocator.free(self.footer);
        self.* = undefined;
    }
};

pub const KeyStore = struct {
    ptr: ?*const anyopaque = null,
    find_v4_public_fn: ?*const fn (?*const anyopaque, PaserkId) ?V4Public = null,
    find_v4_local_fn: ?*const fn (?*const anyopaque, PaserkId) ?V4Local = null,

    pub fn findV4Public(self: KeyStore, key_id: PaserkId) ?V4Public {
        const find_fn = self.find_v4_public_fn orelse return null;
        return find_fn(self.ptr, key_id);
    }

    pub fn findV4Local(self: KeyStore, key_id: PaserkId) ?V4Local {
        const find_fn = self.find_v4_local_fn orelse return null;
        return find_fn(self.ptr, key_id);
    }

    pub fn requireV4Public(self: KeyStore, key_id: PaserkId) VerifyError!V4Public {
        try requireV4PublicKeyId(key_id);
        const key = self.findV4Public(key_id) orelse return Error.UnknownKey;
        if (!v4PublicKeyMatchesId(key, key_id)) return Error.KeyIdMismatch;
        return key;
    }
};

pub const PublicKeyEntry = struct {
    key_id: PaserkId,
    key: V4Public,
};

pub const StaticKeyStore = struct {
    v4_public_keys: []const PublicKeyEntry = &.{},

    pub fn keyStore(self: *const StaticKeyStore) KeyStore {
        return .{
            .ptr = self,
            .find_v4_public_fn = findV4Public,
        };
    }

    fn findV4Public(ptr: ?*const anyopaque, key_id: PaserkId) ?V4Public {
        const self: *const StaticKeyStore = @ptrCast(@alignCast(ptr orelse return null));
        for (self.v4_public_keys) |entry| {
            if (entry.key_id.eql(key_id)) return entry.key;
        }
        return null;
    }
};

pub fn parsePaserkId(raw: []const u8) Error!PaserkId {
    return paseto.paserk.id.parse(raw) catch return Error.InvalidKeyId;
}

pub fn parseV4PublicKeyId(raw: []const u8) Error!PaserkId {
    const key_id = try parsePaserkId(raw);
    try requireV4PublicKeyId(key_id);
    return key_id;
}

pub fn parseV4PublicFooterKeyId(allocator: std.mem.Allocator, raw: []const u8) Error!PaserkId {
    if (std.mem.startsWith(u8, raw, "k4.")) return try parseV4PublicKeyId(raw);

    var parsed = std.json.parseFromSlice(std.json.Value, allocator, raw, .{}) catch {
        return Error.InvalidKeyId;
    };
    defer parsed.deinit();

    if (parsed.value != .object) return Error.InvalidKeyId;
    const kid = parsed.value.object.get("kid") orelse return Error.InvalidKeyId;
    if (kid != .string) return Error.InvalidKeyId;
    return try parseV4PublicKeyId(kid.string);
}

pub fn requireV4PublicKeyId(key_id: PaserkId) Error!void {
    if (key_id.version != .v4) return Error.UnsupportedCredential;
    if (key_id.kind != .pid) return Error.UnsupportedCredential;
}

pub fn v4PublicKeyId(key: V4Public) VerifyError!PaserkId {
    const public_key = key.publicKeyBytes();
    return PaserkId.fromKey(.v4, .pid, &public_key) catch |err| return mapPasetoError(err);
}

pub fn v4PublicKeyMatchesId(key: V4Public, key_id: PaserkId) bool {
    const computed = v4PublicKeyId(key) catch return false;
    return computed.eql(key_id);
}

pub fn resolveV4PublicKeyId(
    allocator: std.mem.Allocator,
    token: paseto.Token,
    hint: ?PaserkId,
    options: VerifyOptions,
) Error!PaserkId {
    if (token.footer.len > options.max_footer_bytes) return Error.FooterTooLarge;

    const footer_id = if (token.footer.len == 0)
        null
    else
        try parseV4PublicFooterKeyId(allocator, token.footer);

    if (footer_id) |from_footer| {
        if (hint) |from_hint| {
            try requireV4PublicKeyId(from_hint);
            if (options.require_hint_match and !from_footer.eql(from_hint)) return Error.KeyIdMismatch;
        }
        return from_footer;
    }

    if (options.require_footer_key_id) return Error.MissingKeyId;

    const from_hint = hint orelse return Error.MissingKeyId;
    try requireV4PublicKeyId(from_hint);
    return from_hint;
}

pub fn verifyV4Public(
    allocator: std.mem.Allocator,
    keys: KeyStore,
    credential: V4PublicCredential,
    options: VerifyOptions,
) VerifyError!VerifiedV4Public {
    if (credential.token.len > options.max_token_bytes) return Error.TokenTooLarge;
    if (credential.implicit_assertion.len > options.max_implicit_assertion_bytes) {
        return Error.ImplicitAssertionTooLarge;
    }

    var token = paseto.token.parse(allocator, credential.token) catch |err| return mapPasetoError(err);
    defer token.deinit();

    if (token.version != .v4 or token.purpose != .public) return Error.UnsupportedCredential;
    if (token.footer.len > options.max_footer_bytes) return Error.FooterTooLarge;
    if (token.payload.len < v4_public_signature_bytes) return Error.InvalidToken;
    if (token.payload.len - v4_public_signature_bytes > options.max_claims_bytes) {
        return Error.ClaimsTooLarge;
    }

    const key_id = try resolveV4PublicKeyId(allocator, token, credential.key_id_hint, options);
    const key = try keys.requireV4Public(key_id);

    const footer_copy = try allocator.dupe(u8, token.footer);
    errdefer allocator.free(footer_copy);

    const claims = key.verifyToken(
        allocator,
        &token,
        credential.implicit_assertion,
    ) catch |err| return mapPasetoError(err);
    errdefer allocator.free(claims);

    if (claims.len > options.max_claims_bytes) return Error.ClaimsTooLarge;

    if (options.validator) |validator| {
        validator.validate(claims, allocator) catch |err| return mapValidationError(err);
    }

    return .{
        .key_id = key_id,
        .claims = claims,
        .footer = footer_copy,
        .allocator = allocator,
    };
}

pub fn authenticateV4Public(
    allocator: std.mem.Allocator,
    keys: KeyStore,
    credential: V4PublicCredential,
    options: AuthOptions,
) !auth.Authorization {
    var verified = try verifyV4Public(allocator, keys, credential, options.verify);
    defer verified.deinit();

    var authorization = try auth.Authorization.fromClaimsJson(
        allocator,
        verified.claims,
        options.claims,
    );
    errdefer authorization.deinit(allocator);

    if (options.replay_cache) |replay_cache| {
        try options.replay.validate(authorization);
        const token_id = authorization.token_id orelse return auth.Error.InvalidClaims;
        try replay_cache.checkAndStore(.{
            .issuer = authorization.issuer,
            .token_id = token_id,
            .expires_at_unix_ms = authorization.expires_at_unix_ms,
        });
    }

    return authorization;
}

fn mapPasetoError(err: anyerror) VerifyError {
    return switch (err) {
        error.OutOfMemory => error.OutOfMemory,
        error.InvalidKeyId,
        error.InvalidEncoding,
        error.InvalidBase64,
        error.InvalidPadding,
        => Error.InvalidKeyId,
        error.InvalidToken,
        error.InvalidHeader,
        error.InvalidFooter,
        error.InvalidPayload,
        error.MessageTooShort,
        => Error.InvalidToken,
        error.InvalidSignature,
        error.InvalidAuthenticator,
        => Error.InvalidSignature,
        error.WrongVersion,
        error.WrongPurpose,
        error.UnsupportedVersion,
        error.UnsupportedPurpose,
        error.UnsupportedOperation,
        => Error.UnsupportedCredential,
        else => Error.UnsupportedCredential,
    };
}

fn mapValidationError(err: anyerror) VerifyError {
    return switch (err) {
        error.OutOfMemory => error.OutOfMemory,
        error.ExpiredToken => Error.CredentialExpired,
        error.InactiveToken,
        error.ImmatureToken,
        => Error.CredentialNotYetValid,
        else => Error.InvalidClaims,
    };
}

test "PaserkId alias uses real paseto dependency" {
    try std.testing.expect(PaserkId == paseto.PaserkId);
    try std.testing.expect(paseto.PaserkId == paseto.paserk.Id);
}

test "parse v4 public PASERK ID from generated key" {
    const seed: [32]u8 = @splat(7);
    const key = try V4Public.fromSeed(&seed);
    const key_id = try v4PublicKeyId(key);
    const encoded = key_id.toArray();

    const parsed = try parseV4PublicKeyId(&encoded);
    try std.testing.expect(key_id.eql(parsed));
    const footer_json = try std.fmt.allocPrint(std.testing.allocator, "{{\"kid\":\"{s}\"}}", .{&encoded});
    defer std.testing.allocator.free(footer_json);
    const parsed_json = try parseV4PublicFooterKeyId(std.testing.allocator, footer_json);
    try std.testing.expect(key_id.eql(parsed_json));

    const local_key_bytes: [32]u8 = @splat(3);
    const local_id = try PaserkId.fromKey(.v4, .lid, &local_key_bytes);
    const local_encoded = local_id.toArray();
    try std.testing.expectError(Error.UnsupportedCredential, parseV4PublicKeyId(&local_encoded));
    try std.testing.expectError(Error.InvalidKeyId, parsePaserkId("k4.pid.not-a-real-key-id"));
}

test "static key store lookup validates key id mismatch" {
    const first = try V4Public.fromSeed(&@as([32]u8, @splat(1)));
    const second = try V4Public.fromSeed(&@as([32]u8, @splat(2)));
    const first_id = try v4PublicKeyId(first);
    const second_id = try v4PublicKeyId(second);

    const entries = [_]PublicKeyEntry{.{ .key_id = first_id, .key = first }};
    const static = StaticKeyStore{ .v4_public_keys = &entries };
    const keys = static.keyStore();

    try std.testing.expect(keys.findV4Public(first_id) != null);
    try std.testing.expect(keys.findV4Public(second_id) == null);
    _ = try keys.requireV4Public(first_id);
    try std.testing.expectError(Error.UnknownKey, keys.requireV4Public(second_id));

    const mismatched_entries = [_]PublicKeyEntry{.{ .key_id = first_id, .key = second }};
    const mismatched_static = StaticKeyStore{ .v4_public_keys = &mismatched_entries };
    try std.testing.expectError(
        Error.KeyIdMismatch,
        mismatched_static.keyStore().requireV4Public(first_id),
    );
}

test "verify v4 public token using PASERK ID footer and validator" {
    const allocator = std.testing.allocator;
    const key = try V4Public.fromSeed(&@as([32]u8, @splat(11)));
    const key_id = try v4PublicKeyId(key);
    const footer = key_id.toArray();

    const claims =
        \\{"iss":"issuer.example","sub":"service:image-worker","jti":"token-1"}
    ;
    const token = try key.sign(allocator, claims, .{ .footer = &footer });
    defer allocator.free(token);

    const entries = [_]PublicKeyEntry{.{ .key_id = key_id, .key = key }};
    const static = StaticKeyStore{ .v4_public_keys = &entries };

    var verified = try verifyV4Public(
        allocator,
        static.keyStore(),
        .{ .token = token },
        .{
            .validator = paseto.Validator{
                .expected_issuer = "issuer.example",
                .require_subject = true,
                .expected_token_identifier = "token-1",
                .now_override = 1_700_000_000,
            },
        },
    );
    defer verified.deinit();

    try std.testing.expect(key_id.eql(verified.key_id));
    try std.testing.expectEqualSlices(u8, &footer, verified.footer);
    try std.testing.expectEqualSlices(u8, claims, verified.claims);
}

test "verify v4 public token is bound to HELLO implicit assertion" {
    const allocator = std.testing.allocator;
    const key = try V4Public.fromSeed(&@as([32]u8, @splat(15)));
    const key_id = try v4PublicKeyId(key);
    const footer = key_id.toArray();
    const entries = [_]PublicKeyEntry{.{ .key_id = key_id, .key = key }};
    const static = StaticKeyStore{ .v4_public_keys = &entries };

    const good_assertion = try auth.allocHelloImplicitAssertion(allocator, .{
        .audience = "qmsg://jobs.example",
        .authority = "jobs.example:443",
        .listener_id = "listener-a",
        .challenge = "nonce-1",
    });
    defer allocator.free(good_assertion);
    const wrong_assertion = try auth.allocHelloImplicitAssertion(allocator, .{
        .audience = "qmsg://jobs.example",
        .authority = "jobs.example:443",
        .listener_id = "listener-a",
        .challenge = "nonce-2",
    });
    defer allocator.free(wrong_assertion);

    const claims =
        \\{"iss":"issuer.example","sub":"service:hello","aud":"qmsg://jobs.example","qmsg":{"purpose":"hello","patterns":["pair"]}}
    ;
    const token = try key.sign(allocator, claims, .{
        .footer = &footer,
        .implicit_assertion = good_assertion,
    });
    defer allocator.free(token);

    var verified = try verifyV4Public(
        allocator,
        static.keyStore(),
        .{ .token = token, .implicit_assertion = good_assertion },
        .{},
    );
    defer verified.deinit();

    try std.testing.expectError(
        Error.InvalidSignature,
        verifyV4Public(
            allocator,
            static.keyStore(),
            .{ .token = token, .implicit_assertion = wrong_assertion },
            .{},
        ),
    );
}

test "verify rejects missing unknown and mismatched key ids fail closed" {
    const allocator = std.testing.allocator;
    const first = try V4Public.fromSeed(&@as([32]u8, @splat(21)));
    const second = try V4Public.fromSeed(&@as([32]u8, @splat(22)));
    const first_id = try v4PublicKeyId(first);
    const second_id = try v4PublicKeyId(second);
    const first_footer = first_id.toArray();

    const token_with_footer = try first.sign(allocator, "{}", .{ .footer = &first_footer });
    defer allocator.free(token_with_footer);
    const token_without_footer = try first.sign(allocator, "{}", .{});
    defer allocator.free(token_without_footer);

    const entries = [_]PublicKeyEntry{.{ .key_id = first_id, .key = first }};
    const static = StaticKeyStore{ .v4_public_keys = &entries };
    const keys = static.keyStore();

    try std.testing.expectError(
        Error.MissingKeyId,
        verifyV4Public(allocator, keys, .{ .token = token_without_footer }, .{}),
    );
    try std.testing.expectError(
        Error.KeyIdMismatch,
        verifyV4Public(
            allocator,
            keys,
            .{ .token = token_with_footer, .key_id_hint = second_id },
            .{},
        ),
    );
    try std.testing.expectError(
        Error.UnknownKey,
        verifyV4Public(
            allocator,
            .{},
            .{ .token = token_with_footer },
            .{},
        ),
    );
}

test "authenticate maps qmsg claims into Authorization and checks replay cache" {
    const allocator = std.testing.allocator;
    const key = try V4Public.fromSeed(&@as([32]u8, @splat(31)));
    const key_id = try v4PublicKeyId(key);
    const footer = key_id.toArray();

    const claims =
        \\{
        \\  "iss":"issuer.example",
        \\  "sub":"service:image-worker",
        \\  "aud":"qmsg://jobs.example",
        \\  "exp":"2026-06-01T00:00:00Z",
        \\  "jti":"token-replay-1",
        \\  "qmsg":{
        \\    "patterns":["pull"],
        \\    "subjects":["jobs.image.*"],
        \\    "datagram":false,
        \\    "max_message_size":4096
        \\  }
        \\}
    ;
    const token = try key.sign(allocator, claims, .{ .footer = &footer });
    defer allocator.free(token);

    const entries = [_]PublicKeyEntry{.{ .key_id = key_id, .key = key }};
    const static = StaticKeyStore{ .v4_public_keys = &entries };
    const audiences = [_][]const u8{"qmsg://jobs.example"};

    const Replay = struct {
        seen: bool = false,

        fn checkAndStore(ptr: ?*anyopaque, entry: auth.ReplayEntry) !void {
            const self: *@This() = @ptrCast(@alignCast(ptr.?));
            try std.testing.expectEqualStrings("issuer.example", entry.issuer);
            try std.testing.expectEqualStrings("token-replay-1", entry.token_id);
            try std.testing.expectEqual(@as(?i64, 1_780_272_000_000), entry.expires_at_unix_ms);
            if (self.seen) return auth.Error.ReplayedCredential;
            self.seen = true;
        }
    };
    var replay = Replay{};

    var authorization = try authenticateV4Public(
        allocator,
        static.keyStore(),
        .{ .token = token },
        .{
            .verify = .{
                .validator = paseto.Validator{
                    .expected_issuer = "issuer.example",
                    .expected_audience = &audiences,
                    .require_subject = true,
                    .require_token_identifier = true,
                    .now_override = 1_700_000_000,
                },
            },
            .replay_cache = .{
                .ptr = &replay,
                .check_and_store_fn = Replay.checkAndStore,
            },
        },
    );
    defer authorization.deinit(allocator);

    try std.testing.expectEqualStrings("service:image-worker", authorization.subject);
    try authorization.check(.{ .pattern = .pull, .subject = "jobs.image.resize", .message_size = 4096 });
    try std.testing.expectError(auth.Error.Unauthorized, authorization.check(.{ .pattern = .push }));

    try std.testing.expectError(
        auth.Error.ReplayedCredential,
        authenticateV4Public(
            allocator,
            static.keyStore(),
            .{ .token = token },
            .{
                .verify = .{
                    .validator = paseto.Validator{
                        .expected_issuer = "issuer.example",
                        .expected_audience = &audiences,
                        .require_subject = true,
                        .require_token_identifier = true,
                        .now_override = 1_700_000_000,
                    },
                },
                .replay_cache = .{
                    .ptr = &replay,
                    .check_and_store_fn = Replay.checkAndStore,
                },
            },
        ),
    );
}

test "authenticate replay cache requires expiry and rejects expired entries before store" {
    const allocator = std.testing.allocator;
    const key = try V4Public.fromSeed(&@as([32]u8, @splat(33)));
    const key_id = try v4PublicKeyId(key);
    const footer = key_id.toArray();
    const entries = [_]PublicKeyEntry{.{ .key_id = key_id, .key = key }};
    const static = StaticKeyStore{ .v4_public_keys = &entries };

    const Replay = struct {
        calls: usize = 0,

        fn checkAndStore(ptr: ?*anyopaque, _: auth.ReplayEntry) !void {
            const self: *@This() = @ptrCast(@alignCast(ptr.?));
            self.calls += 1;
        }
    };
    var replay = Replay{};

    const missing_exp_claims =
        \\{"iss":"issuer.example","sub":"service","jti":"token-no-exp","qmsg":{"patterns":["pair"]}}
    ;
    const missing_exp_token = try key.sign(allocator, missing_exp_claims, .{ .footer = &footer });
    defer allocator.free(missing_exp_token);
    try std.testing.expectError(
        auth.Error.InvalidClaims,
        authenticateV4Public(
            allocator,
            static.keyStore(),
            .{ .token = missing_exp_token },
            .{
                .replay_cache = .{
                    .ptr = &replay,
                    .check_and_store_fn = Replay.checkAndStore,
                },
            },
        ),
    );
    try std.testing.expectEqual(@as(usize, 0), replay.calls);

    const expired_claims =
        \\{"iss":"issuer.example","sub":"service","jti":"token-expired","exp":"2022-01-01T00:00:00Z","qmsg":{"patterns":["pair"]}}
    ;
    const expired_token = try key.sign(allocator, expired_claims, .{ .footer = &footer });
    defer allocator.free(expired_token);
    try std.testing.expectError(
        auth.Error.CredentialExpired,
        authenticateV4Public(
            allocator,
            static.keyStore(),
            .{ .token = expired_token },
            .{
                .replay_cache = .{
                    .ptr = &replay,
                    .check_and_store_fn = Replay.checkAndStore,
                },
                .replay = .{ .now_unix_ms = 1_700_000_000_000 },
            },
        ),
    );
    try std.testing.expectEqual(@as(usize, 0), replay.calls);
}

test "V4PublicAuthenticator adapts generic HELLO credentials" {
    const allocator = std.testing.allocator;
    const key = try V4Public.fromSeed(&@as([32]u8, @splat(35)));
    const key_id = try v4PublicKeyId(key);
    const key_id_bytes = key_id.toArray();

    const claims =
        \\{
        \\  "iss":"issuer.example",
        \\  "sub":"service:hello",
        \\  "qmsg":{
        \\    "patterns":["pair"],
        \\    "subjects":">"
        \\  }
        \\}
    ;
    const token = try key.sign(allocator, claims, .{});
    defer allocator.free(token);

    const entries = [_]PublicKeyEntry{.{ .key_id = key_id, .key = key }};
    const static = StaticKeyStore{ .v4_public_keys = &entries };
    var concrete = V4PublicAuthenticator{
        .keys = static.keyStore(),
        .options = .{
            .verify = .{ .require_footer_key_id = false },
        },
    };

    var authorization = try concrete.authenticator().authenticate(allocator, .{
        .token = token,
        .key_id_hint = &key_id_bytes,
    });
    defer authorization.deinit(allocator);

    try std.testing.expectEqualStrings("service:hello", authorization.subject);
    try authorization.check(.{ .pattern = .pair, .subject = "anything" });

    var unknown = V4PublicAuthenticator{
        .keys = .{},
        .options = .{
            .verify = .{ .require_footer_key_id = false },
        },
    };
    try std.testing.expectError(
        Error.UnknownKey,
        unknown.authenticator().authenticate(allocator, .{
            .token = token,
            .key_id_hint = &key_id_bytes,
        }),
    );
}

test "verify rejects footer key-id tampering and wrong trusted key" {
    const allocator = std.testing.allocator;
    const first = try V4Public.fromSeed(&@as([32]u8, @splat(41)));
    const second = try V4Public.fromSeed(&@as([32]u8, @splat(42)));
    const first_id = try v4PublicKeyId(first);
    const second_id = try v4PublicKeyId(second);
    const first_footer = first_id.toArray();
    const second_footer = second_id.toArray();

    const token = try first.sign(allocator, "{}", .{ .footer = &first_footer });
    defer allocator.free(token);

    var parsed = try paseto.token.parse(allocator, token);
    defer parsed.deinit();
    const tampered = try paseto.token.serialize(allocator, .v4, .public, parsed.payload, &second_footer);
    defer allocator.free(tampered);

    const entries = [_]PublicKeyEntry{
        .{ .key_id = first_id, .key = first },
        .{ .key_id = second_id, .key = second },
    };
    const static = StaticKeyStore{ .v4_public_keys = &entries };
    try std.testing.expectError(
        Error.InvalidSignature,
        verifyV4Public(allocator, static.keyStore(), .{ .token = tampered }, .{}),
    );

    const wrong_entries = [_]PublicKeyEntry{.{ .key_id = first_id, .key = second }};
    const wrong_static = StaticKeyStore{ .v4_public_keys = &wrong_entries };
    try std.testing.expectError(
        Error.KeyIdMismatch,
        verifyV4Public(allocator, wrong_static.keyStore(), .{ .token = token }, .{}),
    );
}

test "verify maps expiry and not-before validation errors" {
    const allocator = std.testing.allocator;
    const key = try V4Public.fromSeed(&@as([32]u8, @splat(51)));
    const key_id = try v4PublicKeyId(key);
    const footer = key_id.toArray();
    const entries = [_]PublicKeyEntry{.{ .key_id = key_id, .key = key }};
    const static = StaticKeyStore{ .v4_public_keys = &entries };

    const expired_claims =
        \\{"iss":"issuer.example","sub":"service","exp":"2022-01-01T00:00:00Z","qmsg":{"patterns":["pair"]}}
    ;
    const expired_token = try key.sign(allocator, expired_claims, .{ .footer = &footer });
    defer allocator.free(expired_token);
    try std.testing.expectError(
        Error.CredentialExpired,
        verifyV4Public(
            allocator,
            static.keyStore(),
            .{ .token = expired_token },
            .{ .validator = paseto.Validator{ .now_override = 1_700_000_000 } },
        ),
    );

    const future_claims =
        \\{"iss":"issuer.example","sub":"service","nbf":"2026-01-01T00:00:00Z","qmsg":{"patterns":["pair"]}}
    ;
    const future_token = try key.sign(allocator, future_claims, .{ .footer = &footer });
    defer allocator.free(future_token);
    try std.testing.expectError(
        Error.CredentialNotYetValid,
        verifyV4Public(
            allocator,
            static.keyStore(),
            .{ .token = future_token },
            .{ .validator = paseto.Validator{ .now_override = 1_700_000_000 } },
        ),
    );
}
