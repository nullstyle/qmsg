const std = @import("std");
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
    max_footer_bytes: usize = paserk_id_bytes,
    max_claims_bytes: usize = 16 * 1024,
    max_implicit_assertion_bytes: usize = 1024,
    require_footer_key_id: bool = true,
    require_hint_match: bool = true,
    validator: ?paseto.Validator = null,
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
    token: paseto.Token,
    hint: ?PaserkId,
    options: VerifyOptions,
) Error!PaserkId {
    if (token.footer.len > options.max_footer_bytes) return Error.FooterTooLarge;

    const footer_id = if (token.footer.len == 0)
        null
    else
        try parseV4PublicKeyId(token.footer);

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

    const key_id = try resolveV4PublicKeyId(token, credential.key_id_hint, options);
    const key = try keys.requireV4Public(key_id);

    const footer_copy = try allocator.dupe(u8, token.footer);
    errdefer allocator.free(footer_copy);

    const claims = key.verifyToken(
        allocator,
        token,
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
