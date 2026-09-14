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
    peer_supported_patterns: u64 = 0,
    auth_state: AuthState = .anonymous,
    authorization: ?auth.Authorization = null,
    datagram_enabled: bool = false,
    max_message_size: usize = 1024 * 1024,
    /// Peer's advertised `HELLO.heartbeat_interval_ms` (0 = not offered).
    /// The effective session heartbeat is `min(local, peer)` when BOTH
    /// sides offer a nonzero interval — see
    /// `QuicSessionRuntime.heartbeatInterval`.
    peer_heartbeat_interval_ms: u64 = 0,
    /// The identity the TLS handshake authenticated: SHA-256 over the
    /// DER SubjectPublicKeyInfo of the peer's leaf certificate, from
    /// `quic.Connection.peerCertSpkiDigest()`. Null before the
    /// handshake completes, on inproc sessions, and on QUIC sessions
    /// whose peer presented no certificate (a listener without
    /// `client_ca_pem`).
    ///
    /// Unlike `peer_id` — a claim the peer makes inside the channel —
    /// this is proved by the handshake. `AuthConfig.cert_binding`
    /// makes the claim answer to it.
    ///
    /// These are the same 32 bytes qmesh-zig uses as its `PeerId`, so
    /// one identity keys a qmsg session and a qmesh cluster member.
    peer_cert_spki: ?[32]u8 = null,
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

    /// Lowercase-hex rendering of `peer_cert_spki` (64 bytes), the
    /// canonical string form of the transport identity. Byte-for-byte
    /// equal to `qmesh.PeerId.hex()` for the same certificate, and to
    /// the standard `openssl x509 -pubkey | openssl pkey -pubin
    /// -outform DER | openssl dgst -sha256` fingerprint.
    pub fn certPeerIdHex(self: Session) ?[64]u8 {
        const digest = self.peer_cert_spki orelse return null;
        return std.fmt.bytesToHex(digest, .lower);
    }

    /// Enforce `config.cert_binding` against an announced HELLO id.
    /// An empty announcement is not a lie — the transport identity
    /// stands on its own — so only a non-empty mismatch is rejected.
    pub fn enforceCertBinding(
        self: Session,
        config: auth.AuthConfig,
        announced: []const u8,
    ) auth.Error!void {
        if (config.cert_binding == .off) return;
        const hex = self.certPeerIdHex() orelse {
            if (config.cert_binding == .required) return auth.Error.PeerIdentityRequired;
            return;
        };
        if (announced.len == 0) return;
        if (!std.mem.eql(u8, announced, &hex)) return auth.Error.PeerIdentityMismatch;
    }

    pub fn setAuthorization(self: *Session, authorization: auth.Authorization) void {
        self.auth_state = .authenticated;
        self.authorization = authorization;
    }

    pub fn authenticateHello(
        self: *Session,
        allocator: std.mem.Allocator,
        config: auth.AuthConfig,
        hello: auth.HelloCredentials,
    ) !void {
        var clear_on_error = true;
        errdefer if (clear_on_error) self.clearAuthorization(allocator);

        try config.hello_binding.validate();
        try auth.validateHelloChallenge(hello.challenge, .{
            .max_bytes = config.hello_binding.max_challenge_bytes,
        });

        var owned_implicit_assertion: ?[]u8 = null;
        defer if (owned_implicit_assertion) |assertion| allocator.free(assertion);

        var bound_hello = hello;
        if (config.hello_binding.context) |context| {
            owned_implicit_assertion = try auth.allocHelloImplicitAssertion(allocator, context);
            bound_hello.implicit_assertion = owned_implicit_assertion.?;
        }

        const credential = (try auth.credentialFromHello(config, bound_hello)) orelse {
            if (!config.allowsAnonymousSubject(hello.peer_id)) {
                return auth.Error.AuthenticationRequired;
            }
            self.clearAuthorization(allocator);
            clear_on_error = false;
            return;
        };

        const authenticator = config.authenticator orelse return auth.Error.UnsupportedCredential;
        var authorization = try authenticator.authenticate(allocator, credential);
        errdefer authorization.deinit(allocator);
        try config.validateAuthorization(authorization);

        self.clearAuthorization(allocator);
        self.setAuthorization(authorization);
        clear_on_error = false;
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

    /// Apply a cached policy at the semantic admission seam. Anonymous sessions
    /// remain usable when HELLO configuration allowed them.
    pub fn admit(self: Session, request: auth.Authorization.Check) auth.Error!void {
        if (self.authorization != null) return self.check(request);
        if (request.message_size) |size| if (size > self.max_message_size) return auth.Error.MessageTooLarge;
        if (request.datagram and !self.datagram_enabled) return auth.Error.Unauthorized;
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

test "Session authenticates HELLO credentials and caches authorization" {
    const allocator = std.testing.allocator;

    const TestAuthenticator = struct {
        calls: usize = 0,

        fn authenticate(
            ptr: ?*anyopaque,
            inner_allocator: std.mem.Allocator,
            credential: auth.Credential,
        ) !auth.Authorization {
            const self: *@This() = @ptrCast(@alignCast(ptr.?));
            self.calls += 1;
            try std.testing.expectEqualStrings("hello-token", credential.token);
            return try (auth.Authorization{
                .subject = "service:client",
                .issuer = "auth.example",
                .allowed_patterns = auth.PatternSet.init(&.{.req}),
                .allowed_subjects = .allow_all,
            }).clone(inner_allocator);
        }
    };

    var authenticator = TestAuthenticator{};
    var session = Session{ .id = 1, .transport = .inproc };
    defer session.clearAuthorization(allocator);

    try session.authenticateHello(allocator, .{
        .required = true,
        .authenticator = .{
            .ptr = &authenticator,
            .authenticate_fn = TestAuthenticator.authenticate,
        },
    }, .{
        .peer_id = "client-a",
        .scheme = auth.hello_auth_scheme_paseto,
        .credential = "hello-token",
    });

    try std.testing.expectEqual(@as(usize, 1), authenticator.calls);
    try session.requirePattern(.req);
    try std.testing.expectEqualStrings("service:client", session.authorizationCache().?.subject);
}

test "Session binds HELLO credential to configured challenge context" {
    const allocator = std.testing.allocator;

    const expected_assertion = try auth.allocHelloImplicitAssertion(allocator, .{
        .audience = "qmsg://jobs.example",
        .authority = "jobs.example:443",
        .listener_id = "listener-a",
        .challenge = "nonce-1",
    });
    defer allocator.free(expected_assertion);

    const TestAuthenticator = struct {
        expected: []const u8,

        fn authenticate(
            ptr: ?*anyopaque,
            inner_allocator: std.mem.Allocator,
            credential: auth.Credential,
        ) !auth.Authorization {
            const self: *@This() = @ptrCast(@alignCast(ptr.?));
            try std.testing.expectEqualStrings("hello-token", credential.token);
            try std.testing.expectEqualSlices(u8, self.expected, credential.implicit_assertion);
            return try (auth.Authorization{
                .subject = "service:client",
                .issuer = "auth.example",
                .audience = "qmsg://jobs.example",
                .purpose = auth.hello_auth_purpose,
                .allowed_patterns = auth.PatternSet.init(&.{.req}),
            }).clone(inner_allocator);
        }
    };

    var authenticator = TestAuthenticator{ .expected = expected_assertion };
    var session = Session{ .id = 1, .transport = .inproc };
    defer session.clearAuthorization(allocator);

    const expected_audiences = [_][]const u8{"qmsg://jobs.example"};
    const expected_purposes = [_][]const u8{auth.hello_auth_purpose};
    try session.authenticateHello(allocator, .{
        .required = true,
        .authenticator = .{
            .ptr = &authenticator,
            .authenticate_fn = TestAuthenticator.authenticate,
        },
        .hello_binding = .{
            .context = .{
                .audience = "qmsg://jobs.example",
                .authority = "jobs.example:443",
                .listener_id = "listener-a",
                .challenge = "nonce-1",
            },
            .require_challenge = true,
        },
        .expected_audiences = &expected_audiences,
        .expected_purposes = &expected_purposes,
    }, .{
        .peer_id = "client-a",
        .scheme = auth.hello_auth_scheme_paseto,
        .credential = "hello-token",
    });

    try std.testing.expect(session.isAuthenticated());
}

test "Session required HELLO challenge ignores peer challenge and fails wrong bindings closed" {
    const allocator = std.testing.allocator;

    const expected_assertion = try auth.allocHelloImplicitAssertion(allocator, .{
        .audience = "qmsg://jobs.example",
        .authority = "jobs.example:443",
        .listener_id = "listener-a",
        .challenge = "nonce-good",
    });
    defer allocator.free(expected_assertion);

    const TestAuthenticator = struct {
        expected: []const u8,

        fn authenticate(
            ptr: ?*anyopaque,
            inner_allocator: std.mem.Allocator,
            credential: auth.Credential,
        ) !auth.Authorization {
            const self: *@This() = @ptrCast(@alignCast(ptr.?));
            try std.testing.expectEqualStrings("hello-token", credential.token);
            if (!std.mem.eql(u8, self.expected, credential.implicit_assertion)) {
                return auth.Error.Unauthorized;
            }
            return try (auth.Authorization{
                .subject = "service:client",
                .issuer = "auth.example",
                .purpose = auth.hello_auth_purpose,
                .allowed_patterns = auth.PatternSet.init(&.{.req}),
            }).clone(inner_allocator);
        }
    };

    var authenticator = TestAuthenticator{ .expected = expected_assertion };
    var session = Session{ .id = 1, .transport = .inproc };
    defer session.clearAuthorization(allocator);

    try std.testing.expectError(
        auth.Error.ChallengeRequired,
        session.authenticateHello(allocator, .{
            .required = true,
            .authenticator = .{
                .ptr = &authenticator,
                .authenticate_fn = TestAuthenticator.authenticate,
            },
            .hello_binding = .{ .require_challenge = true },
        }, .{
            .peer_id = "client-a",
            .scheme = auth.hello_auth_scheme_paseto,
            .credential = "hello-token",
            .challenge = "peer-advertised-nonce",
        }),
    );
    try std.testing.expect(session.isAnonymous());

    try std.testing.expectError(
        auth.Error.Unauthorized,
        session.authenticateHello(allocator, .{
            .required = true,
            .authenticator = .{
                .ptr = &authenticator,
                .authenticate_fn = TestAuthenticator.authenticate,
            },
            .hello_binding = .{
                .context = .{
                    .audience = "qmsg://jobs.example",
                    .authority = "jobs.example:443",
                    .listener_id = "listener-a",
                    .challenge = "nonce-replayed-from-old-session",
                },
                .require_challenge = true,
            },
        }, .{
            .peer_id = "client-a",
            .scheme = auth.hello_auth_scheme_paseto,
            .credential = "hello-token",
        }),
    );
    try std.testing.expect(session.isAnonymous());
}

test "Session clears cached authorization when HELLO auth fails policy" {
    const allocator = std.testing.allocator;

    const TestAuthenticator = struct {
        fn authenticate(
            _: ?*anyopaque,
            inner_allocator: std.mem.Allocator,
            _: auth.Credential,
        ) !auth.Authorization {
            return try (auth.Authorization{
                .subject = "service:client",
                .issuer = "auth.example",
                .purpose = "wrong-purpose",
                .allowed_patterns = auth.PatternSet.init(&.{.req}),
            }).clone(inner_allocator);
        }
    };

    var session = Session{ .id = 1, .transport = .inproc };
    try session.replaceAuthorization(allocator, .{
        .subject = "service:old",
        .issuer = "auth.example",
        .allowed_patterns = auth.PatternSet.init(&.{.pair}),
    });

    const expected_purposes = [_][]const u8{auth.hello_auth_purpose};
    try std.testing.expectError(
        auth.Error.InvalidClaims,
        session.authenticateHello(allocator, .{
            .required = true,
            .authenticator = .{ .authenticate_fn = TestAuthenticator.authenticate },
            .expected_purposes = &expected_purposes,
        }, .{
            .peer_id = "client-a",
            .scheme = auth.hello_auth_scheme_paseto,
            .credential = "hello-token",
        }),
    );
    try std.testing.expect(session.isAnonymous());

    try std.testing.expectError(
        auth.Error.ChallengeRequired,
        session.authenticateHello(allocator, .{
            .required = true,
            .hello_binding = .{ .require_challenge = true },
        }, .{
            .peer_id = "client-a",
            .scheme = auth.hello_auth_scheme_paseto,
            .credential = "hello-token",
        }),
    );
    try std.testing.expect(session.isAnonymous());
}

test "Session permits anonymous HELLO only when configured" {
    const allocator = std.testing.allocator;

    var session = Session{ .id = 1, .transport = .inproc };
    try std.testing.expectError(
        auth.Error.AuthenticationRequired,
        session.authenticateHello(allocator, .{ .required = true }, .{ .peer_id = "client-a" }),
    );

    try session.authenticateHello(allocator, .{ .required = false }, .{ .peer_id = "client-a" });
    try std.testing.expect(session.isAnonymous());
}

test {
    std.testing.refAllDecls(@This());
}

// ---- cert-bound peer identity ------------------------------------

/// The digest a test session pretends the handshake authenticated.
const test_digest: [32]u8 = .{
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
    0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
    0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
};
const test_digest_hex = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20";

fn certSession(digest: ?[32]u8) Session {
    return .{ .id = 1, .transport = .quic, .peer_cert_spki = digest };
}

test "certPeerIdHex renders the digest as lowercase hex" {
    const bound = certSession(test_digest);
    const hex = bound.certPeerIdHex().?;
    try std.testing.expectEqualStrings(test_digest_hex, &hex);
    // 64 hex characters: the same rendering qmesh's PeerId.hex()
    // produces for the same certificate, so one identity keys both.
    try std.testing.expectEqual(@as(usize, 64), hex.len);

    // No certificate, no identity.
    try std.testing.expect(certSession(null).certPeerIdHex() == null);
}

test "cert binding off takes an announced id at face value" {
    const bound = certSession(test_digest);
    try bound.enforceCertBinding(.{ .cert_binding = .off }, "someone-else");
}

test "cert binding require_match accepts the certificate's own id" {
    const bound = certSession(test_digest);
    try bound.enforceCertBinding(.{ .cert_binding = .require_match }, test_digest_hex);
}

test "cert binding require_match rejects an announced lie" {
    const bound = certSession(test_digest);
    try std.testing.expectError(
        auth.Error.PeerIdentityMismatch,
        bound.enforceCertBinding(.{ .cert_binding = .require_match }, "someone-else"),
    );
    // Right length, wrong value: not a length check.
    const wrong_hex = "00" ++ test_digest_hex[2..];
    try std.testing.expectError(
        auth.Error.PeerIdentityMismatch,
        bound.enforceCertBinding(.{ .cert_binding = .require_match }, wrong_hex),
    );
    // Uppercase is a different string; the rendering is canonical.
    var upper: [64]u8 = undefined;
    _ = std.ascii.upperString(&upper, test_digest_hex);
    try std.testing.expectError(
        auth.Error.PeerIdentityMismatch,
        bound.enforceCertBinding(.{ .cert_binding = .require_match }, &upper),
    );
}

test "cert binding require_match passes sessions that carry no certificate" {
    // The mixed-deployment mode: an inproc session, or a listener
    // without client_ca_pem, is unaffected.
    const unbound = certSession(null);
    try unbound.enforceCertBinding(.{ .cert_binding = .require_match }, "anything");
}

test "cert binding required fails closed without a certificate" {
    const unbound = certSession(null);
    try std.testing.expectError(
        auth.Error.PeerIdentityRequired,
        unbound.enforceCertBinding(.{ .cert_binding = .required }, "anything"),
    );
    // With a certificate it behaves exactly like require_match.
    const bound = certSession(test_digest);
    try bound.enforceCertBinding(.{ .cert_binding = .required }, test_digest_hex);
    try std.testing.expectError(
        auth.Error.PeerIdentityMismatch,
        bound.enforceCertBinding(.{ .cert_binding = .required }, "someone-else"),
    );
}

test "cert binding treats an empty announcement as no claim" {
    // Announcing nothing is not a lie: the certificate identity
    // stands on its own.
    const bound = certSession(test_digest);
    try bound.enforceCertBinding(.{ .cert_binding = .require_match }, "");
    try bound.enforceCertBinding(.{ .cert_binding = .required }, "");
}
