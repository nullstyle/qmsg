# PASETO and PASERK Integration

`qmsg` should treat PASETO and PASERK as the optional authentication,
authorization, and key-management layer around the messaging core.

They should not replace QUIC TLS and they should not become the `qmsg` message
envelope. QUIC already gives encrypted transport sessions. `qmsg` still needs a
small binary envelope for routing, pattern state, deadlines, and backpressure.
PASETO belongs at the trust boundary: who is this peer, what may it do, and
which keys should be used to verify or decrypt application credentials?

## Roles

Use PASETO for:

- peer authentication during `HELLO`;
- bearer authorization grants;
- scoped capabilities for subjects/patterns;
- signed delegation between services;
- optional per-message authorization headers for cross-session forwarding.

Use PASERK for:

- stable key identifiers (`kid`);
- serialized local/public/secret keys at rest;
- wrapped keys for operational rotation and deployment;
- password-protected keys for developer or ops tooling;
- key-discovery metadata without in-band key trust.

Do not use PASETO for:

- replacing QUIC TLS;
- hiding `qmsg` payloads that are already inside QUIC, unless the app wants
  end-to-end object security across intermediaries;
- replay protection by itself. Replay defense needs nonce/session/deadline
  checks in `qmsg` or in the application.

## Default Version and Purposes

Default to PASETO v4 for new deployments.

Recommended purposes:

- `v4.public` for peer credentials and authorization grants. Services can
  verify tokens without sharing signing keys.
- `v4.local` for confidential bootstrap material when every verifier is also
  allowed to decrypt.

Avoid supporting every historical version in the first `qmsg` auth package.
Make the initial implementation intentionally small:

```zig
pub const PasetoOptions = struct {
    allowed_versions: []const PasetoVersion = &.{ .v4 },
    allowed_purposes: []const PasetoPurpose = &.{ .public },
};
```

`qmsg` should use
[`paseto-zig` release `0.2.0`](https://github.com/nullstyle/paseto-zig/releases/tag/0.2.0)
for the concrete auth kit. The package is imported as `paseto`; qmsg's core
auth interfaces stay optional so inproc tests and unauthenticated deployments
do not need to pay for token verification.

Relevant dependency surface:

- `paseto.v4.Public.generate`, `fromPublicKeyBytes`, `fromSeed`,
  `fromSecretKeyBytes`, `sign`, `verify`, `verifyToken`, `pid`, `sid`;
- `paseto.v4.Local.generate`, `fromBytes`, `encrypt`, `decrypt`,
  `decryptToken`, `lid`;
- `paseto.token.parse` / `paseto.token.serialize` for header/footer inspection;
- `paseto.Validator` for registered claim validation;
- `paseto.paserk.keys.parse`, `paseto.paserk.id.*`, `paseto.paserk.pie`,
  `paseto.paserk.pke`, and `paseto.paserk.pbkw` for key operations.

`paseto-zig` already implements v3/v4 local/public and the registered PASERK
operations. `qmsg` should still start with v4.public session credentials and
use the rest of the dependency as operational tooling until a specific runtime
need appears.

## HELLO Authentication

`qmsg/1` already has a `HELLO` control frame. Add optional auth fields:

```text
HELLO {
  version
  peer_id
  supported_patterns
  max_message_size
  datagram_enabled
  auth:
    scheme = paseto
    token = bytes
    key_id_hint = optional PASERK ID string
}
```

Server validation flow:

1. Bound token length before parsing (`AuthConfig.max_token_bytes`).
2. Parse the PASETO with `paseto.token.parse` and reject unsupported
   version/purpose before expensive work.
3. Extract the PASERK key ID string from authenticated-looking metadata:
   preferably the token footer (`{"kid":"k4.pid..."}` or a raw `k4.pid...`
   value), otherwise the HELLO `key_id_hint`. Treat both as untrusted lookup
   hints.
4. Resolve the verification/decryption key from a trusted key store.
5. Verify/decrypt the PASETO using the qmsg implicit assertion bytes.
6. Validate registered claims with `paseto.Validator`: issuer, audience,
   subject, expiry, not-before, issued-at, and token id.
7. Parse and validate the custom `qmsg` claim block.
8. Run the application `onAuthenticate` hook.
9. Promote the connection to an authenticated `Session`.

The session should not dispatch application messages until authentication
succeeds, unless the listener explicitly allows anonymous sessions.

## Context Binding

PASETO v3/v4 support implicit assertions. `qmsg` should use them to bind a
token to the protocol context without putting that context inside the token
payload.

Recommended implicit assertion input:

```text
"qmsg/1" ||
listener identity ||
server authority ||
required pattern set ||
optional server nonce/challenge
```

The exact byte format should be fixed before implementation. The purpose is to
stop a token minted for one protocol, listener, or audience from being replayed
as a valid `qmsg` credential somewhere else.

For deployments that cannot use implicit assertions, put protocol and audience
constraints in claims and require strict claim validation.

## Claims

Use a compact JSON payload initially. A binary claims codec can come later.

Suggested claims:

```json
{
  "iss": "auth.example",
  "sub": "service:image-worker-17",
  "aud": "qmsg://jobs.example",
  "exp": "2026-06-01T00:00:00Z",
  "nbf": "2026-05-11T00:00:00Z",
  "jti": "unique-token-id",
  "qmsg": {
    "patterns": ["rep", "pull"],
    "subjects": ["jobs.image.*"],
    "datagram": false,
    "max_message_size": 1048576
  }
}
```

`qmsg` should map validated claims into a session authorization object:

```zig
pub const Authorization = struct {
    subject: []const u8,
    issuer: []const u8,
    token_id: ?[]const u8,
    allowed_patterns: PatternSet,
    allowed_subjects: SubjectPolicy,
    datagram_allowed: bool,
    max_message_size: ?usize,
    expires_at_unix_ms: ?i64,
};
```

Handlers should see authorization as session state, not parse tokens directly
in every message handler.

`src/auth.zig` owns the qmsg claim parser. `Authorization.fromClaimsJson`
requires `iss`, `sub`, and a `qmsg` block by default, maps `jti` into
`token_id`, maps `exp` into `expires_at_unix_ms`, and parses:

- `qmsg.patterns`: non-empty list of `pair`, `req`, `rep`, `pub`, `sub`,
  `push`, or `pull`;
- `qmsg.subjects`: subject filters, `">"` for allow-all, or an empty list for
  deny-all;
- `qmsg.datagram`: optional boolean;
- `qmsg.max_message_size`: optional byte limit.

## PASERK Key IDs

PASERK key IDs are the right way to identify keys in token metadata.

Recommended policy:

- Permit `lid`, `pid`, and `sid` as key identifiers.
- Permit wrapped-key forms only where the implementation explicitly unwraps
  them through a trusted configured wrapping key.
- Reject raw `local`, `public`, and `secret` PASERKs in untrusted token
  metadata or `HELLO`.
- Require PASERK version to match PASETO token version.
- Represent key IDs in concrete paseto integration code as the typed
  `paseto.paserk.Id` value from `paseto-zig` `0.2.0`. Core qmsg session state
  may still carry borrowed or owned byte strings for issuer, subject, and token
  IDs, but key lookup should not downgrade PASERK IDs to arbitrary strings once
  the paseto dependency is available.

Key lookup should be fail-closed:

```zig
pub const KeyStore = struct {
    pub fn findV4Public(self: *KeyStore, kid: []const u8) ?paseto.v4.Public;
    pub fn findV4Local(self: *KeyStore, kid: []const u8) ?paseto.v4.Local;
};
```

Never accept a public key supplied by the peer as the authority for verifying
that peer's own token. A peer-supplied key can be recorded as data, but trust
must come from local configuration, a trusted key server, or a previously
verified chain.

## Key Rotation

PASERK gives `qmsg` a practical key rotation story:

- tokens carry a PASERK ID in footer/metadata;
- servers keep an active key set plus a retired verification window;
- signers publish new public keys before issuing tokens with the new `kid`;
- local/shared keys can be deployed as PASERK-wrapped values;
- ops tooling can inspect key IDs without exposing key material.

Suggested config:

```zig
pub const AuthConfig = struct {
    paseto: PasetoOptions,
    keystore: *KeyStore,
    required: bool = true,
    allow_anonymous_subjects: []const []const u8 = &.{},
    max_token_bytes: usize = 4096,
    max_clock_skew_ms: u64 = 30_000,
    replay_cache: ?*ReplayCache = null,
};
```

Public-key stores should keep verifier-only `paseto.v4.Public` values created
with `paseto.v4.Public.fromPublicKeyBytes`. Signing keys created with
`fromSeed`, `fromSecretKeyBytes`, or `generate` belong in the token issuer, not
in ordinary qmsg listener processes.

See `examples/auth_paseto.zig` for a compact rotation example. It keeps both
the current and next verifier keys in a static store, signs a token with the
next key, carries the next key's PASERK ID in the footer, and verifies through
the same transport-independent authenticator used by sessions.

## Replay Defense

PASETO verifies authenticity, not freshness by itself.

`qmsg` should offer replay controls:

- require short token lifetime for HELLO credentials;
- validate `nbf` / `exp`;
- optionally require `jti`;
- optionally keep a replay cache per issuer/audience;
- optionally add a server challenge to the implicit assertion;
- close or downgrade duplicate-token sessions according to policy.

For service-to-service deployments, the clean model is:

1. client opens QUIC connection;
2. server sends or exposes a challenge in pre-auth control state;
3. client presents PASETO bound to `qmsg/1` and the challenge;
4. server verifies and consumes the challenge.

The MVP can skip challenge-response and document that deployments should use
short-lived tokens plus TLS server authentication. The API should leave room for
challenge-bound tokens.

The concrete PASETO helper accepts an optional `auth.ReplayCache`. When present,
`authenticateV4Public` requires `jti`, parses qmsg claims into an
`Authorization`, then calls `checkAndStore` with `{ issuer, token_id,
expires_at_unix_ms }`. The cache interface stays transport-independent so
listeners can back it with memory, a process-wide store, or application state.

## Per-Message Authorization

Default: authenticate once per session and authorize every message from cached
session policy.

Optional: allow a message header to carry a PASETO capability:

```text
MESSAGE.headers:
  authorization: "paseto v4.public...."
```

Use this only when messages may cross trust boundaries after the original QUIC
session, such as:

- forwarded jobs;
- brokered topologies;
- store-and-forward queues;
- object-level delegation.

Per-message PASETO validation must be bounded and cacheable. It should not be
required on the hot path for ordinary direct sessions.

## API Sketch

Application facade:

```zig
var app = try qmsg.App.init(allocator, .{
    .auth = .{
        .scheme = .paseto,
        .keystore = &keys,
        .required = true,
    },
});

app.onAuthenticate(authenticate);
app.rep("user.get", getUser);
```

Lower-level socket:

```zig
var sock = try qmsg.Socket(.req).init(allocator, .{
    .auth = .{
        .token_provider = .{ .paseto = makeToken },
    },
});
```

Handler:

```zig
fn getUser(ctx: *qmsg.Context, msg: qmsg.Message) !void {
    try ctx.requireSubject("user.get");
    try ctx.requirePattern(.rep);
    // Authorization has already been validated and cached on session.
}
```

## Package Boundary

Use `paseto-zig` as the crypto package:

```text
paseto-zig
  PASETO encode/decode/verify/decrypt
  PASERK parse/serialize/id/wrap helpers
  official test vectors

qmsg
  auth integration
  custom qmsg claim validation policy
  key store interface
  replay cache interface
  session authorization
```

This keeps `qmsg` from becoming a cryptography implementation. `paseto-zig`
already has the lower-level operations qmsg needs, including registered-claim
validation. `qmsg` still owns qmsg-specific authorization policy: parsing the
custom `qmsg` claim block, mapping it into `Authorization`, enforcing subjects
and patterns, and deciding replay/session policy.

### Dependency Wiring

Use the `paseto-zig` `0.2.0` release when wiring the optional auth-kit
dependency:

```zig
.dependencies = .{
    .paseto = .{
        .url = "https://github.com/nullstyle/paseto-zig/archive/refs/tags/0.2.0.tar.gz",
        .hash = "...", // fill with the hash from `zig fetch`
    },
},
```

During local development, use the sibling checkout:

```zig
.dependencies = .{
    .paseto = .{
        .path = "../paseto-zig",
    },
},
```

and import it in `build.zig`:

```zig
const paseto = b.dependency("paseto", .{ .target = target, .optimize = optimize });
exe.root_module.addImport("paseto", paseto.module("paseto"));
```

### Validation Code Shape

The first qmsg authenticator should look roughly like this:

```zig
var tok = try paseto.token.parse(allocator, credential);
defer tok.deinit();

if (tok.version != .v4 or tok.purpose != .public) return error.UnsupportedCredential;

const kid = try extractKidFromFooterOrHello(tok.footer, hello.key_id_hint);
const verifier = keystore.findV4Public(kid) orelse return error.UnknownKey;

const claims_json = try verifier.verifyToken(allocator, tok, implicit_assertion);
defer allocator.free(claims_json);

try paseto.Validator{
    .verify_exp = true,
    .verify_nbf = true,
    .verify_iat = true,
    .expected_issuer = config.expected_issuer,
    .expected_audience = config.expected_audiences,
    .require_issuer = true,
    .require_audience = true,
    .require_subject = true,
    .require_token_identifier = config.replay_cache != null,
}.validate(claims_json, allocator);

const authz = try parseQmsgClaims(allocator, claims_json);
```

`extractKidFromFooterOrHello` must treat both sources as untrusted lookup hints.
The footer becomes authenticated only when `verifyToken` succeeds; if an
attacker tampers with the footer to steer lookup to the wrong trusted key, token
verification fails.

Current concrete API:

```zig
var authorization = try qmsg.PasetoAuth.authenticateV4Public(
    allocator,
    key_store,
    .{ .token = token, .implicit_assertion = assertion },
    .{
        .verify = .{ .validator = validator },
        .replay_cache = replay_cache,
    },
);
defer authorization.deinit(allocator);
```

## Implementation Phases

### Phase A: Interfaces First

- Define `AuthConfig`, `Authenticator`, `Authorization`, `KeyStore`.
- Add auth fields to `HELLO`.
- Add anonymous vs authenticated session states.
- Add handler helpers: `requirePattern`, `requireSubject`, `hasScope`.

### Phase B: PASETO v4.public

- Wire `paseto-zig` `0.2.0` as the optional auth-kit dependency.
- Verify v4 public tokens with `paseto.v4.Public.verifyToken`.
- Support typed PASERK `pid` lookup with `paseto.paserk.Id`.
- Validate `iss`, `sub`, `aud`, `exp`, `nbf`, `iat`, `jti` with
  `paseto.Validator`.
- Parse and enforce the custom `qmsg` claim block in qmsg.
- Cache authorization on session.
- Add qmsg auth tests that use `paseto-zig`; rely on `paseto-zig` for official
  PASETO/PASERK vector coverage.

### Phase C: PASERK Operations

- Use `paseto-zig` to generate and parse PASERK IDs / key records.
- Add wrapped key loading for deployment config using `paseto.paserk.pie`,
  `paseto.paserk.pke`, and `paseto.paserk.pbkw`.
- Add key rotation examples.
- Add fail-closed tests for unknown or mismatched key IDs.

### Phase D: v4.local and Advanced Modes

- Support v4 local tokens if deployments need confidential auth payloads.
- Add replay cache hooks.
- Add challenge-bound auth.
- Add per-message capability token validation and cache.

## Open Questions

- Should `qmsg` require authentication by default for network listeners?
- Should auth failure use a qmsg `SESSION_ERROR` frame or close QUIC directly?
- How much JSON claim validation belongs in core versus an optional auth kit?
- Do we want challenge-bound authentication in the MVP or phase it in later?
- Should per-message capability tokens be standardized now or left as an app
  convention until brokered topologies exist?
