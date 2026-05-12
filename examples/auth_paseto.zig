const std = @import("std");
const qmsg = @import("qmsg");
const paseto = @import("paseto");

const Auth = qmsg.PasetoAuth;

pub fn main() !void {
    var debug_allocator = std.heap.DebugAllocator(.{}){};
    defer _ = debug_allocator.deinit();
    const allocator = debug_allocator.allocator();

    const current_signing_key = try Auth.V4Public.fromSeed(&@as([32]u8, @splat(61)));
    const next_signing_key = try Auth.V4Public.fromSeed(&@as([32]u8, @splat(62)));

    const current_verifier = try Auth.V4Public.fromPublicKeyBytes(&current_signing_key.publicKeyBytes());
    const next_verifier = try Auth.V4Public.fromPublicKeyBytes(&next_signing_key.publicKeyBytes());
    const current_id = try Auth.v4PublicKeyId(current_verifier);
    const next_id = try Auth.v4PublicKeyId(next_verifier);
    const current_id_bytes = current_id.toArray();
    const next_id_bytes = next_id.toArray();

    const keys = [_]Auth.PublicKeyEntry{
        .{ .key_id = current_id, .key = current_verifier },
        .{ .key_id = next_id, .key = next_verifier },
    };
    const static_keys = Auth.StaticKeyStore{ .v4_public_keys = &keys };

    const footer = try std.fmt.allocPrint(allocator, "{{\"kid\":\"{s}\"}}", .{&next_id_bytes});
    defer allocator.free(footer);
    const claims =
        \\{
        \\  "iss":"auth.example",
        \\  "sub":"service:image-worker",
        \\  "aud":"qmsg://jobs.example",
        \\  "exp":"2026-06-01T00:00:00Z",
        \\  "jti":"hello-token-42",
        \\  "qmsg":{
        \\    "patterns":["pull","rep"],
        \\    "subjects":["jobs.image.*"],
        \\    "datagram":false,
        \\    "max_message_size":1048576
        \\  }
        \\}
    ;

    const token = try next_signing_key.sign(allocator, claims, .{ .footer = footer });
    defer allocator.free(token);

    const audiences = [_][]const u8{"qmsg://jobs.example"};
    var replay = OneShotReplayCache{};
    var authorization = try Auth.authenticateV4Public(
        allocator,
        static_keys.keyStore(),
        .{ .token = token },
        .{
            .verify = .{
                .validator = paseto.Validator{
                    .expected_issuer = "auth.example",
                    .expected_audience = &audiences,
                    .require_subject = true,
                    .require_token_identifier = true,
                    .now_override = 1_700_000_000,
                },
            },
            .replay_cache = .{
                .ptr = &replay,
                .check_and_store_fn = OneShotReplayCache.checkAndStore,
            },
        },
    );
    defer authorization.deinit(allocator);

    std.debug.print(
        "authorized {s} via rotated key {s}; old key remains accepted as {s}\n",
        .{ authorization.subject, &next_id_bytes, &current_id_bytes },
    );
}

const OneShotReplayCache = struct {
    used: bool = false,

    fn checkAndStore(ptr: ?*anyopaque, entry: qmsg.auth.ReplayEntry) !void {
        _ = entry;
        const self: *@This() = @ptrCast(@alignCast(ptr.?));
        if (self.used) return qmsg.auth.Error.ReplayedCredential;
        self.used = true;
    }
};
