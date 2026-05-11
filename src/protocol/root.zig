const std = @import("std");

pub const Pattern = enum(u8) {
    pair,
    req,
    rep,
    @"pub",
    sub,
    push,
    pull,

    pub fn canSendTo(self: Pattern, peer: Pattern) bool {
        return switch (self) {
            .pair => peer == .pair,
            .req => peer == .rep,
            .rep => peer == .req,
            .@"pub" => peer == .sub,
            .sub => peer == .@"pub",
            .push => peer == .pull,
            .pull => peer == .push,
        };
    }

    pub fn expectsReplies(self: Pattern) bool {
        return self == .req;
    }
};

pub const Delivery = enum {
    reliable,
    unreliable,
};

pub const Operation = enum {
    message,
    request,
    reply,
    publish,
    subscribe,
    unsubscribe,
    credit,
};

pub const RequestMeta = struct {
    id: u64,
    deadline_ms: ?u64 = null,
    subject: []const u8,
};

test "patterns only connect to their counterpart roles" {
    try std.testing.expect(Pattern.pair.canSendTo(.pair));
    try std.testing.expect(Pattern.req.canSendTo(.rep));
    try std.testing.expect(Pattern.rep.canSendTo(.req));
    try std.testing.expect(Pattern.@"pub".canSendTo(.sub));
    try std.testing.expect(Pattern.push.canSendTo(.pull));

    try std.testing.expect(!Pattern.@"pub".canSendTo(.pull));
    try std.testing.expect(!Pattern.req.canSendTo(.sub));
}

test {
    std.testing.refAllDecls(@This());
}
