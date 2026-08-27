//! The embedder contract for a socketless embedded qmsg Node.
//!
//! Everything an embedder owns and drives is here:
//!
//!   - the loop and the clock — `tick(now_us)` advances node time
//!     (request deadlines are evaluated against it); nothing in qmsg
//!     sleeps, spawns threads, or opens sockets on the inproc surface;
//!   - the event drain — `poll` pumps node-owned inproc state into
//!     the event queue and hands events out; every event owns memory,
//!     so the embedder deinits each one after handling it;
//!   - the allocator — one allocator for the node and everything it
//!     queues; event payloads come back to that allocator on deinit;
//!   - backpressure — send-path pressure (`requestInproc`,
//!     `publishInproc`, `replyInproc`) is synchronous and observable,
//!     and `stats()` renders counters as plain fields.
//!
//! The "peers" in this example are plain qmsg sockets in the same
//! process standing in for foreign services over the `InprocNetwork`
//! — from the node's point of view they are just external parties.
//! This is the loop mruby-quic's bridge mimics: route each event by
//! pattern, deliver into per-actor queues, never let a handler fault
//! escape the loop.

const std = @import("std");
const qmsg = @import("qmsg");

const Node = qmsg.node.Node;
const Event = qmsg.node.Event;

const clock_step_us = 1_000; // 1 ms per loop iteration
const max_iterations = 200;

const Outcome = enum(u8) {
    served_request = 0,
    received_reply = 1,
    deadline_failed = 2,
    matched_delivery = 3,
    subscriber_received = 4,

    fn mask(self: Outcome) u8 {
        return @as(u8, 1) << @as(std.math.Log2Int(u8), @intCast(@backingInt(self)));
    }
};

fn markDone(done: *u8, outcome: Outcome) void {
    done.* |= outcome.mask();
}

fn isDone(done: u8, outcome: Outcome) bool {
    return done & outcome.mask() != 0;
}

fn allDone(done: u8) bool {
    return done == @as(u8, 0b11111);
}

pub fn main(init: std.process.Init) !void {
    const allocator = init.gpa;

    var network = qmsg.InprocNetwork.init(allocator);
    defer network.deinit();

    var node = try Node.init(allocator, .{});
    defer node.deinit();

    // Serve: requests to "svc" arrive as `request` events.
    _ = try node.listenInprocRep(&network, "svc", .{});

    // Publish: subscribers dial "feed" and receive `publishInproc` fanout.
    const feed_id = try node.listenInprocPub(&network, "feed", .{});

    // The external parties: a requesting client, a serving peer that
    // answers "echo.*" but never "time.*" (the deadline case), a
    // publisher, and a subscriber for our feed. Inproc dials need
    // their peer bound first, so the binds happen above/below.
    var peer_req = try qmsg.Socket(.req).init(allocator, .{});
    defer peer_req.deinit();
    try peer_req.dialInproc(&network, "svc");

    var peer_rep = try qmsg.Socket(.rep).init(allocator, .{});
    defer peer_rep.deinit();
    try peer_rep.listenInproc(&network, "peers");

    var peer_pub = try qmsg.Socket(.@"pub").init(allocator, .{});
    defer peer_pub.deinit();
    try peer_pub.listenInproc(&network, "events");

    var peer_sub = try qmsg.Socket(.sub).init(allocator, .{});
    defer peer_sub.deinit();
    try peer_sub.dialInproc(&network, "feed");
    try peer_sub.subscribe("presence.>");

    // Subscribe: deliveries matching our filters arrive as `delivery`
    // events carrying the filter that matched. Filters may be added
    // before or after the dial — they replay at connect time.
    try node.subscribeInproc("metrics.*");
    try node.dialInprocSub(&network, "events");

    // Request: outbound req transport to a served peer; replies (or
    // classified failures) arrive as events keyed by correlation id.
    const dial_id = try node.dialInprocReq(&network, "peers", .{});

    // Seed the loop: one inbound request, one matching and one
    // non-matching publication, two outbound requests (one answered,
    // one left to die past its deadline), one publication of our own.
    const asked_id = try peer_req.sendRequest(.{
        .subject = "user.get",
        .body = "42",
        .deadline_ms = 1_000,
    });
    try peer_pub.publish(.{ .subject = "metrics.cpu", .body = "91" });
    try peer_pub.publish(.{ .subject = "jobs.noise", .body = "filtered" });

    try node.tick(0);
    const echo_id = try node.requestInproc(dial_id, .{
        .subject = "echo.hi",
        .body = "hi",
        .deadline_ms = 1_000,
    });
    const timeout_id = try node.requestInproc(dial_id, .{
        .subject = "time.now",
        .body = "",
        .deadline_ms = 25,
    });
    try node.publishInproc(feed_id, .{ .subject = "presence.ada", .body = "online" });

    var done: u8 = 0;
    var now_us: u64 = 0;
    var iteration: usize = 0;
    while (iteration < max_iterations) : (iteration += 1) {
        now_us += clock_step_us;
        try node.tick(now_us);
        drivePeers(allocator, &peer_rep, &peer_req, &peer_sub, &done);

        var events: [16]Event = undefined;
        const count = try node.poll(&events);
        for (events[0..count]) |*event| {
            defer event.deinit();
            try handleEvent(&node, dial_id, event, asked_id, echo_id, timeout_id, &done);
        }

        if (allDone(done)) break;
    }

    if (!allDone(done)) return error.EmbeddedLoopIncomplete;

    const stats = node.stats();
    std.debug.print(
        "embedded node stats: sent={d} recv={d} dropped={d} queue_high_water={d} events_dropped={d}\n",
        .{ stats.sent, stats.recv, stats.dropped, stats.queue_high_water, stats.events_dropped },
    );
}

/// The embedder's event router: every poll outcome renders from this
/// switch alone — requests (with correlation id + deadline), replies
/// and their classified failures, deliveries with the matched filter.
fn handleEvent(
    node: *Node,
    dial_id: qmsg.InprocDialId,
    event: *Event,
    asked_id: qmsg.MessageId,
    echo_id: qmsg.MessageId,
    timeout_id: qmsg.MessageId,
    done: *u8,
) !void {
    switch (event.*) {
        .request => |*ev| {
            std.debug.print("served {s} ({s}) id={d}\n", .{ ev.msg.subject, ev.msg.body, ev.msg.id });
            try node.replyInproc(ev, .{ .subject = "", .body = "user-42" });
            markDone(done, .served_request);
        },
        .reply => |*ev| {
            if (ev.msg.flags.err) {
                std.debug.print("reply id={d} error: {s}\n", .{ ev.msg.id, ev.msg.body });
            } else {
                std.debug.print("reply id={d} ({s})\n", .{ ev.msg.id, ev.msg.body });
            }
            if (ev.dial_id == dial_id and ev.msg.id == echo_id) markDone(done, .received_reply);
        },
        .request_failed => |ev| {
            std.debug.print("request id={d} failed: {s}\n", .{ ev.id, @tagName(ev.failure) });
            if (ev.dial_id == dial_id and ev.id == timeout_id) markDone(done, .deadline_failed);
        },
        .delivery => |*ev| {
            std.debug.print("delivery {s} ({s}) via filter {s}\n", .{ ev.msg.subject, ev.msg.body, ev.filter });
            markDone(done, .matched_delivery);
        },
        .message_dropped => |ev| {
            std.debug.print("message dropped: {d} bytes\n", .{ev.bytes});
        },
        .connected, .closed => {},
    }
    _ = asked_id;
}

/// One unit of progress per external peer per iteration, so the loop
/// interleaves realistically instead of resolving everything at once.
fn drivePeers(
    allocator: std.mem.Allocator,
    peer_rep: *qmsg.Socket(.rep),
    peer_req: *qmsg.Socket(.req),
    peer_sub: *qmsg.Socket(.sub),
    done: *u8,
) void {
    _ = allocator;

    if (peer_req.tryRecv()) |maybe| {
        if (maybe) |received| {
            var reply = received;
            defer reply.deinit();
            std.debug.print("peer got reply id={d} ({s})\n", .{ reply.id, reply.body });
        }
    } else |_| {}

    if (peer_rep.tryRecv()) |maybe| {
        if (maybe) |received| {
            var request = received;
            defer request.deinit();
            // "time.*" is deliberately never answered: its deadline
            // expiry is the `request_failed` demonstration.
            if (std.mem.startsWith(u8, request.subject(), "echo.")) {
                peer_rep.reply(request, .{ .subject = "echo.ok", .body = "hi yourself" }) catch {};
            }
        }
    } else |_| {}

    if (peer_sub.tryRecv()) |maybe| {
        if (maybe) |received| {
            var delivery = received;
            defer delivery.deinit();
            std.debug.print("subscriber got {s} ({s})\n", .{ delivery.subject, delivery.body });
            markDone(done, .subscriber_received);
        }
    } else |_| {}
}
