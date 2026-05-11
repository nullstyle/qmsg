const std = @import("std");

pub fn validate(subject: []const u8) !void {
    if (!isValid(subject)) return error.InvalidSubject;
}

pub fn isValid(subject: []const u8) bool {
    if (subject.len == 0) return false;

    var previous_was_dot = true;
    for (subject) |byte| {
        if (byte == '.') {
            if (previous_was_dot) return false;
            previous_was_dot = true;
        } else {
            previous_was_dot = false;
        }
    }

    return !previous_was_dot;
}

pub const Filter = struct {
    allocator: std.mem.Allocator,
    text: []u8,
    segment_count: usize,
    literal_segments: usize,
    wildcard_segments: usize,
    has_glob: bool,
    exact: bool,

    pub fn init(allocator: std.mem.Allocator, filter: []const u8) !Filter {
        const parsed = try parseFilter(filter);
        const text = try allocator.dupe(u8, filter);
        return .{
            .allocator = allocator,
            .text = text,
            .segment_count = parsed.segment_count,
            .literal_segments = parsed.literal_segments,
            .wildcard_segments = parsed.wildcard_segments,
            .has_glob = parsed.has_glob,
            .exact = parsed.exact,
        };
    }

    pub fn clone(self: Filter, allocator: std.mem.Allocator) !Filter {
        return init(allocator, self.text);
    }

    pub fn deinit(self: *Filter) void {
        self.allocator.free(self.text);
        self.* = undefined;
    }

    pub fn matches(self: Filter, subject: []const u8) !bool {
        try validate(subject);
        return self.matchesValid(subject);
    }

    fn matchesValid(self: Filter, subject: []const u8) bool {
        var filter_segments = std.mem.splitScalar(u8, self.text, '.');
        var subject_segments = std.mem.splitScalar(u8, subject, '.');

        while (filter_segments.next()) |filter_segment| {
            if (std.mem.eql(u8, filter_segment, ">")) return true;

            const subject_segment = subject_segments.next() orelse return false;
            if (std.mem.eql(u8, filter_segment, "*")) continue;
            if (!std.mem.eql(u8, filter_segment, subject_segment)) return false;
        }

        return subject_segments.next() == null;
    }
};

pub fn Router(comptime Value: type) type {
    return struct {
        const Self = @This();

        allocator: std.mem.Allocator,
        entries: std.ArrayList(Entry),
        next_order: usize = 0,

        pub const Entry = struct {
            filter: Filter,
            value: Value,
            order: usize,
        };

        pub const Match = struct {
            filter: *const Filter,
            value: *const Value,
            order: usize,
        };

        pub fn init(allocator: std.mem.Allocator) Self {
            return .{
                .allocator = allocator,
                .entries = .empty,
            };
        }

        pub fn deinit(self: *Self) void {
            for (self.entries.items) |*entry| {
                entry.filter.deinit();
            }
            self.entries.deinit(self.allocator);
            self.* = undefined;
        }

        pub fn add(self: *Self, filter: []const u8, value: Value) !void {
            var parsed_filter = try Filter.init(self.allocator, filter);
            errdefer parsed_filter.deinit();

            try self.entries.append(self.allocator, .{
                .filter = parsed_filter,
                .value = value,
                .order = self.next_order,
            });
            self.next_order += 1;
        }

        pub fn len(self: Self) usize {
            return self.entries.items.len;
        }

        pub fn route(self: Self, subject: []const u8) !?Match {
            try validate(subject);

            var best_index: ?usize = null;
            for (self.entries.items, 0..) |entry, index| {
                if (!entry.filter.matchesValid(subject)) continue;

                if (best_index) |best| {
                    if (isHigherPriority(entry, self.entries.items[best])) {
                        best_index = index;
                    }
                } else {
                    best_index = index;
                }
            }

            const index = best_index orelse return null;
            const entry = &self.entries.items[index];
            return .{
                .filter = &entry.filter,
                .value = &entry.value,
                .order = entry.order,
            };
        }

        fn isHigherPriority(candidate: Entry, incumbent: Entry) bool {
            if (candidate.filter.exact != incumbent.filter.exact) {
                return candidate.filter.exact;
            }
            if (candidate.filter.segment_count != incumbent.filter.segment_count) {
                return candidate.filter.segment_count > incumbent.filter.segment_count;
            }
            if (candidate.filter.literal_segments != incumbent.filter.literal_segments) {
                return candidate.filter.literal_segments > incumbent.filter.literal_segments;
            }
            if (candidate.filter.has_glob != incumbent.filter.has_glob) {
                return !candidate.filter.has_glob;
            }
            return candidate.order < incumbent.order;
        }
    };
}

const ParsedFilter = struct {
    segment_count: usize,
    literal_segments: usize,
    wildcard_segments: usize,
    has_glob: bool,
    exact: bool,
};

fn parseFilter(filter: []const u8) !ParsedFilter {
    if (filter.len == 0) return error.InvalidSubjectFilter;
    if (filter[0] == '.' or filter[filter.len - 1] == '.') return error.InvalidSubjectFilter;

    var segment_count: usize = 0;
    var literal_segments: usize = 0;
    var wildcard_segments: usize = 0;
    var has_glob = false;

    var start: usize = 0;
    while (start < filter.len) {
        var end = start;
        while (end < filter.len and filter[end] != '.') : (end += 1) {}

        const segment = filter[start..end];
        if (segment.len == 0) return error.InvalidSubjectFilter;

        const is_last = end == filter.len;
        if (std.mem.eql(u8, segment, ">")) {
            if (!is_last) return error.InvalidSubjectFilter;
            has_glob = true;
        } else if (std.mem.eql(u8, segment, "*")) {
            wildcard_segments += 1;
        } else {
            if (std.mem.indexOfScalar(u8, segment, '*') != null) return error.InvalidSubjectFilter;
            if (std.mem.indexOfScalar(u8, segment, '>') != null) return error.InvalidSubjectFilter;
            literal_segments += 1;
        }

        segment_count += 1;
        if (is_last) break;
        start = end + 1;
    }

    return .{
        .segment_count = segment_count,
        .literal_segments = literal_segments,
        .wildcard_segments = wildcard_segments,
        .has_glob = has_glob,
        .exact = !has_glob and wildcard_segments == 0,
    };
}

test "subject validation rejects empty segments" {
    try validate("user.get");
    try validate("presence.user.123");

    try std.testing.expectError(error.InvalidSubject, validate(""));
    try std.testing.expectError(error.InvalidSubject, validate(".user"));
    try std.testing.expectError(error.InvalidSubject, validate("user."));
    try std.testing.expectError(error.InvalidSubject, validate("user..get"));
}

test "filter validation and matching" {
    const allocator = std.testing.allocator;

    var exact = try Filter.init(allocator, "user.get");
    defer exact.deinit();
    try std.testing.expect(try exact.matches("user.get"));
    try std.testing.expect(!try exact.matches("user.put"));

    var star = try Filter.init(allocator, "metrics.*");
    defer star.deinit();
    try std.testing.expect(try star.matches("metrics.cpu"));
    try std.testing.expect(!try star.matches("metrics.host.cpu"));

    var glob = try Filter.init(allocator, "presence.>");
    defer glob.deinit();
    try std.testing.expect(try glob.matches("presence"));
    try std.testing.expect(try glob.matches("presence.user.123"));
    try std.testing.expect(!try glob.matches("metrics.cpu"));
}

test "filter rejects malformed wildcard placement" {
    const allocator = std.testing.allocator;

    try std.testing.expectError(error.InvalidSubjectFilter, Filter.init(allocator, ""));
    try std.testing.expectError(error.InvalidSubjectFilter, Filter.init(allocator, "metrics."));
    try std.testing.expectError(error.InvalidSubjectFilter, Filter.init(allocator, "metrics..cpu"));
    try std.testing.expectError(error.InvalidSubjectFilter, Filter.init(allocator, "metrics.>.cpu"));
    try std.testing.expectError(error.InvalidSubjectFilter, Filter.init(allocator, "metrics.cpu*"));
    try std.testing.expectError(error.InvalidSubjectFilter, Filter.init(allocator, "metrics.>>"));
}

test "router priority is exact then longest then registration order" {
    const allocator = std.testing.allocator;

    var router = Router([]const u8).init(allocator);
    defer router.deinit();

    try router.add("metrics.>", "glob");
    try router.add("metrics.*", "star-first");
    try router.add("metrics.*", "star-second");
    try router.add("metrics.cpu", "exact");
    try router.add("metrics.host.*", "longer");

    var routed = (try router.route("metrics.cpu")).?;
    try std.testing.expectEqualStrings("exact", routed.value.*);

    routed = (try router.route("metrics.mem")).?;
    try std.testing.expectEqualStrings("star-first", routed.value.*);

    routed = (try router.route("metrics.host.cpu")).?;
    try std.testing.expectEqualStrings("longer", routed.value.*);

    try std.testing.expect((try router.route("jobs.image")) == null);
}

test "router validates subject before matching" {
    const allocator = std.testing.allocator;

    var router = Router(void).init(allocator);
    defer router.deinit();

    try router.add(">", {});
    try std.testing.expectError(error.InvalidSubject, router.route("bad..subject"));
}
