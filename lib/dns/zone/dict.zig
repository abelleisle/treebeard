const std = @import("std");

// DNS
const treebeard = @import("treebeard");
const DNSMemory = treebeard.DNSMemory;
const Zone = treebeard.Zone;
const NameTree = treebeard.NameTree;

// Types
const RecordList = treebeard.RecordList;
const Record = treebeard.Record;
const Type = treebeard.Type;
const Class = treebeard.Class;
const Name = treebeard.Name;

//--------------------------------------------------
// Dictionary zone backend

const Self = @This();

// Our dictionary record storage
records: struct {
    // DNS Class
    IN: struct {
        // DNS Record Type
        A: NameTree.RecordListTree,
        AAAA: NameTree.RecordListTree,
        CNAME: NameTree.RecordTree,
    },
},

pub fn init(
    memory: *DNSMemory,
) !Self {
    return Self{
        .records = .{
            .IN = .{
                .A = try NameTree.RecordListTree.init(memory, "@", null),
                .AAAA = try NameTree.RecordListTree.init(memory, "@", null),
                .CNAME = try NameTree.RecordTree.init(memory, "@", null),
            },
        },
    };
}

pub fn deinit(self: *Self) void {
    self.records.IN.A.deinit();
    self.records.IN.AAAA.deinit();
    self.records.IN.CNAME.deinit();
}

pub fn query(self: *const Self, name: *const Name, context: *const Name, dnsType: Type, class: Class) Zone.Errors!?*const RecordList {
    switch (class) {
        .IN => switch (dnsType) {
            .A => {
                const tree = self.records.IN.A.findContext(name, context) catch {
                    return error.QueryError;
                };
                if (tree.value) |*v| return v else return null;
            },
            .AAAA => {
                const tree = self.records.IN.AAAA.findContext(name, context) catch {
                    return error.QueryError;
                };
                if (tree.value) |*v| return v else return null;
            },
            else => @panic("NOT IMPLEMENTED"),
        },
        else => @panic("NOT IMPLEMENTED"),
    }
}

//--------------------------------------------------
// Testing

const testing = std.testing;

// ==========================================================
// Dict Zone Initialization Tests
// ==========================================================

test "dict - init and deinit" {
    var pool = try DNSMemory.init();
    defer pool.deinit();

    var dict = try Self.init(&pool);
    defer dict.deinit();

    // Verify trees are initialized with root key "@"
    try testing.expectEqualStrings("@", dict.records.IN.A.key);
    try testing.expectEqualStrings("@", dict.records.IN.AAAA.key);
    try testing.expectEqualStrings("@", dict.records.IN.CNAME.key);

    // Verify no values at root
    try testing.expectEqual(null, dict.records.IN.A.value);
    try testing.expectEqual(null, dict.records.IN.AAAA.value);
    try testing.expectEqual(null, dict.records.IN.CNAME.value);
}

// ==========================================================
// RecordListTree Tests (A and AAAA records)
// ==========================================================

test "dict - add A records to tree" {
    var pool = try DNSMemory.init();
    defer pool.deinit();

    var dict = try Self.init(&pool);
    defer dict.deinit();

    // Add subdomain nodes to the A record tree
    const www = try dict.records.IN.A.addChild("www", null);
    const api = try dict.records.IN.A.addChild("api", null);

    try testing.expectEqualStrings("www", www.key);
    try testing.expectEqualStrings("api", api.key);
}

test "dict - add nested subdomains" {
    var pool = try DNSMemory.init();
    defer pool.deinit();

    var dict = try Self.init(&pool);
    defer dict.deinit();

    // Build: @ -> www -> staging
    const www = try dict.records.IN.A.addChild("www", null);
    const staging = try www.addChild("staging", null);

    try testing.expectEqualStrings("www", www.key);
    try testing.expectEqualStrings("staging", staging.key);
}

test "dict - add wildcard subdomain" {
    var pool = try DNSMemory.init();
    defer pool.deinit();

    var dict = try Self.init(&pool);
    defer dict.deinit();

    // Add wildcard node
    const wildcard = try dict.records.IN.A.addChild("*", null);
    try testing.expectEqualStrings("*", wildcard.key);
}

// ==========================================================
// RecordTree Tests (CNAME records)
// ==========================================================

test "dict - add CNAME record structure" {
    var pool = try DNSMemory.init();
    defer pool.deinit();

    var dict = try Self.init(&pool);
    defer dict.deinit();

    // Add www CNAME node
    const www = try dict.records.IN.CNAME.addChild("www", null);
    try testing.expectEqualStrings("www", www.key);
}

// ==========================================================
// findContext Tests via Query
// ==========================================================

test "dict - query returns null for empty tree" {
    var pool = try DNSMemory.init();
    defer pool.deinit();

    var dict = try Self.init(&pool);
    defer dict.deinit();

    const context = try Name.fromStr("example.com");
    const query_name = try Name.fromStr("www.example.com");

    // Query on empty tree should return null
    const result = try dict.query(&query_name, &context, .A, .IN);
    try testing.expectEqual(null, result);
}

test "dict - query with exact context match" {
    var pool = try DNSMemory.init();
    defer pool.deinit();

    var dict = try Self.init(&pool);
    defer dict.deinit();

    const context = try Name.fromStr("example.com");

    // Query for the zone apex (exact match with context)
    const result = try dict.query(&context, &context, .A, .IN);
    try testing.expectEqual(null, result);
}

test "dict - query error for non-subdomain" {
    var pool = try DNSMemory.init();
    defer pool.deinit();

    var dict = try Self.init(&pool);
    defer dict.deinit();

    const context = try Name.fromStr("example.com");
    const query_name = try Name.fromStr("www.other.com");

    // Query for a name that's not a subdomain should return QueryError
    const result = dict.query(&query_name, &context, .A, .IN);
    try testing.expectError(error.QueryError, result);
}

test "dict - query finds subdomain node" {
    var pool = try DNSMemory.init();
    defer pool.deinit();

    var dict = try Self.init(&pool);
    defer dict.deinit();

    // Add www subdomain (no value yet)
    _ = try dict.records.IN.A.addChild("www", null);

    const context = try Name.fromStr("example.com");
    const query_name = try Name.fromStr("www.example.com");

    // Should find the www node but it has no value
    const result = try dict.query(&query_name, &context, .A, .IN);
    try testing.expectEqual(null, result);
}

test "dict - query with wildcard matching" {
    var pool = try DNSMemory.init();
    defer pool.deinit();

    var dict = try Self.init(&pool);
    defer dict.deinit();

    // Add wildcard subdomain
    _ = try dict.records.IN.A.addChild("*", null);

    const context = try Name.fromStr("example.com");
    const query_name = try Name.fromStr("anything.example.com");

    // Should match the wildcard node
    const result = try dict.query(&query_name, &context, .A, .IN);
    try testing.expectEqual(null, result);
}

test "dict - query prefers exact match over wildcard" {
    var pool = try DNSMemory.init();
    defer pool.deinit();

    var dict = try Self.init(&pool);
    defer dict.deinit();

    // Add both exact and wildcard
    _ = try dict.records.IN.A.addChild("www", null);
    _ = try dict.records.IN.A.addChild("*", null);

    const context = try Name.fromStr("example.com");
    const www_query = try Name.fromStr("www.example.com");
    const other_query = try Name.fromStr("other.example.com");

    // www should find exact match
    const www_result = try dict.query(&www_query, &context, .A, .IN);
    try testing.expectEqual(null, www_result);

    // other should find wildcard
    const other_result = try dict.query(&other_query, &context, .A, .IN);
    try testing.expectEqual(null, other_result);
}

// ==========================================================
// Multiple Record Type Tests
// ==========================================================

test "dict - separate trees for A and AAAA" {
    var pool = try DNSMemory.init();
    defer pool.deinit();

    var dict = try Self.init(&pool);
    defer dict.deinit();

    // Add www to A tree only
    _ = try dict.records.IN.A.addChild("www", null);

    // Add api to AAAA tree only
    _ = try dict.records.IN.AAAA.addChild("api", null);

    // Verify trees are separate
    try testing.expect(dict.records.IN.A.children != null);
    try testing.expect(dict.records.IN.AAAA.children != null);

    // A tree should have www
    const a_children = dict.records.IN.A.children.?;
    try testing.expect(a_children.contains("www"));
    try testing.expect(!a_children.contains("api"));

    // AAAA tree should have api
    const aaaa_children = dict.records.IN.AAAA.children.?;
    try testing.expect(aaaa_children.contains("api"));
    try testing.expect(!aaaa_children.contains("www"));
}

test "dict - query correct record type" {
    var pool = try DNSMemory.init();
    defer pool.deinit();

    var dict = try Self.init(&pool);
    defer dict.deinit();

    // Add www to both A and AAAA trees
    _ = try dict.records.IN.A.addChild("www", null);
    _ = try dict.records.IN.AAAA.addChild("www", null);

    const context = try Name.fromStr("example.com");
    const query_name = try Name.fromStr("www.example.com");

    // Both should work independently
    const a_result = try dict.query(&query_name, &context, .A, .IN);
    try testing.expectEqual(null, a_result);

    const aaaa_result = try dict.query(&query_name, &context, .AAAA, .IN);
    try testing.expectEqual(null, aaaa_result);
}

// ==========================================================
// Complex Hierarchy Tests
// ==========================================================

test "dict - deep subdomain hierarchy" {
    var pool = try DNSMemory.init();
    defer pool.deinit();

    var dict = try Self.init(&pool);
    defer dict.deinit();

    // Build: @ -> www -> staging -> v1
    var www = try dict.records.IN.A.addChild("www", null);
    var staging = try www.addChild("staging", null);
    _ = try staging.addChild("v1", null);

    const context = try Name.fromStr("example.com");

    const test_cases = .{
        .{ .domain = "www.example.com", .expected_key = "www" },
        .{ .domain = "staging.www.example.com", .expected_key = "staging" },
        .{ .domain = "v1.staging.www.example.com", .expected_key = "v1" },
        // Unknown subdomain falls back to deepest match
        .{ .domain = "unknown.staging.www.example.com", .expected_key = "staging" },
    };

    inline for (test_cases) |case| {
        const query_name = try Name.fromStr(case.domain);
        const tree = try dict.records.IN.A.findContext(&query_name, &context);
        try testing.expectEqualStrings(case.expected_key, tree.key);
    }
}

test "dict - multiple branches at same level" {
    var pool = try DNSMemory.init();
    defer pool.deinit();

    var dict = try Self.init(&pool);
    defer dict.deinit();

    // Add multiple subdomains at root level
    _ = try dict.records.IN.A.addChild("www", null);
    _ = try dict.records.IN.A.addChild("api", null);
    _ = try dict.records.IN.A.addChild("mail", null);
    _ = try dict.records.IN.A.addChild("ftp", null);

    const context = try Name.fromStr("example.com");

    const subdomains = .{ "www", "api", "mail", "ftp" };

    inline for (subdomains) |sub| {
        const domain = sub ++ ".example.com";
        const query_name = try Name.fromStr(domain);
        const tree = try dict.records.IN.A.findContext(&query_name, &context);
        try testing.expectEqualStrings(sub, tree.key);
    }
}
