const std = @import("std");

// DNS
const treebeard = @import("treebeard");
const DNSMemory = treebeard.DNSMemory;
const Name = treebeard.Name;
const Record = treebeard.Record;
const RecordList = treebeard.RecordList;

//--------------------------------------------------
// Record Tree
pub const RecordTree = Tree(Record, .{ .deinit = recordDeinit });

fn recordDeinit(ctx: *anyopaque, memory: *DNSMemory) void {
    const self: *Record = @ptrCast(@alignCast(ctx));
    _ = memory;

    self.deinit();
}

//--------------------------------------------------
// Request List Tree
pub const RecordListTree = Tree(RecordList, .{ .deinit = recordListDeinit });

fn recordListDeinit(ctx: *anyopaque, memory: *DNSMemory) void {
    const self: *RecordList = @ptrCast(@alignCast(ctx));

    for (self.items) |*record| record.deinit();
    self.deinit(memory.alloc());
}

//--------------------------------------------------
// Tree

/// Tree virtual table.
/// Used for dynamic dispatching based on the custom tree type
const VTable = struct {
    deinit: ?*const fn (*anyopaque, memory: *DNSMemory) void,
};

const TreeKey = union(enum) {
    str: []u8,
    namespace: Name,
    root,
};

/// Name Tree. Used to create a DNS name tree broken down
/// by labels. This is used very heavily in DNS systems.
fn Tree(comptime T: type, vTable: VTable) type {
    return struct {
        const NT = @This();
        const vtable: VTable = vTable;

        key: TreeKey,
        value: ?T,
        children: ?std.StringHashMap(NT),

        freed: bool,

        memory: *DNSMemory,

        /// Creates a root-name tree.
        ///
        /// The parent node has no children and points to the root domain.
        ///
        /// Note: Initial name trees have no children.
        pub fn init(memory: *DNSMemory) NT {
            return NT{
                .key = .root,
                .value = null,
                .children = null,
                .memory = memory,
                .freed = false,
            };
        }

        /// Creates a namespace tree.
        ///
        /// The parent node has no children and points to the "@" key,
        /// or the namespace of the provided domain.
        ///
        /// Note: Initial name trees have no children.
        pub fn namespace(memory: *DNSMemory, name: *const Name) NT {
            return NT{
                .key = .{ .namespace = name.* },
                .value = null,
                .children = null,
                .memory = memory,
                .freed = false,
            };
        }

        /// Creates a child tree.
        ///
        /// key: Name of the node. This value will be duped, so this can be
        ///      a temporary value. This should refer to a single name label
        ///      generally. For root domains, a dot should be used.
        /// value: Optional value to apply to the node.
        ///
        /// Note: Initial name trees have no children.
        fn child(memory: *DNSMemory, key: []const u8, value: ?T) !NT {
            return NT{
                .key = .{ .str = try memory.alloc().dupe(u8, key) },
                .value = value,
                .children = null,
                .memory = memory,
                .freed = false,
            };
        }

        /// Adds a key/value pair as the child of this entry.
        pub fn addChild(self: *NT, key: []const u8, value: ?T) !*NT {
            // We need to add a child? Let's make sure we have a children
            // tree.
            if (self.children == null) {
                self.children = std.StringHashMap(NT).init(self.memory.alloc());
            }

            // Important: reference the children so we don't clone
            // and modify our own hashmap
            const children = &(self.children orelse unreachable);

            // Try to put an entry in for our current child
            var gop = try children.getOrPut(key);

            // If we found an existing entry for the same key
            if (gop.found_existing) {
                // The entry already has a value assigned
                if (gop.value_ptr.value) |_| {
                    // We already have a value assigned
                    if (value) |_| {
                        // We can't assign our value, this is an error
                        return error.DuplicateNameTreeValue;
                    }
                    // Entry doesn't have a value, this means it's just a branch
                    // so we can go ahead and assign our value
                } else {
                    gop.value_ptr.value = value;
                }
                // No node currently exists, let's create one and add it
            } else {
                gop.value_ptr.* = try NT.child(self.memory, key, value);
            }

            // Return our obtained or placed child node
            return gop.value_ptr;
        }

        /// De-inits a name tree object and frees the required memory.
        pub fn deinit(self: *NT) void {
            // This isn't super awesome, but it allows a child
            // to either free itself, or get freed by the parent.
            // If we try to do both, this prevents a double free.
            if (self.freed) return;
            self.freed = true;

            // Make sure the key is deinitialized
            switch (self.key) {
                .root => {},
                .namespace => |*n| n.deinit(),
                .str => |k| self.memory.alloc().free(k),
            }

            // Deinit the value object
            if (self.value) |*value| {
                if (vTable.deinit) |di| {
                    di(value, self.memory);
                }
            }

            if (self.children) |*c| {
                var iter = c.valueIterator();
                while (iter.next()) |childValue| {
                    childValue.deinit();
                }
                c.deinit();
                self.children = null;
            }
        }

        const TreeLoc = struct {
            depth: usize,
            tree: *const NT,
        };

        pub fn find(self: *const NT, name: *const Name) *const NT {
            var iter = switch (self.key) {
                .namespace => |*ns| name.iterContext(ns) catch {
                    return self;
                } orelse {
                    return self;
                },
                else => name.iterReverse(),
            };
            var depth = TreeLoc{
                .depth = 0,
                .tree = self,
            };

            const deepest = self.find_inner(&iter, &depth);
            return deepest.tree;
        }

        fn find_inner(self: *const NT, iter: *Name.Iterator, deepest: *TreeLoc) TreeLoc {
            // We still have labels, keep searching
            if (iter.next()) |label| {
                // This tree has child trees
                if (self.children) |children| {
                    // There is an exact domain match in the tree beneath
                    if (children.getPtr(label)) |found| {
                        deepest.depth += 1;
                        deepest.tree = found;
                        return found.find_inner(iter, deepest);
                        // There is a wildcard domain match in the tree beneath
                    } else if (children.getPtr("*")) |wildfound| {
                        deepest.depth += 1;
                        deepest.tree = wildfound;
                        return wildfound.find_inner(iter, deepest);
                        // No more child trees found, we've gone as far as we can
                    } else {
                        return deepest.*;
                    }
                    // This tree has no children, so we have found the deepest tree
                    // matching
                } else {
                    return deepest.*;
                }
                // We are out of labels, return the deepest tree we have so far
            } else {
                return deepest.*;
            }
        }
    };
}

//--------------------------------------------------
// Testing
const testing = std.testing;

test "creating tree" {
    var pool = try DNSMemory.init();
    defer pool.deinit();

    var tree = Tree(i32, .{ .deinit = null }).init(&pool);
    defer tree.deinit();
}

test "add node" {
    var pool = try DNSMemory.init();
    defer pool.deinit();

    var tree = Tree(i32, .{ .deinit = null }).init(&pool);
    defer tree.deinit();

    var com = try tree.addChild("com", null);
    defer com.deinit();

    var example = try com.addChild("example", 32);
    defer example.deinit();
}

test "deinit node" {
    var pool = try DNSMemory.init();
    defer pool.deinit();

    const Zone = struct {
        value: []u8,

        pub fn deinit(ctx: *anyopaque, memory: *DNSMemory) void {
            const self: *@This() = @ptrCast(@alignCast(ctx));
            memory.alloc().free(self.value);
        }
    };

    const zone = Zone{
        .value = try pool.alloc().alloc(u8, 1024),
    };

    var tree = Tree(Zone, .{ .deinit = Zone.deinit }).init(&pool);
    defer tree.deinit();

    var com = try tree.addChild("com", zone);
    defer com.deinit();
}

// ==========================================================
// find() and find_inner() tests
// ==========================================================

// ----------------------------------------------------------
// Basic Exact Matching Tests
// ----------------------------------------------------------

test "find - exact match" {
    var pool = try DNSMemory.init();
    defer pool.deinit();

    var tree = Tree(i32, .{ .deinit = null }).init(&pool);
    defer tree.deinit();

    var com = try tree.addChild("com", 1);
    var example = try com.addChild("example", 2);
    _ = try example.addChild("www", 3);

    const cases = .{
        // Single level - direct child of root
        .{ .domain = "com", .expected_key = "com", .expected_value = 1 },
        // Two levels - nested node
        .{ .domain = "example.com", .expected_key = "example", .expected_value = 2 },
        // Deep hierarchy - three levels
        .{ .domain = "www.example.com", .expected_key = "www", .expected_value = 3 },
    };

    inline for (cases) |case| {
        const name = try Name.fromStr(case.domain);
        const found = tree.find(&name);

        try testing.expectEqualStrings(case.expected_key, found.key.str);
        try testing.expectEqual(case.expected_value, found.value.?);
    }
}

test "find - root only returns root" {
    var pool = try DNSMemory.init();
    defer pool.deinit();

    var tree = Tree(i32, .{ .deinit = null }).init(&pool);
    defer tree.deinit();

    // Tree has no children, any lookup should return root
    const name = try Name.fromStr("anything.com");
    const found = tree.find(&name);

    try testing.expect(found.key == .root);
    try testing.expectEqual(null, found.value);
}

// ----------------------------------------------------------
// Partial Matching Tests (Deepest Node)
// ----------------------------------------------------------

test "find - partial match returns deepest node" {
    var pool = try DNSMemory.init();
    defer pool.deinit();

    var tree = Tree(i32, .{ .deinit = null }).init(&pool);
    defer tree.deinit();

    var com = try tree.addChild("com", 1);
    _ = try com.addChild("example", 2);

    // Name has more labels than tree depth - returns deepest match
    {
        const name = try Name.fromStr("www.example.com");
        const found = tree.find(&name);
        try testing.expectEqualStrings("example", found.key.str);
        try testing.expectEqual(2, found.value.?);
    }

    // Name diverges from tree - returns last matching node
    {
        const name = try Name.fromStr("other.com");
        const found = tree.find(&name);
        try testing.expectEqualStrings("com", found.key.str);
        try testing.expectEqual(1, found.value.?);
    }

    // First label doesn't match any children - returns root
    {
        const name = try Name.fromStr("org");
        const found = tree.find(&name);
        try testing.expect(found.key == .root);
        try testing.expectEqual(null, found.value);
    }

    // Completely different domain - returns root
    {
        const name = try Name.fromStr("www.test.org");
        const found = tree.find(&name);
        try testing.expect(found.key == .root);
        try testing.expectEqual(null, found.value);
    }
}

test "find - graceful fallback when no match" {
    var pool = try DNSMemory.init();
    defer pool.deinit();

    var tree = Tree(i32, .{ .deinit = null }).init(&pool);
    defer tree.deinit();

    // Build a specific branch
    var com = try tree.addChild("com", 1);
    var example = try com.addChild("example", 2);
    _ = try example.addChild("api", 3);

    // Query for a completely unrelated domain - should gracefully return root
    const unrelated_cases = .{
        "net",
        "example.org",
        "www.test.net",
        "deep.nested.domain.io",
    };

    inline for (unrelated_cases) |domain| {
        const name = try Name.fromStr(domain);
        const found = tree.find(&name);

        // Should always return root without error
        try testing.expect(found.key == .root);
        try testing.expectEqual(null, found.value);
    }
}

// ----------------------------------------------------------
// Wildcard Matching Tests
// ----------------------------------------------------------

test "find - wildcard matches when exact fails" {
    var pool = try DNSMemory.init();
    defer pool.deinit();

    var tree = Tree(i32, .{ .deinit = null }).init(&pool);
    defer tree.deinit();

    var com = try tree.addChild("com", 1);
    _ = try com.addChild("*", 99);

    const cases = .{
        "anything.com",
        "random.com",
        "test.com",
        "wildcard-match.com",
    };

    inline for (cases) |domain| {
        const name = try Name.fromStr(domain);
        const found = tree.find(&name);

        try testing.expectEqualStrings("*", found.key.str);
        try testing.expectEqual(99, found.value.?);
    }
}

test "find - exact match takes priority over wildcard" {
    var pool = try DNSMemory.init();
    defer pool.deinit();

    var tree = Tree(i32, .{ .deinit = null }).init(&pool);
    defer tree.deinit();

    var com = try tree.addChild("com", 1);
    _ = try com.addChild("example", 100); // Exact match
    _ = try com.addChild("*", 99); // Wildcard

    // Exact match should be preferred
    const exact_name = try Name.fromStr("example.com");
    const exact_found = tree.find(&exact_name);
    try testing.expectEqualStrings("example", exact_found.key.str);
    try testing.expectEqual(100, exact_found.value.?);

    // Wildcard should match other domains
    const wildcard_name = try Name.fromStr("other.com");
    const wildcard_found = tree.find(&wildcard_name);
    try testing.expectEqualStrings("*", wildcard_found.key.str);
    try testing.expectEqual(99, wildcard_found.value.?);
}

test "find - nested under wildcard" {
    var pool = try DNSMemory.init();
    defer pool.deinit();

    var tree = Tree(i32, .{ .deinit = null }).init(&pool);
    defer tree.deinit();

    var com = try tree.addChild("com", 1);
    var wildcard = try com.addChild("*", 50);
    _ = try wildcard.addChild("www", 100);

    // Direct wildcard match
    const direct_name = try Name.fromStr("anything.com");
    const direct_found = tree.find(&direct_name);
    try testing.expectEqualStrings("*", direct_found.key.str);
    try testing.expectEqual(50, direct_found.value.?);

    // Nested under wildcard - www.anything.com should find www under *
    const nested_name = try Name.fromStr("www.anything.com");
    const nested_found = tree.find(&nested_name);
    try testing.expectEqualStrings("www", nested_found.key.str);
    try testing.expectEqual(100, nested_found.value.?);
}

test "find - wildcard at deep level" {
    var pool = try DNSMemory.init();
    defer pool.deinit();

    var tree = Tree(i32, .{ .deinit = null }).init(&pool);
    defer tree.deinit();

    var com = try tree.addChild("com", 1);
    var example = try com.addChild("example", 2);
    _ = try example.addChild("*", 99);

    const cases = .{
        .{ .domain = "api.example.com", .expected_key = "*", .expected_value = 99 },
        .{ .domain = "www.example.com", .expected_key = "*", .expected_value = 99 },
        .{ .domain = "anything.example.com", .expected_key = "*", .expected_value = 99 },
        // Exact parent should still work
        .{ .domain = "example.com", .expected_key = "example", .expected_value = 2 },
    };

    inline for (cases) |case| {
        const name = try Name.fromStr(case.domain);
        const found = tree.find(&name);

        try testing.expectEqualStrings(case.expected_key, found.key.str);
        try testing.expectEqual(case.expected_value, found.value.?);
    }
}

// ----------------------------------------------------------
// Edge Case Tests
// ----------------------------------------------------------

test "find - nodes without values" {
    var pool = try DNSMemory.init();
    defer pool.deinit();

    var tree = Tree(i32, .{ .deinit = null }).init(&pool);
    defer tree.deinit();

    // Create intermediate nodes without values
    var com = try tree.addChild("com", null);
    var example = try com.addChild("example", null);
    _ = try example.addChild("www", 100);

    // Should still find deepest matching node even without value
    const intermediate_name = try Name.fromStr("example.com");
    const intermediate_found = tree.find(&intermediate_name);
    try testing.expectEqualStrings("example", intermediate_found.key.str);
    try testing.expectEqual(null, intermediate_found.value);

    // Should find node with value
    const leaf_name = try Name.fromStr("www.example.com");
    const leaf_found = tree.find(&leaf_name);
    try testing.expectEqualStrings("www", leaf_found.key.str);
    try testing.expectEqual(100, leaf_found.value.?);
}

test "find - empty children hashmap" {
    var pool = try DNSMemory.init();
    defer pool.deinit();

    var tree = Tree(i32, .{ .deinit = null }).init(&pool);
    defer tree.deinit();

    // Add a child but don't give it any children
    _ = try tree.addChild("com", 1);

    // Query for a subdomain of com - should return com since it has no children
    const name = try Name.fromStr("example.com");
    const found = tree.find(&name);

    try testing.expectEqualStrings("com", found.key.str);
    try testing.expectEqual(1, found.value.?);
}

// ----------------------------------------------------------
// Multiple Branches Tests
// ----------------------------------------------------------

test "find - multiple TLD branches" {
    var pool = try DNSMemory.init();
    defer pool.deinit();

    var tree = Tree(i32, .{ .deinit = null }).init(&pool);
    defer tree.deinit();

    _ = try tree.addChild("com", 1);
    _ = try tree.addChild("org", 2);
    _ = try tree.addChild("net", 3);
    _ = try tree.addChild("io", 4);

    const cases = .{
        .{ .domain = "com", .expected_key = "com", .expected_value = 1 },
        .{ .domain = "org", .expected_key = "org", .expected_value = 2 },
        .{ .domain = "net", .expected_key = "net", .expected_value = 3 },
        .{ .domain = "io", .expected_key = "io", .expected_value = 4 },
    };

    inline for (cases) |case| {
        const name = try Name.fromStr(case.domain);
        const found = tree.find(&name);

        try testing.expectEqualStrings(case.expected_key, found.key.str);
        try testing.expectEqual(case.expected_value, found.value.?);
    }
}

test "find - multiple sibling domains under same TLD" {
    var pool = try DNSMemory.init();
    defer pool.deinit();

    var tree = Tree(i32, .{ .deinit = null }).init(&pool);
    defer tree.deinit();

    var com = try tree.addChild("com", 1);
    _ = try com.addChild("example", 10);
    _ = try com.addChild("test", 20);
    _ = try com.addChild("demo", 30);

    const cases = .{
        .{ .domain = "example.com", .expected_key = "example", .expected_value = 10 },
        .{ .domain = "test.com", .expected_key = "test", .expected_value = 20 },
        .{ .domain = "demo.com", .expected_key = "demo", .expected_value = 30 },
        // Non-existent sibling should fall back to parent
        .{ .domain = "other.com", .expected_key = "com", .expected_value = 1 },
    };

    inline for (cases) |case| {
        const name = try Name.fromStr(case.domain);
        const found = tree.find(&name);

        try testing.expectEqualStrings(case.expected_key, found.key.str);
        try testing.expectEqual(case.expected_value, found.value.?);
    }
}

test "find - complex tree with multiple branches and depths" {
    var pool = try DNSMemory.init();
    defer pool.deinit();

    var tree = Tree(i32, .{ .deinit = null }).init(&pool);
    defer tree.deinit();

    // Build complex tree:
    // . (root, no value)
    // |-- com (1)
    // |   |-- example (10)
    // |   |   |-- www (100)
    // |   |   +-- api (101)
    // |   +-- test (20)
    // |       +-- * (200)
    // +-- org (2)
    //     +-- example (11)
    //         +-- docs (110)

    var com = try tree.addChild("com", 1);
    var example_com = try com.addChild("example", 10);
    _ = try example_com.addChild("www", 100);
    _ = try example_com.addChild("api", 101);

    var test_com = try com.addChild("test", 20);
    _ = try test_com.addChild("*", 200);

    var org = try tree.addChild("org", 2);
    var example_org = try org.addChild("example", 11);
    _ = try example_org.addChild("docs", 110);

    // Test .com branch
    {
        const name = try Name.fromStr("com");
        const found = tree.find(&name);
        try testing.expectEqualStrings("com", found.key.str);
        try testing.expectEqual(1, found.value.?);
    }
    {
        const name = try Name.fromStr("example.com");
        const found = tree.find(&name);
        try testing.expectEqualStrings("example", found.key.str);
        try testing.expectEqual(10, found.value.?);
    }
    {
        const name = try Name.fromStr("www.example.com");
        const found = tree.find(&name);
        try testing.expectEqualStrings("www", found.key.str);
        try testing.expectEqual(100, found.value.?);
    }
    {
        const name = try Name.fromStr("api.example.com");
        const found = tree.find(&name);
        try testing.expectEqualStrings("api", found.key.str);
        try testing.expectEqual(101, found.value.?);
    }
    {
        const name = try Name.fromStr("unknown.example.com");
        const found = tree.find(&name);
        try testing.expectEqualStrings("example", found.key.str);
        try testing.expectEqual(10, found.value.?);
    }

    // Test test.com with wildcard
    {
        const name = try Name.fromStr("test.com");
        const found = tree.find(&name);
        try testing.expectEqualStrings("test", found.key.str);
        try testing.expectEqual(20, found.value.?);
    }
    {
        const name = try Name.fromStr("anything.test.com");
        const found = tree.find(&name);
        try testing.expectEqualStrings("*", found.key.str);
        try testing.expectEqual(200, found.value.?);
    }
    {
        const name = try Name.fromStr("staging.test.com");
        const found = tree.find(&name);
        try testing.expectEqualStrings("*", found.key.str);
        try testing.expectEqual(200, found.value.?);
    }

    // Test .org branch
    {
        const name = try Name.fromStr("org");
        const found = tree.find(&name);
        try testing.expectEqualStrings("org", found.key.str);
        try testing.expectEqual(2, found.value.?);
    }
    {
        const name = try Name.fromStr("example.org");
        const found = tree.find(&name);
        try testing.expectEqualStrings("example", found.key.str);
        try testing.expectEqual(11, found.value.?);
    }
    {
        const name = try Name.fromStr("docs.example.org");
        const found = tree.find(&name);
        try testing.expectEqualStrings("docs", found.key.str);
        try testing.expectEqual(110, found.value.?);
    }

    // Test non-existent branches - should return root
    {
        const name = try Name.fromStr("net");
        const found = tree.find(&name);
        try testing.expect(found.key == .root);
        try testing.expectEqual(null, found.value);
    }
    {
        const name = try Name.fromStr("other.org");
        const found = tree.find(&name);
        try testing.expectEqualStrings("org", found.key.str);
        try testing.expectEqual(2, found.value.?);
    }
}
