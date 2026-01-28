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

const VTable = struct {
    deinit: ?*const fn (*anyopaque, memory: *DNSMemory) void,
};

/// Name Tree. Used to create a DNS name tree broken down
/// by labels. This is used very heavily in DNS systems.
fn Tree(comptime T: type, vTable: VTable) type {
    return struct {
        const NT = @This();
        const vtable: VTable = vTable;

        key: []u8,
        value: ?T,
        children: ?std.StringHashMap(NT),

        freed: bool,

        memory: *DNSMemory,

        /// Creates a name tree.
        ///
        /// key: Name of the node. This value will be duped, so this can be
        ///      a temporary value. This should refer to a single name label
        ///      generally. For root domains, a dot should be used.
        /// value: Optional value to apply to the node.
        ///
        /// Note: Initial name trees have no children.
        pub fn init(memory: *DNSMemory, key: []const u8, value: ?T) !NT {
            const buf = try memory.alloc().dupe(u8, key);
            errdefer memory.alloc().free(buf);
            return NT{
                .key = buf,
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
                gop.value_ptr.* = try NT.init(self.memory, key, value);
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

            self.memory.alloc().free(self.key);

            // Deinit the value object
            if (self.value) |*value| {
                if (vTable.deinit) |di| {
                    di(value, self.memory);
                }
            }

            if (self.children) |*c| {
                var iter = c.valueIterator();
                while (iter.next()) |child| {
                    child.deinit();
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
            var iter = name.iterReverse();
            var depth = TreeLoc{
                .depth = 0,
                .tree = self,
            };

            const deepest = self.find_inner(&iter, &depth);
            return deepest.tree;
        }

        pub fn findContext(self: *const NT, name: *const Name, context: *const Name) *const NT {
            var iter = try name.iterContext(context);
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

    var tree = try Tree(i32, .{ .deinit = null }).init(&pool, ".", null);
    defer tree.deinit();
}

test "add node" {
    var pool = try DNSMemory.init();
    defer pool.deinit();

    var tree = try Tree(i32, .{ .deinit = null }).init(&pool, ".", null);
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

    var tree = try Tree(Zone, .{ .deinit = Zone.deinit }).init(&pool, ".", null);
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

    var tree = try Tree(i32, .{ .deinit = null }).init(&pool, ".", 0);
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

        try testing.expectEqualStrings(case.expected_key, found.key);
        try testing.expectEqual(case.expected_value, found.value.?);
    }
}

test "find - root only returns root" {
    var pool = try DNSMemory.init();
    defer pool.deinit();

    var tree = try Tree(i32, .{ .deinit = null }).init(&pool, ".", 0);
    defer tree.deinit();

    // Tree has no children, any lookup should return root
    const name = try Name.fromStr("anything.com");
    const found = tree.find(&name);

    try testing.expectEqualStrings(".", found.key);
    try testing.expectEqual(0, found.value.?);
}

// ----------------------------------------------------------
// Partial Matching Tests (Deepest Node)
// ----------------------------------------------------------

test "find - partial match returns deepest node" {
    var pool = try DNSMemory.init();
    defer pool.deinit();

    var tree = try Tree(i32, .{ .deinit = null }).init(&pool, ".", 0);
    defer tree.deinit();

    var com = try tree.addChild("com", 1);
    _ = try com.addChild("example", 2);

    const cases = .{
        // Name has more labels than tree depth - returns deepest match
        .{ .domain = "www.example.com", .expected_key = "example", .expected_value = 2 },
        // Name diverges from tree - returns last matching node
        .{ .domain = "other.com", .expected_key = "com", .expected_value = 1 },
        // First label doesn't match any children - returns root
        .{ .domain = "org", .expected_key = ".", .expected_value = 0 },
        // Completely different domain - returns root
        .{ .domain = "www.test.org", .expected_key = ".", .expected_value = 0 },
    };

    inline for (cases) |case| {
        const name = try Name.fromStr(case.domain);
        const found = tree.find(&name);

        try testing.expectEqualStrings(case.expected_key, found.key);
        try testing.expectEqual(case.expected_value, found.value.?);
    }
}

test "find - graceful fallback when no match" {
    var pool = try DNSMemory.init();
    defer pool.deinit();

    var tree = try Tree(i32, .{ .deinit = null }).init(&pool, ".", 0);
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
        try testing.expectEqualStrings(".", found.key);
        try testing.expectEqual(0, found.value.?);
    }
}

// ----------------------------------------------------------
// Wildcard Matching Tests
// ----------------------------------------------------------

test "find - wildcard matches when exact fails" {
    var pool = try DNSMemory.init();
    defer pool.deinit();

    var tree = try Tree(i32, .{ .deinit = null }).init(&pool, ".", 0);
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

        try testing.expectEqualStrings("*", found.key);
        try testing.expectEqual(99, found.value.?);
    }
}

test "find - exact match takes priority over wildcard" {
    var pool = try DNSMemory.init();
    defer pool.deinit();

    var tree = try Tree(i32, .{ .deinit = null }).init(&pool, ".", 0);
    defer tree.deinit();

    var com = try tree.addChild("com", 1);
    _ = try com.addChild("example", 100); // Exact match
    _ = try com.addChild("*", 99); // Wildcard

    // Exact match should be preferred
    const exact_name = try Name.fromStr("example.com");
    const exact_found = tree.find(&exact_name);
    try testing.expectEqualStrings("example", exact_found.key);
    try testing.expectEqual(100, exact_found.value.?);

    // Wildcard should match other domains
    const wildcard_name = try Name.fromStr("other.com");
    const wildcard_found = tree.find(&wildcard_name);
    try testing.expectEqualStrings("*", wildcard_found.key);
    try testing.expectEqual(99, wildcard_found.value.?);
}

test "find - nested under wildcard" {
    var pool = try DNSMemory.init();
    defer pool.deinit();

    var tree = try Tree(i32, .{ .deinit = null }).init(&pool, ".", 0);
    defer tree.deinit();

    var com = try tree.addChild("com", 1);
    var wildcard = try com.addChild("*", 50);
    _ = try wildcard.addChild("www", 100);

    // Direct wildcard match
    const direct_name = try Name.fromStr("anything.com");
    const direct_found = tree.find(&direct_name);
    try testing.expectEqualStrings("*", direct_found.key);
    try testing.expectEqual(50, direct_found.value.?);

    // Nested under wildcard - www.anything.com should find www under *
    const nested_name = try Name.fromStr("www.anything.com");
    const nested_found = tree.find(&nested_name);
    try testing.expectEqualStrings("www", nested_found.key);
    try testing.expectEqual(100, nested_found.value.?);
}

test "find - wildcard at deep level" {
    var pool = try DNSMemory.init();
    defer pool.deinit();

    var tree = try Tree(i32, .{ .deinit = null }).init(&pool, ".", 0);
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

        try testing.expectEqualStrings(case.expected_key, found.key);
        try testing.expectEqual(case.expected_value, found.value.?);
    }
}

// ----------------------------------------------------------
// Edge Case Tests
// ----------------------------------------------------------

test "find - nodes without values" {
    var pool = try DNSMemory.init();
    defer pool.deinit();

    var tree = try Tree(i32, .{ .deinit = null }).init(&pool, ".", null);
    defer tree.deinit();

    // Create intermediate nodes without values
    var com = try tree.addChild("com", null);
    var example = try com.addChild("example", null);
    _ = try example.addChild("www", 100);

    // Should still find deepest matching node even without value
    const intermediate_name = try Name.fromStr("example.com");
    const intermediate_found = tree.find(&intermediate_name);
    try testing.expectEqualStrings("example", intermediate_found.key);
    try testing.expectEqual(null, intermediate_found.value);

    // Should find node with value
    const leaf_name = try Name.fromStr("www.example.com");
    const leaf_found = tree.find(&leaf_name);
    try testing.expectEqualStrings("www", leaf_found.key);
    try testing.expectEqual(100, leaf_found.value.?);
}

test "find - empty children hashmap" {
    var pool = try DNSMemory.init();
    defer pool.deinit();

    var tree = try Tree(i32, .{ .deinit = null }).init(&pool, ".", 0);
    defer tree.deinit();

    // Add a child but don't give it any children
    _ = try tree.addChild("com", 1);

    // Query for a subdomain of com - should return com since it has no children
    const name = try Name.fromStr("example.com");
    const found = tree.find(&name);

    try testing.expectEqualStrings("com", found.key);
    try testing.expectEqual(1, found.value.?);
}

// ----------------------------------------------------------
// Multiple Branches Tests
// ----------------------------------------------------------

test "find - multiple TLD branches" {
    var pool = try DNSMemory.init();
    defer pool.deinit();

    var tree = try Tree(i32, .{ .deinit = null }).init(&pool, ".", 0);
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

        try testing.expectEqualStrings(case.expected_key, found.key);
        try testing.expectEqual(case.expected_value, found.value.?);
    }
}

test "find - multiple sibling domains under same TLD" {
    var pool = try DNSMemory.init();
    defer pool.deinit();

    var tree = try Tree(i32, .{ .deinit = null }).init(&pool, ".", 0);
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

        try testing.expectEqualStrings(case.expected_key, found.key);
        try testing.expectEqual(case.expected_value, found.value.?);
    }
}

test "find - complex tree with multiple branches and depths" {
    var pool = try DNSMemory.init();
    defer pool.deinit();

    var tree = try Tree(i32, .{ .deinit = null }).init(&pool, ".", 0);
    defer tree.deinit();

    // Build complex tree:
    // . (0)
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

    const cases = .{
        // .com branch
        .{ .domain = "com", .expected_key = "com", .expected_value = 1 },
        .{ .domain = "example.com", .expected_key = "example", .expected_value = 10 },
        .{ .domain = "www.example.com", .expected_key = "www", .expected_value = 100 },
        .{ .domain = "api.example.com", .expected_key = "api", .expected_value = 101 },
        .{ .domain = "unknown.example.com", .expected_key = "example", .expected_value = 10 },
        // test.com with wildcard
        .{ .domain = "test.com", .expected_key = "test", .expected_value = 20 },
        .{ .domain = "anything.test.com", .expected_key = "*", .expected_value = 200 },
        .{ .domain = "staging.test.com", .expected_key = "*", .expected_value = 200 },
        // .org branch
        .{ .domain = "org", .expected_key = "org", .expected_value = 2 },
        .{ .domain = "example.org", .expected_key = "example", .expected_value = 11 },
        .{ .domain = "docs.example.org", .expected_key = "docs", .expected_value = 110 },
        // Non-existent branches
        .{ .domain = "net", .expected_key = ".", .expected_value = 0 },
        .{ .domain = "other.org", .expected_key = "org", .expected_value = 2 },
    };

    inline for (cases) |case| {
        const name = try Name.fromStr(case.domain);
        const found = tree.find(&name);

        try testing.expectEqualStrings(case.expected_key, found.key);
        try testing.expectEqual(case.expected_value, found.value.?);
    }
}
