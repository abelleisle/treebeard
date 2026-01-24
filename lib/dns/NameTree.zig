const std = @import("std");

// DNS
const treebeard = @import("treebeard");
const DNSMemory = treebeard.DNSMemory;
const Name = treebeard.Name;

//--------------------------------------------------
// Name Tree

/// Name Tree. Used to create a DNS name tree broken down
/// by labels. This is used very heavily in DNS systems.
pub fn NameTree(comptime T: type) type {
    return struct {
        const NT = @This();

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

            // Can our value type have declarations?
            const hasChildren =
                (@typeInfo(T) == .@"struct") or
                (@typeInfo(T) == .@"enum") or
                (@typeInfo(T) == .@"union") or
                (@typeInfo(T) == .@"opaque");

            // If our value type has a "deinit" field, we should call it.
            if (hasChildren and @hasDecl(T, "deinit")) {
                if (self.value) |*value| value.deinit();
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

        pub fn find(self: *const NT, name: *const Name) usize {
            var iter = name.labels.iterReverse();
            return self.find_inner(&iter);
        }

        fn find_inner(self: *const NT, labelList: *Name.LabelList.LabelListIterator, depth: usize) usize {
            if (labelList.next()) |label| {
                if (self.key == label) {} else {
                    return depth; // TODO
                }
            } else {
                return depth; // TODO
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

    var tree = try NameTree(i32).init(&pool, ".", null);
    defer tree.deinit();
}

test "add node" {
    var pool = try DNSMemory.init();
    defer pool.deinit();

    var tree = try NameTree(i32).init(&pool, ".", null);
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

        pub fn deinit(self: *@This()) void {
            testing.allocator.free(self.value);
        }
    };

    const zone = Zone{
        .value = try std.testing.allocator.alloc(u8, 1024),
    };

    var tree = try NameTree(Zone).init(&pool, ".", null);
    defer tree.deinit();

    var com = try tree.addChild("com", zone);
    defer com.deinit();
}
