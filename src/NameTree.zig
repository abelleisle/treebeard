const std = @import("std");

// DNS
const treebeard = @import("treebeard");
const DNSMemory = treebeard.DNSMemory;

//--------------------------------------------------
// Name Tree

/// Name Tree. Used to create a DNS name tree broken down
/// by labels. This is used very heavily in DNS systems.
pub fn NameTree(comptime T: type) type {
    return struct {
        const NT = @This();

        key: []u8,
        value: ?T,
        children: ?std.StringHashMap(NameTree(T)),

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
            };
        }

        /// Adds a key/value pair as the child of this entry.
        pub fn addChild(self: *NT, key: []u8, value: ?T) ?*NT {
            // We need to add a child? Let's make sure we have a children
            // tree.
            if (self.children == null) {
                self.children = std.StringHashMap(NameTree(T)).init(self.memory.alloc());
            }

            var children = self.children.?;

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
            self.memory.alloc().free(self.key);
            if (self.children) |*c| c.deinit();
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
