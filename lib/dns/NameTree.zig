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
                        return deepest;
                    }
                    // This tree has no children, so we have found the deepest tree
                    // matching
                } else {
                    return deepest;
                }
                // We are out of labels, return the deepest tree we have so far
            } else {
                return deepest;
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

test "find depth" {}
