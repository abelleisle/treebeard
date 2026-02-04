const std = @import("std");
const RwLock = std.Thread.RwLock;

// DNS
const treebeard = @import("treebeard");
const DNSMemory = treebeard.DNSMemory;

// Types
const RecordList = treebeard.RecordList;
const Question = treebeard.Question;
const Record = treebeard.Record;
const Type = treebeard.Type;
const Class = treebeard.Class;
const Name = treebeard.Name;

// Backends
const Dict = @import("zone/dict.zig");

//--------------------------------------------------
// Zone
const Zone = @This();

const Backend = union(enum) { dict: Dict, custom: struct {
    inner: *anyopaque,
    vtable: *const CustomVTable,
} };

pub const CustomVTable = struct {
    /// Query our DNS zone to get a list of records.
    ///
    /// Returns a list of found records.
    query: *const fn (*anyopaque, question: *const Question) Errors!?*const RecordList,

    /// Deinit the inner zone backend.
    deinit: *const fn (*anyopaque, memory: *DNSMemory) void,
};

backend: Backend,

memory: *DNSMemory,

namespace: Name,

lock: RwLock,

/// Create a DNS Zone using a dictionary based backend
pub fn initDict(memory: *DNSMemory, namespace: Name) !Zone {
    return Zone{
        .backend = .{ .dict = Dict.init(memory, &namespace) },
        .memory = memory,
        .namespace = namespace,
        .lock = .{},
    };
}

/// De-init a DNS Zone.
/// Will call the appropriate backend deinit function
pub fn deinit(self: *Zone) void {
    switch (self.backend) {
        .dict => |*d| d.deinit(),
        .custom => |*c| c.vtable.deinit(c, self.memory),
    }

    self.namespace.deinit();
}

/// Given a question, return the matching records.
pub fn query(self: *const Zone, question: *const Question) Errors!?*const RecordList {
    @constCast(self).lock.lockShared();
    defer @constCast(self).lock.unlockShared();

    switch (self.backend) {
        .dict => |d| {
            const result = d.query(question);

            return result;
        },
        .custom => |c| {
            const result = c.vtable.query(c.inner, question) catch |err| {
                return err;
            };

            return result;
        },
    }
}

/// Begin a zone write operation.
/// This prevents zone reads from occuring during a large write operation.
///
/// Note: We will not automatically unlock the zone, use `stopWrite` to do that.
pub inline fn startWrite(self: *Zone) void {
    self.lock.lock();
}

/// Ends the ongoing zone write operation.
/// This allows zone reads to continue after a write operation.
pub inline fn stopWrite(self: *Zone) void {
    self.lock.unlock();
}

pub const Errors = error{
    QueryError,
};

//--------------------------------------------------
// Testing

test {
    _ = @import("zone/dict.zig");
}
