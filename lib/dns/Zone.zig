const std = @import("std");

// DNS
const treebeard = @import("treebeard");
const DNSMemory = treebeard.DNSMemory;

// Types
const RecordList = treebeard.RecordList;
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
    query: *const fn (*anyopaque, name: *const Name, dnsType: Type, class: Class) Errors!?*const RecordList,

    /// Deinit the inner zone backend.
    deinit: *const fn (*anyopaque, memory: *DNSMemory) void,
};

backend: Backend,

memory: *DNSMemory,

context: Name,

/// Create a DNS Zone using a dictionary based backend
pub fn initDict(memory: *DNSMemory, context: Name) !Zone {
    return Zone{
        .backend = .{ .dict = try Dict.init(memory) },
        .memory = memory,
        .context = context,
    };
}

/// De-init a DNS Zone.
/// Will call the appropriate backend deinit function
pub fn deinit(self: *Zone) void {
    switch (self.backend) {
        .dict => |*d| d.deinit(),
        .custom => |*c| c.vtable.deinit(c, self.memory),
    }

    self.context.deinit();
}

pub fn query(self: *const Zone, name: *const Name, dnsType: Type, class: Class) Errors!?*const RecordList {
    switch (self.backend) {
        .dict => |d| {
            const result = d.query(name, &self.context, dnsType, class) catch |err| {
                return err;
            };

            return result;
        },
        .custom => |c| {
            const result = c.vtable.query(c.inner, name, dnsType, class) catch |err| {
                return err;
            };

            return result;
        },
    }
}

pub const Errors = error{
    QueryError,
};

//--------------------------------------------------
// Testing

test {
    _ = @import("zone/dict.zig");
}
