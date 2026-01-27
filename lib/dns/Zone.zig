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

//--------------------------------------------------
// Zone
const Zone = @This();

inner: *anyopaque,
memory: *DNSMemory,

context: Name,

vtable: *const VTable,

pub const VTable = struct {
    /// Query our DNS zone to get a list of records.
    ///
    /// Returns a list of found records.
    query: *const fn (*anyopaque, name: *const Name, dnsType: Type, class: Class) Errors!?*RecordList,

    /// Deinit the inner zone backend.
    deinit: *const fn (*anyopaque, memory: *DNSMemory) void,
};

pub fn query(self: *const Zone, name: *const Name, dnsType: Type, class: Class) Errors!?*RecordList {
    const result = self.vtable.query(self.inner, name, dnsType, class) catch |err| {
        return err;
    };

    return result;
}

pub fn deinit(self: *const Zone) void {
    self.vtable.deinit(self.inner, self.memory);
    self.context.deinit();
}

pub const Errors = error{
    QueryError,
};

//--------------------------------------------------
// Testing

test {
    _ = @import("zone/dict.zig");
}
