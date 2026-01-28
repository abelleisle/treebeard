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

pub fn query(self: *Self, name: *const Name, dnsType: Type, class: Class) Zone.Errors!?*RecordList {
    _ = self;
    _ = name;
    switch (class) {
        .IN => switch (dnsType) {
            .A => {},
            else => @panic("NOT IMPLEMENTED"),
        },
        else => @panic("NOT IMPLEMENTED"),
    }
}

//--------------------------------------------------
// Testing

test "testing query A" {}
