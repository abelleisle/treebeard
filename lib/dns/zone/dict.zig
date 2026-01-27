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
        A: NameTree.NameTree(RecordList),
        AAAA: NameTree.NameTree(RecordList),
        CNAME: NameTree.NameTree(Record),
    },
},

context: Name,

pub fn init(
    memory: *DNSMemory,
    context: Name,
) !Self {
    return Self{
        .context = context,
        .records = .{
            .IN = .{
                .A = try NameTree.NameTree(RecordList).init(memory, "@", null),
                .AAAA = try NameTree.NameTree(RecordList).init(memory, "@", null),
                .CNAME = try NameTree.NameTree(Record).init(memory, "@", null),
            },
        },
    };
}

pub fn deinit(self: *Self, memory: *DNSMemory) void {
    self.context.deinit();
}

pub fn query(ctx: *anyopaque, name: *const Name, dnsType: Type, class: Class) Zone.Errors!?*RecordList {
    const self: *Self = @ptrCast(@alignCast(ctx));
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
