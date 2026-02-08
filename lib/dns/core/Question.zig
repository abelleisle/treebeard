const std = @import("std");

// Memory
const Allocator = std.mem.Allocator;

// Core
const codes = @import("codes.zig");
const Type = codes.Type;
const Class = codes.Class;
const Name = @import("Name.zig");

const treebeard = @import("treebeard");
const Context = treebeard.Context;
const DNSWriter = treebeard.DNSWriter;

//--------------------------------------------------
// DNS Question

/// DNS question (query)
const Question = @This();

/// Name of the requested resource
name: Name,

/// Type of RR (A, AAAA, MX, TXT, etc.)
type: Type,

/// Class code
class: Class,

pub fn decode(ctx: *Context) !Question {
    var name = try Name.decode(ctx);
    errdefer name.deinit();

    const typeRR = try codes.Type.decode(ctx);
    const classRR = try codes.Class.decode(ctx);

    return Question{
        .name = name,
        .type = typeRR,
        .class = classRR,
    };
}

pub fn deinit(self: *Question) void {
    self.name.deinit();
}

pub fn encode(self: *Question, writer: *DNSWriter) !void {
    try self.name.encode(writer);
    try writer.writer.writeInt(u16, @intFromEnum(self.type), .big);
    try writer.writer.writeInt(u16, @intFromEnum(self.class), .big);
}
