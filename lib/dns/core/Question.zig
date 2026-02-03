const std = @import("std");

// Memory
const Allocator = std.mem.Allocator;

// Core
const codes = @import("codes.zig");
const Type = codes.Type;
const Class = codes.Class;
const Name = @import("Name.zig");

const DNSMemory = @import("../pool.zig").DNSMemory;
const DNSReader = @import("../pool.zig").DNSReader;
const DNSWriter = @import("../pool.zig").DNSWriter;

//--------------------------------------------------
// DNS Question

/// DNS question (query)
const Question = @This();

memory: *DNSMemory,

/// Name of the requested resource
name: Name,

/// Type of RR (A, AAAA, MX, TXT, etc.)
type: Type,

/// Class code
class: Class,

pub fn decode(reader: *DNSReader) !Question {
    var name = try Name.decode(reader);
    errdefer name.deinit();

    const typeRR = try codes.Type.decode(reader);
    const classRR = try codes.Class.decode(reader);

    return Question{
        .memory = reader.memory,
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
