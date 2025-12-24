const std = @import("std");

// IO
const io = std.io;
const Writer = io.Writer;
const Reader = io.Reader;

// Memory
const Allocator = std.mem.Allocator;

// Core
const codes = @import("codes.zig");
const Type = codes.Type;
const Class = codes.Class;
const QName = @import("QName.zig");

//--------------------------------------------------
// DNS Question

/// DNS question (query)
const Question = @This();

allocator: Allocator,

/// Name of the requested resource
name: QName,

/// Type of RR (A, AAAA, MX, TXT, etc.)
type: Type,

/// Class code
class: Class,

pub fn from_reader(allocator: Allocator, reader: *Reader) !Question {
    var name = try QName.from_reader(allocator, reader);
    errdefer name.deinit();

    const typeRR = try reader.takeInt(u16, .big);
    const classCode = try reader.takeInt(u16, .big);

    return Question{ .allocator = allocator, .name = name, .typeRR = typeRR, .classCode = classCode };
}

pub fn deinit(self: *Question) void {
    self.name.deinit();
}
