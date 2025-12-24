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

    // TODO: make sure type and class are valid values
    const typeRR: codes.Type = try std.meta.intToEnum(codes.Type, try reader.takeInt(u16, .big));
    const classRR: codes.Class = try std.meta.intToEnum(codes.Class, try reader.takeInt(u16, .big));

    // zig fmt: off
    return Question{
        .allocator = allocator,
        .name = name,
        .type = typeRR,
        .class = classRR,
    };
    // zig fmt: on
}

pub fn deinit(self: *Question) void {
    self.name.deinit();
}

pub fn encode(self: *const Question, writer: *Writer) !void {
    try self.name.encode(writer);
    try writer.writeInt(u16, @intFromEnum(self.type), .big);
    try writer.writeInt(u16, @intFromEnum(self.class), .big);
}
