const std = @import("std");

// IO
const io = std.io;
const Reader = io.Reader;
const Writer = io.Writer;

// Memory
const Allocator = std.mem.Allocator;

// Core
const Label = @import("Label.zig");

//--------------------------------------------------
// DNS Query Name

const QName = @This();

allocator: Allocator,
labels: []Label,

pub fn from_str(alloc: Allocator, domain: []const u8) !QName {
    var labelVec = try std.ArrayList(Label).initCapacity(alloc, 255);
    defer labelVec.deinit(alloc);

    errdefer {
        for (labelVec.items) |*l| l.deinit();
        labelVec.deinit(alloc);
    }

    var iter = std.mem.splitScalar(u8, domain, '.');
    while (iter.next()) |label| {
        if (label.len > Label.MAX_LEN) return error.LabelTooLong;
        const buf = try alloc.alloc(u8, label.len);
        errdefer alloc.free(buf);

        @memcpy(buf, label);

        try labelVec.append(alloc, Label{ .allocator = alloc, .data = buf });
    }

    return QName{
        .allocator = alloc,
        .labels = try labelVec.toOwnedSlice(alloc),
    };
}

pub fn from_reader(alloc: Allocator, reader: *Reader) !QName {
    var labelVec = try std.ArrayList(Label).initCapacity(alloc, 255);
    defer labelVec.deinit(alloc);
    errdefer {
        for (labelVec.items) |*l| {
            l.deinit();
        }
        labelVec.deinit(alloc);
    }

    while (try Label.from_reader(alloc, reader)) |l| {
        try labelVec.append(alloc, l);
    }

    return QName{
        .allocator = alloc,
        .labels = try labelVec.toOwnedSlice(alloc),
    };
}

pub fn deinit(self: *QName) void {
    for (self.labels) |*l| {
        l.deinit();
    }
    self.allocator.free(self.labels);
}

pub fn encode(self: *const QName, writer: *Writer) !void {
    for (self.labels) |l| {
        try l.encode(writer);
    }
    try writer.writeInt(u8, 0, .big);
}
