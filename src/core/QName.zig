const std = @import("std");

// IO
const io = std.io;
const Reader = io.Reader;

// Memory
const Allocator = std.mem.Allocator;

// Core
const Label = @import("Label.zig");

//--------------------------------------------------
// DNS Query Name

const QName = @This();

allocator: Allocator,
labels: []Label,

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
