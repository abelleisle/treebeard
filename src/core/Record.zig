const std = @import("std");

// IO
const io = std.io;
const Reader = io.Reader;
const Writer = io.Writer;

// Memory
const Allocator = std.mem.Allocator;

// Core
const codes = @import("codes.zig");
const Type = codes.Type;
const Class = codes.Class;
const Name = @import("Name.zig");

//--------------------------------------------------
// DNS Record

/// Resource Record
const Record = @This();

/// Allocator for handling name and rdata init
allocator: Allocator,

/// Name of the node to which this record pertains
name: Name,

/// Type of RR in numeric form (e.g., 15 for MX RRs)
type: Type,

/// Class code
class: Class,

/// Count of seconds that the RR stays valid (The maximum is 231−1, which is about 68 years)
ttl: u32,

/// Length of RDATA field (specified in octets)
rDLength: u16,

/// Additional RR-specific data
rData: []u8,

// TODO: Free rData when we own the data
pub fn deinit(self: *Record) void {
    self.name.deinit();
}

// TODO free
pub fn decode(allocator: Allocator, reader: *Reader) !Record {
    const n = try Name.decode(allocator, reader);
    const t = try Type.decode(reader);
    const c = try Class.decode(reader);
    const l = try reader.takeInt(u32, .big);
    const len = try reader.takeInt(u16, .big);
    const data = try reader.take(len);

    return Record{
        .allocator = allocator,
        .name = n,
        .type = t,
        .class = c,
        .ttl = l,
        .rDLength = len,
        .rData = data,
    };
}

pub fn encode(self: *const Record, writer: *Writer) !void {
    try self.name.encode(writer);
    try self.type.encode(writer);
    try self.class.encode(writer);
    try writer.writeInt(u32, self.ttl, .big);
    try writer.writeInt(u16, self.rDLength, .big);
    const write_len = try writer.write(self.rData);
    if ((write_len != self.rData.len) and (write_len != self.rDLength)) {
        return error.NotEnoughBytes;
    }
}

pub fn display(self: *const Record) !void {
    std.debug.print("{s} {d} {s} {s}  ", .{
        self.name.name,
        self.ttl,
        @tagName(self.class),
        @tagName(self.type),
    });

    switch (self.type) {
        .A => {
            if (self.rDLength < 4) return error.InvalidARecord;
            std.debug.print("{d}.{d}.{d}.{d}", .{
                self.rData[0],
                self.rData[1],
                self.rData[2],
                self.rData[3],
            });
        },
        .AAAA => {
            if (self.rDLength < 16) return error.InvalidAAAARecord;
            for (0..8) |j| {
                if (j > 0) std.debug.print(":", .{});
                const val = std.mem.readInt(u16, self.rData[j * 2 ..][0..2], .big);
                std.debug.print("{x}", .{val});
            }
        },
        .MX => {
            if (self.rDLength < 2) return error.InvalidMXRecord;
            const pref = std.mem.readInt(u16, self.rData[0..2], .big);
            var reader = Reader.fixed(self.rData[2..]);
            var name = try Name.decode(self.allocator, &reader);
            defer name.deinit();

            std.debug.print("{d}  {s}", .{ pref, name.name });
        },
        else => std.debug.print("Unsupported type: {s}\n", .{@tagName(self.type)}),
    }

    std.debug.print("\n", .{});
}
