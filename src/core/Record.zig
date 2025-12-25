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

/// Parsed RDATA
rdata: RData,

/// Parsed RDATA based on record type
const RData = union(enum) {
    A: [4]u8,
    AAAA: [16]u8,
    MX: struct {
        preference: u16,
        exchanger: Name,
    },
    CNAME: Name,
    NS: Name,
    PTR: Name,
    SOA: struct {
        mname: Name,
        rname: Name,
        serial: u32,
        refresh: u32,
        retry: u32,
        expire: u32,
        minimum: u32,
    },
    Unknown: []u8, // For unimplemented types

    pub fn deinit(self: *RData, allocator: Allocator) void {
        switch (self.*) {
            .MX => |*mx| mx.exchanger.deinit(),
            .CNAME => |*name| name.deinit(),
            .NS => |*name| name.deinit(),
            .PTR => |*name| name.deinit(),
            .SOA => |*soa| {
                soa.mname.deinit();
                soa.rname.deinit();
            },
            .Unknown => |data| allocator.free(data),
            else => {},
        }
    }
};

/// Decode the Record type from the encoded DNS data
pub fn decode(allocator: Allocator, reader: *Reader) !Record {
    var n = try Name.decode(allocator, reader);
    errdefer n.deinit();

    const t = try Type.decode(reader);
    const c = try Class.decode(reader);
    const ttl = try reader.takeInt(u32, .big);
    const rdlength = try reader.takeInt(u16, .big);

    // Parse RDATA based on type
    const rdata = switch (t) {
        .A => blk: {
            if (rdlength != 4) return error.InvalidARecord;
            const data = try reader.take(4);
            var addr: [4]u8 = undefined;
            @memcpy(&addr, data);
            break :blk RData{ .A = addr };
        },
        .AAAA => blk: {
            if (rdlength != 16) return error.InvalidAAAARecord;
            const data = try reader.take(16);
            var addr: [16]u8 = undefined;
            @memcpy(&addr, data);
            break :blk RData{ .AAAA = addr };
        },
        .MX => blk: {
            if (rdlength < 3) return error.InvalidMXRecord;
            const pref = try reader.takeInt(u16, .big);
            const exchanger = try Name.decode(allocator, reader);
            break :blk RData{ .MX = .{ .preference = pref, .exchanger = exchanger } };
        },
        .CNAME => blk: {
            const cname = try Name.decode(allocator, reader);
            break :blk RData{ .CNAME = cname };
        },
        .NS => blk: {
            const ns = try Name.decode(allocator, reader);
            break :blk RData{ .NS = ns };
        },
        .PTR => blk: {
            const ptr = try Name.decode(allocator, reader);
            break :blk RData{ .PTR = ptr };
        },
        else => blk: {
            const data = try reader.take(rdlength);
            const owned = try allocator.dupe(u8, data);
            break :blk RData{ .Unknown = owned };
        },
    };

    return Record{
        .allocator = allocator,
        .name = n,
        .type = t,
        .class = c,
        .ttl = ttl,
        .rdata = rdata,
    };
}

/// Encode the Record following the DNS encoding spec
pub fn encode(self: *const Record, writer: *Writer) !void {
    try self.name.encode(writer);
    try self.type.encode(writer);
    try self.class.encode(writer);
    try writer.writeInt(u32, self.ttl, .big);

    switch (self.rdata) {
        .Unknown => |data| {
            try writer.writeInt(u16, @intCast(data.len), .big);
            _ = try writer.write(data);
        },
        else => return error.EncodeNotImplemented,
    }
}

/// Print the record in a human-readable way
pub fn display(self: *const Record) !void {
    std.debug.print("{s} {d} {s} {s}  ", .{
        self.name.name,
        self.ttl,
        @tagName(self.class),
        @tagName(self.type),
    });

    switch (self.rdata) {
        .A => |addr| {
            std.debug.print("{d}.{d}.{d}.{d}", .{ addr[0], addr[1], addr[2], addr[3] });
        },
        .AAAA => |addr| {
            for (0..8) |j| {
                if (j > 0) std.debug.print(":", .{});
                const val = std.mem.readInt(u16, addr[j * 2 ..][0..2], .big);
                std.debug.print("{x}", .{val});
            }
        },
        .MX => |mx| {
            std.debug.print("{d}  {s}", .{ mx.preference, mx.exchanger.name });
        },
        .CNAME => |name| {
            std.debug.print("{s}", .{name.name});
        },
        .NS => |name| {
            std.debug.print("{s}", .{name.name});
        },
        .PTR => |name| {
            std.debug.print("{s}", .{name.name});
        },
        .Unknown => {
            std.debug.print("(raw data)", .{});
        },
        else => std.debug.print("Unsupported type", .{}),
    }

    std.debug.print("\n", .{});
}

/// Deinit the Record type
pub fn deinit(self: *Record) void {
    self.name.deinit();
    self.rdata.deinit(self.allocator);
}
