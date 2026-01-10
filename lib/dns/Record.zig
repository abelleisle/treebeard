const std = @import("std");

// Memory
const Allocator = std.mem.Allocator;

// Core
const codes = @import("codes.zig");
const Type = codes.Type;
const Class = codes.Class;
const Name = @import("Name.zig");

const treebeard = @import("treebeard");
const DNSMemory = treebeard.DNSMemory;
const DNSReader = treebeard.DNSReader;
const DNSWriter = treebeard.DNSWriter;

//--------------------------------------------------
// DNS Record

/// Resource Record
const Record = @This();

/// Allocator for handling name and rdata init
memory: *DNSMemory,

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
pub const RData = union(enum) {
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
    TXT: []u8,
    // SRV: struct {
    //     service: []u8,
    //     proto: []u8,
    //     name: Name,
    //     ttl: u32,
    //     class: Class,
    //     priority: u16,
    //     weight: u16,
    //     port: u16,
    //     target: Name,
    // },
    Unknown: []u8, // For unimplemented types

    pub fn deinit(self: *RData, memory: *DNSMemory) void {
        switch (self.*) {
            .MX => |*mx| mx.exchanger.deinit(),
            .CNAME => |*name| name.deinit(),
            .NS => |*name| name.deinit(),
            .PTR => |*name| name.deinit(),
            .SOA => |*soa| {
                soa.mname.deinit();
                soa.rname.deinit();
            },
            .TXT => |txt| {
                memory.alloc().free(txt);
            },
            .Unknown => |data| memory.alloc().free(data),
            else => {},
        }
    }
};

/// Decode the Record type from the encoded DNS data
pub fn decode(reader: *DNSReader) !Record {
    var n = try Name.decode(reader);
    errdefer n.deinit();

    const t = try Type.decode(reader);
    const c = try Class.decode(reader);
    const ttl = try reader.reader.takeInt(u32, .big);
    const rdlength = try reader.reader.takeInt(u16, .big);

    // Parse RDATA based on type
    const rdata = switch (t) {
        .A => blk: {
            if (rdlength != 4) return error.InvalidARecord;
            const data = try reader.reader.take(4);
            var addr: [4]u8 = undefined;
            @memcpy(&addr, data);
            break :blk RData{ .A = addr };
        },
        .AAAA => blk: {
            if (rdlength != 16) return error.InvalidAAAARecord;
            const data = try reader.reader.take(16);
            var addr: [16]u8 = undefined;
            @memcpy(&addr, data);
            break :blk RData{ .AAAA = addr };
        },
        .MX => blk: {
            if (rdlength < 3) return error.InvalidMXRecord;
            const pref = try reader.reader.takeInt(u16, .big);
            const exchanger = try Name.decode(reader);
            break :blk RData{ .MX = .{ .preference = pref, .exchanger = exchanger } };
        },
        .CNAME => blk: {
            const cname = try Name.decode(reader);
            break :blk RData{ .CNAME = cname };
        },
        .NS => blk: {
            const ns = try Name.decode(reader);
            break :blk RData{ .NS = ns };
        },
        .PTR => blk: {
            const ptr = try Name.decode(reader);
            break :blk RData{ .PTR = ptr };
        },
        .TXT => blk: {
            const data = try reader.reader.take(rdlength);
            const owned = try reader.memory.alloc().dupe(u8, data);
            break :blk RData{ .TXT = owned };
        },
        else => blk: {
            const data = try reader.reader.take(rdlength);
            const owned = try reader.memory.alloc().dupe(u8, data);
            break :blk RData{ .Unknown = owned };
        },
    };

    return Record{
        .memory = reader.memory,
        .name = n,
        .type = t,
        .class = c,
        .ttl = ttl,
        .rdata = rdata,
    };
}

/// Encode the Record following the DNS encoding spec
pub fn encode(self: *Record, writer: *DNSWriter) !void {
    try self.name.encode(writer);
    try self.type.encode(writer);
    try self.class.encode(writer);
    try writer.writer.writeInt(u32, self.ttl, .big);

    switch (self.rdata) {
        .A => |*ip| {
            try writer.writer.writeInt(u16, ip.len, .big);
            const written = try writer.writer.write(ip);
            if (written != ip.len) {
                return error.NotEnoughBytes;
            }
        },
        .AAAA => |*ip| {
            try writer.writer.writeInt(u16, ip.len, .big);
            const written = try writer.writer.write(ip);
            if (written != ip.len) {
                return error.NotEnoughBytes;
            }
        },
        .CNAME, .NS, .PTR => |*name| {
            try writer.writer.writeInt(u16, @intCast(name.encodeLength()), .big);
            try name.encode(writer);
        },
        .MX => |*mx| {
            try writer.writer.writeInt(u16, @intCast(mx.exchanger.encodeLength() + 2), .big);
            try writer.writer.writeInt(u16, mx.preference, .big);
            try mx.exchanger.encode(writer);
        },
        .TXT => |txt| {
            try writer.writer.writeInt(u16, @intCast(txt.len), .big);
            const written = try writer.writer.write(txt);
            if (written != txt.len) {
                return error.NotEnoughBytes;
            }
        },
        .Unknown => |data| {
            try writer.writer.writeInt(u16, @intCast(data.len), .big);
            _ = try writer.writer.write(data);
        },
        else => return error.EncodeNotImplemented,
    }
}

/// Print the record in a human-readable way
pub fn display(self: *const Record) !void {
    std.debug.print("{f} {d} {s} {s}  ", .{
        self.name,
        self.ttl,
        @tagName(self.class),
        @tagName(self.type),
    });

    switch (self.rdata) {
        .A => |addr| {
            std.debug.print("{d}.{d}.{d}.{d}", .{ addr[0], addr[1], addr[2], addr[3] });
        },
        .AAAA => |addr| {
            var zeroTrunc = false;
            for (0..8) |j| {
                const val = std.mem.readInt(u16, addr[j * 2 ..][0..2], .big);
                if (j > 0 and val != 0) std.debug.print(":", .{});
                if (val != 0) {
                    std.debug.print("{x}", .{val});
                } else if (val == 0 and zeroTrunc == false) {
                    std.debug.print(":", .{});
                    zeroTrunc = true;
                }
            }
        },
        .MX => |mx| {
            std.debug.print("{d}  {f}", .{ mx.preference, mx.exchanger });
        },
        .CNAME => |name| {
            std.debug.print("{f}", .{name});
        },
        .NS => |name| {
            std.debug.print("{f}", .{name});
        },
        .PTR => |name| {
            std.debug.print("{f}", .{name});
        },
        .TXT => |txt| {
            std.debug.print("{s}", .{txt});
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
    self.rdata.deinit(self.memory);
}
