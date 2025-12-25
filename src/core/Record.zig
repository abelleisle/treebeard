const std = @import("std");

// IO
const io = std.io;
const Reader = std.io.Reader;

// Memory
const Allocator = std.mem.Allocator;

// Core
const codes = @import("codes.zig");
const Type = codes.RRType;
const Class = codes.Class;

//--------------------------------------------------
// DNS Record

/// Resource Record
const Record = @This();

/// Allocator for handling name and rdata init
allocator: Allocator,

/// Name of the node to which this record pertains
name: []u8,

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

// pub fn decode(reader: *Reader) !Record {
// }
//
pub fn deinit(self: *Record) void {
    self.allocator.free(self.name);
    self.allocator.free(self.rData);
}
