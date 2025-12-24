// Core
const codes = @import("codes.zig");
const Type = codes.RRType;
const Class = codes.Class;

//--------------------------------------------------
// DNS Record

/// Resource Record
const Record = @This();

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
