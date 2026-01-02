const std = @import("std");

const treebeard = @import("treebeard");
const DNSReader = treebeard.DNSReader;
const DNSWriter = treebeard.DNSWriter;

//--------------------------------------------------
// Header Types

/// Header Opcodes
/// From: https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-5
pub const Opcode = enum(u4) {
    /// Query [RFC1035]
    query = 0,

    /// Inverse Query, OBSOLETE [RFC3425]
    inverse = 1,

    /// Status [RFC1035]
    status = 2,

    /// Unassigned
    _unassigned_3 = 3,

    /// Notify [RFC1996]
    notify = 4,

    /// Update [RFC2136]
    update = 5,

    /// DNS Stateful Operations (DSO) [RFC8490]
    DSO = 6,

    _,
};

/// Header response codes
/// From: https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-6
pub const ResponseCode = enum(u4) {
    /// No Error
    noError = 0,

    /// Format Error
    formErr = 1,

    /// Server Failure
    servFail = 2,

    /// Non-Existant Domain
    nxDomain = 3,

    /// Not Implemented
    notImp = 4,

    /// Query Refused
    refused = 5,

    /// Name Exists when it should not
    yxDomain = 6,

    /// RR Set Exists when it should not
    yxRRSet = 7,

    /// RR Set that should exist does not
    nxRRSet = 8,

    /// Server not authoritative for zone
    notAuth = 9,

    /// Name not contained in zone
    notZone = 10,

    /// DSO-TYPE Not Implemented
    DSOTypeNotImp = 11,

    /// 12-15 are unassigned
    _,
};

/// RR Type class
/// References:
///   docs/rfc/rfc1035 : 3.2.2 - (Base DNS)
///   docs/rfc/rfc2782 - (SRV)
///   docs/rfc/rfc3596 - (AAAA)
pub const Type = enum(u16) {
    /// An IPv4 host address
    A = 1,

    /// An authoritative name server
    NS = 2,

    /// The canonical name for an alias
    CNAME = 5,

    /// Marks the start of a zone of authority
    SOA = 6,

    /// Domain name pointer
    PTR = 12,

    /// Mail exchange
    MX = 15,

    /// Text Strings
    TXT = 16,

    /// An IPv6 host address
    AAAA = 28,

    /// Service locations
    SRV = 33,

    /// Decode Record type from encoded DNS format
    pub fn decode(reader: *DNSReader) !Type {
        const typeInt: u16 = reader.reader.takeInt(u16, .big) catch return error.NotEnoughBytes;
        const typeEnum: Type = std.meta.intToEnum(Type, typeInt) catch return error.InvalidType;
        return typeEnum;
    }

    /// Encodes Record type to encoded DNS format
    pub fn encode(self: Type, writer: *DNSWriter) !void {
        const typeInt: u16 = @intFromEnum(self);
        try writer.writer.writeInt(u16, typeInt, .big);
    }
};

/// QType values
/// QTypes are a superset of Types, so all Types are valid QTypes.
/// References:
///   docs/rfc/rfc1035
pub const QType = enum(u16) {
    /// A request for a transfer of an entire zone
    AXFR = 252,

    /// A request for all records
    ALL = 255,
};

/// Class fields appear in record resources
/// References:
///   docs/rfc/rfc1035
pub const Class = enum(u16) {
    /// The internet
    IN = 1,

    /// CSNET class (obsolete, used only for examples in obsolete RFCs)
    CS = 2,

    /// The chaos class
    CH = 3,

    /// Hesoid [Dyer 87]
    HS = 4,

    /// Decode Record class from encoded DNS format
    pub fn decode(reader: *DNSReader) !Class {
        const classInt: u16 = reader.reader.takeInt(u16, .big) catch return error.NotEnoughBytes;
        const classEnum: Class = std.meta.intToEnum(Class, classInt) catch return error.InvalidClass;
        return classEnum;
    }

    /// Encodes Record class to encoded DNS format
    pub fn encode(self: Class, writer: *DNSWriter) !void {
        const classInt: u16 = @intFromEnum(self);
        try writer.writer.writeInt(u16, classInt, .big);
    }
};

/// QClass fields appear in question sections of a query.
/// QClass values ar a superset of Class values, so every Class is a value
/// QClass
/// References:
///   docs/rfc/rfc1035
pub const QClass = enum(u16) {
    /// Any class
    ANY = 255,
};
