const std = @import("std");

const treebeard = @import("treebeard");
const DNSReader = treebeard.DNSReader;
const DNSWriter = treebeard.DNSWriter;

//--------------------------------------------------
// Header Types

/// Header Opcodes
/// References:
///   docs/rfc/rfc1035 : 4.1.1 - (Base DNS)
pub const Opcode = enum(u4) {
    /// Query                         [RFC1035]
    query = 0,

    /// Inverse Query, OBSOLETE       [RFC3425]
    inverse = 1,

    /// Status                        [RFC1035]
    status = 2,

    /// Unassigned                    [RFC1035]
    _unassigned_3 = 3,

    /// Notify                        [RFC1996]
    notify = 4,

    /// Update                        [RFC2136]
    update = 5,

    /// DNS Stateful Operations (DSO) [RFC8490]
    DSO = 6,

    _,
};

/// Header response codes
/// References:
///   docs/rfc/rfc1035 : 3.2.2 - (Base DNS)
///   docs/rfc/rfc2136 : 1.3   - (DNS Update)
///   docs/rfc/rfc2845 : 1.7   - (TSIG)
pub const ResponseCode = enum(u4) {
    /// No Error                           [RFC1035]
    noError = 0,

    /// Format Error                       [RFC1035]
    formErr = 1,

    /// Server Failure                     [RFC1035]
    servFail = 2,

    /// Non-Existant Domain                [RFC1035]
    nxDomain = 3,

    /// Not Implemented                    [RFC1035]
    notImp = 4,

    /// Query Refused                      [RFC1035]
    refused = 5,

    /// Name Exists when it should not     [RFC2136]
    yxDomain = 6,

    /// RR Set Exists when it should not   [RFC2136]
    yxRRSet = 7,

    /// RR Set that should exist does not  [RFC2136]
    nxRRSet = 8,

    /// Server not authoritative for zone  [RFC2845]
    notAuth = 9,

    /// Name not contained in zone         [RFC2136]
    notZone = 10,

    /// 11-15 are unassigned               [RFC1035]
    _,
};

/// Extended response codes
/// References:
///   docs/rfc/rfc1035 : 3.2.2 - (Base DNS)
///   docs/rfc/rfc2136 : 1.3   - (DNS Update)
///   docs/rfc/rfc2845 : 1.7   - (TSIG)
pub const ExtendedResponseCode = enum(u16) {
    /// No Error                           [RFC1035]
    noError = 0,

    /// Format Error                       [RFC1035]
    formErr = 1,

    /// Server Failure                     [RFC1035]
    servFail = 2,

    /// Non-Existant Domain                [RFC1035]
    nxDomain = 3,

    /// Not Implemented                    [RFC1035]
    notImp = 4,

    /// Query Refused                      [RFC1035]
    refused = 5,

    /// Name Exists when it should not     [RFC2136]
    yxDomain = 6,

    /// RR Set Exists when it should not   [RFC2136]
    yxRRSet = 7,

    /// RR Set that should exist does not  [RFC2136]
    nxRRSet = 8,

    /// Server not authoritative for zone  [RFC2845]
    notAuth = 9,

    /// Name not contained in zone         [RFC2136]
    notZone = 10,

    /// 11-15 are unassigned               [RFC1035]
    /// TSIG Signature Failure             [RFC2845]
    badSig = 16,

    /// Key not recognized                 [RFC2845]
    badKey = 17,

    /// Signature out of time window       [RFC2845]
    badTime = 18,

    /// Bad TKEY Mode                      [RFC2930]
    badMode = 19,

    /// Duplicate key name                 [RFC2930]
    badName = 20,

    /// Algorithm not supported            [RFC2930]
    badAlg = 21,

    /// Bad Truncation                     [RFC4635]
    badTrunc = 22,

    /// Decode Record type from encoded DNS format
    pub fn decode(reader: *DNSReader) !Type {
        const rcodeInt: u16 = reader.reader.takeInt(u16, .big) catch return error.NotEnoughBytes;
        const rcodeEnum: ExtendedResponseCode = std.meta.intToEnum(ExtendedResponseCode, rcodeInt) catch return error.InvalidExtendedRCode;
        return rcodeEnum;
    }

    /// Encodes Record type to encoded DNS format
    pub fn encode(self: ExtendedResponseCode, writer: *DNSWriter) !void {
        const rcodeInt: u16 = @intFromEnum(self);
        try writer.writer.writeInt(u16, rcodeInt, .big);
    }
};

/// RR Type class
/// References:
///   docs/rfc/rfc1035 : 3.2.2 - (Base DNS)
///   docs/rfc/rfc2782         - (SRV)
///   docs/rfc/rfc3596         - (AAAA)
///   docs/rfc/rfc2845 : 1.7   - (TSIG)
pub const Type = enum(u16) {
    /// An IPv4 host address                   [RFC1035]
    A = 1,

    /// An authoritative name server           [RFC1035]
    NS = 2,

    /// The canonical name for an alias        [RFC1035]
    CNAME = 5,

    /// Marks the start of a zone of authority [RFC1035]
    SOA = 6,

    /// Domain name pointer                    [RFC1035]
    PTR = 12,

    /// Mail exchange                          [RFC1035]
    MX = 15,

    /// Text Strings                           [RFC1035]
    TXT = 16,

    /// An IPv6 host address                   [RFC3539]
    AAAA = 28,

    /// Service locations                      [RFC2782]
    SRV = 33,

    /// TSIG                                   [RFC2845]
    TSIG = 250,

    /// Decode Record type from encoded DNS format
    pub fn decode(reader: *DNSReader) !Type {
        const typeInt: u16 = reader.reader.takeInt(u16, .big) catch return error.NotEnoughBytes;
        const typeEnum: Type = std.enums.fromInt(Type, typeInt) orelse return error.InvalidType;
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
///   docs/rfc/rfc1035 : 3.2.4 - (Base DNS)
pub const Class = enum(u16) {
    /// The internet                                                    [RFC1035]
    IN = 1,

    /// CSNET class (obsolete, used only for examples in obsolete RFCs) [RFC1035]
    CS = 2,

    /// The chaos class                                                 [RFC1035]
    CH = 3,

    /// Hesoid [Dyer 87]                                                [RFC1035]
    HS = 4,

    /// A request for a transfer of an entire zone                      [RFC1035]
    AXFR = 252,

    /// Any class                                                       [RFC1035]
    ANY = 255,

    /// Decode Record class from encoded DNS format
    pub fn decode(reader: *DNSReader) !Class {
        const classInt: u16 = reader.reader.takeInt(u16, .big) catch return error.NotEnoughBytes;
        const classEnum: Class = std.enums.fromInt(Class, classInt) orelse return error.InvalidClass;
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
