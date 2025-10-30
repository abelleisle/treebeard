const builtin = @import("builtin");
const std = @import("std");
const io = std.io;
const Writer = io.Writer;
const Reader = io.Reader;

const Allocator = std.mem.Allocator;

/// Header included with all DNS messages
pub const Header = packed struct(u96) {
    /// Transaction ID
    transactionID: u16,

    /// DNS flags indicating the message metadata
    /// Note the swapped byte + bit orders from documentation, this it because
    /// zig packs structs little-endian
    flags: packed struct(u16) {
        // ---------------
        // Byte 0

        /// Recursion Desired, indicates if the client means a recursive query.
        RD: bool,

        /// TrunCation, indicates that this message was truncated due to excessive length.
        TC: bool,

        /// Authoritative Answer, in a response, indicates if the DNS server is authoritative for the queried hostname.
        AA: bool,

        /// The type can be QUERY (standard query, 0), IQUERY (inverse query, 1), or STATUS (server status request, 2).
        OPCODE: Opcode, // u4

        /// Indicates if the message is a query (0) or a reply (1).
        QR: bool,

        // ---------------
        // Byte 1

        /// Response code, can be NOERROR (0), FORMERR (1, Format error), SERVFAIL (2), NXDOMAIN (3, Nonexistent domain), etc.
        RCODE: ResponseCode, // u4

        /// Checking Disabled, in a query, indicates that non-verified data is acceptable in a response.
        CD: bool,

        /// Authentic Data, in a response, indicates if the replying DNS server verified the data.
        AD: bool,

        /// Zero, reserved for future use.
        Z: u1 = 0,

        /// Recursion Available, in a response, indicates if the replying DNS server supports recursion.
        RA: bool,
    },

    /// Number of Questions
    numQuestions: u16,

    /// Number of Answers
    numAnswers: u16,

    /// Number of Authority RRs
    numAuthRR: u16,

    /// Number of Additional RRs
    numAddRR: u16,

    pub fn from_reader(reader: *Reader) !Header {
        var bytes = std.mem.zeroes([12]u8);

        reader.readSliceAll(&bytes) catch return error.NotEnoughBytes;

        var header: Header = @bitCast(bytes);

        // If we're running a big endian system, the bytes are already in the
        // correct order
        if (builtin.cpu.arch.endian() == .big) {
            return header;
        }

        // If we're using little endian, we need to swap the bytes around
        header.transactionID = @byteSwap(header.transactionID);
        // header.flags = @bitCast(@byteSwap(@as(u16, @bitCast(header.flags))));
        header.numQuestions = @byteSwap(header.numQuestions);
        header.numAnswers = @byteSwap(header.numAnswers);
        header.numAuthRR = @byteSwap(header.numAuthRR);
        header.numAddRR = @byteSwap(header.numAddRR);

        return header;
    }
};

/// DNS question (query)
pub const Question = struct {
    allocator: Allocator,

    /// Name of the requested resource
    name: QName,

    /// Type of RR (A, AAAA, MX, TXT, etc.)
    typeRR: u16,

    /// Class code
    classCode: u16,

    pub fn from_reader(allocator: Allocator, reader: *Reader) !Question {
        var name = try QName.from_reader(allocator, reader);
        errdefer name.deinit();

        const typeRR = try reader.takeInt(u16, .big);
        const classCode = try reader.takeInt(u16, .big);

        return Question{ .allocator = allocator, .name = name, .typeRR = typeRR, .classCode = classCode };
    }

    pub fn deinit(self: *Question) void {
        self.name.deinit();
    }
};

/// Resource Record
pub const Record = struct {
    /// Name of the node to which this record pertains
    name: []u8,

    /// Type of RR in numeric form (e.g., 15 for MX RRs)
    typeRR: u16,

    /// Class code
    classCode: u16,

    /// Count of seconds that the RR stays valid (The maximum is 231−1, which is about 68 years)
    ttl: u32,

    /// Length of RDATA field (specified in octets)
    rDataLen: u16,

    /// Additional RR-specific data
    rData: []u8,
};

pub const QName = struct {
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
};

/// QName label
/// Used to specify a single piece of a domain name.
/// Example:
///   test.example.com is three labels:
///   Label   Length   Data
///    0       4        test
///    1       7        example
///    2       3        com
pub const Label = struct {
    allocator: Allocator,
    data: []const u8,

    /// Label header/type
    /// From: https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-10
    const LabelHeader = packed struct(u8) {
        len: u6,
        type: u2,
    };

    /// Create a label from a set of bytes.
    /// We can optionally not return a label to indicate the end of a
    /// label list, e.g. in QName,.
    pub fn from_reader(alloc: Allocator, reader: *Reader) !?Label {
        const header_byte: u8 = reader.takeByte() catch return error.NotEnoughBytes;
        const head: LabelHeader = @bitCast(header_byte);

        if (head.type != 0b00) return error.UnsupportedLabelType;

        // If the length is zero, that's a null termination, marking the
        // end of the label list
        if (head.len == 0) return null;

        const data = reader.readAlloc(alloc, head.len) catch return error.NotEnoughBytes;

        return Label{ .allocator = alloc, .data = data };
    }

    pub fn deinit(self: *Label) void {
        self.allocator.free(self.data);
    }
};

//--------------------------------------------------
// DNS Packet

/// DNS Message
pub const Message = struct {
    allocator: Allocator,
    pub fn init(alloc: Allocator) !Message {
        return Message{ .allocator = alloc };
    }
};

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

//--------------------------------------------------
// Tests

const testing = std.testing;

// Got these from wireguard
const test_query_duckduckgo: []const u8 = &[_]u8{ 0x3e, 0x3c, 0x01, 0x20, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x0a, 0x64, 0x75, 0x63, 0x6b, 0x64, 0x75, 0x63, 0x6b, 0x67, 0x6f, 0x03, 0x63, 0x6f, 0x6d, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x29, 0x04, 0xd0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x0a, 0x00, 0x08, 0x92, 0x84, 0x32, 0xd0, 0xcc, 0x88, 0xdd, 0x29 };

const test_response_duckduckgo: []const u8 = &[_]u8{ 0x3e, 0x3c, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x0a, 0x64, 0x75, 0x63, 0x6b, 0x64, 0x75, 0x63, 0x6b, 0x67, 0x6f, 0x03, 0x63, 0x6f, 0x6d, 0x00, 0x00, 0x01, 0x00, 0x01, 0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x82, 0x00, 0x04, 0x34, 0xfa, 0x2a, 0x9d, 0x00, 0x00, 0x29, 0x04, 0xd0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

test "header bit order" {
    var stream = Reader.fixed(test_query_duckduckgo);
    const header = try Header.from_reader(&stream);

    // Test transaction ID
    try testing.expectEqual(0x3e3c, header.transactionID);

    // Test flags
    try testing.expectEqual(0x2001, @as(u16, @bitCast(header.flags)));
    try testing.expectEqual(false, header.flags.QR);
    try testing.expect(header.flags.OPCODE == .query);
    try testing.expectEqual(false, header.flags.AA);
    try testing.expectEqual(false, header.flags.TC);
    try testing.expectEqual(true, header.flags.RD);
    try testing.expectEqual(false, header.flags.RA);
    try testing.expectEqual(0, header.flags.Z);
    try testing.expectEqual(true, header.flags.AD);
    try testing.expectEqual(false, header.flags.CD);
    try testing.expect(header.flags.RCODE == .noError);

    // Test number counts
    try testing.expectEqual(1, header.numQuestions);
    try testing.expectEqual(0, header.numAnswers);
    try testing.expectEqual(0, header.numAuthRR);
    try testing.expectEqual(1, header.numAddRR);
}

test "qname parsing" {
    const alloc = testing.allocator;

    var stream = Reader.fixed(test_query_duckduckgo);
    // Parse header to make sure reader advances.
    _ = try Header.from_reader(&stream);

    // Parse our question
    var question = try Question.from_reader(alloc, &stream);
    defer question.deinit();

    // Check the easy stuff first
    try testing.expectEqual(0x0001, question.typeRR);
    try testing.expectEqual(0x0001, question.classCode);

    // Make sure we parsed two labels
    const qname = &question.name;
    try testing.expectEqual(2, qname.labels.len);

    // Validate 'duckduckgo' label
    try testing.expectEqual(10, qname.labels[0].data.len);
    try testing.expectEqualStrings("duckduckgo", qname.labels[0].data);

    // Validate 'com' label
    try testing.expectEqual(3, qname.labels[1].data.len);
    try testing.expectEqualStrings("com", qname.labels[1].data);
}
