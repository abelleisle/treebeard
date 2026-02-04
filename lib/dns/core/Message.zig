const std = @import("std");

// Memory
const Allocator = std.mem.Allocator;

// List
const ArrayList = std.ArrayList;

// Core
const codes = @import("codes.zig");
const ResponseCode = codes.ResponseCode;
const Opcode = codes.Opcode;
const Question = @import("Question.zig");
const Record = @import("Record.zig");
const Additional = @import("Additional.zig");

const treebeard = @import("treebeard");
const DNSMemory = treebeard.DNSMemory;
const DNSReader = treebeard.DNSReader;
const DNSWriter = treebeard.DNSWriter;

//--------------------------------------------------
// DNS Message
const Message = @This();

memory: *DNSMemory,

/// Message header
header: Header,

/// List of messages
question: ?Question,

/// List of records
answers: ArrayList(Record),

/// List of authority records
authority: ArrayList(Record),

/// List of additional records
additional: ArrayList(Additional),

/// Creates an empty Message.
/// Use `addQuestion`, `addAnswer`, `addAuthority`, or `addAdditional`
/// to add content to the message.
pub fn init(memory: *DNSMemory, transactionID: u16, flags: Header.Flags) Message {
    return Message{
        .memory = memory,
        .header = Header{
            .transactionID = transactionID,
            .flags = flags,
            .numQuestions = 0,
            .numAnswers = 0,
            .numAuthRR = 0,
            .numAddRR = 0,
        },
        .question = null,
        .answers = ArrayList(Record).empty,
        .authority = ArrayList(Record).empty,
        .additional = ArrayList(Additional).empty,
    };
}

/// Creates an update (RFC2136) Message for requesting a name update.
/// Use `addQuestion`, `addAnswer`, `addAuthority`, or `addAdditional`
/// to add content to the message.
pub fn updateRequest(memory: *DNSMemory, transactionID: u16) Message {
    return Message{
        .memory = memory,
        .header = Header{
            .transactionID = transactionID,
            .flags = .{
                .QR = false,
                .OPCODE = .update,
                .AA = false,
                .TC = false,
                .RD = false,
                .RA = false,
                .Z = 0,
                .AD = false,
                .CD = false,
                .RCODE = .noError,
            },
            .numQuestions = 0,
            .numAnswers = 0,
            .numAuthRR = 0,
            .numAddRR = 0,
        },
        .question = null,
        .answers = ArrayList(Record).empty,
        .authority = ArrayList(Record).empty,
        .additional = ArrayList(Additional).empty,
    };
}

/// Creates an update (RFC2136) Message for responding to a name update request.
/// Use `addQuestion`, `addAnswer`, `addAuthority`, or `addAdditional`
/// to add content to the message.
pub fn updateResponse(memory: *DNSMemory, transactionID: u16) Message {
    return Message{
        .memory = memory,
        .header = Header{
            .transactionID = transactionID,
            .flags = .{
                .QR = true,
                .OPCODE = .update,
                .AA = false,
                .TC = false,
                .RD = false,
                .RA = false,
                .Z = 0,
                .AD = false,
                .CD = false,
                .RCODE = .noError,
            },
            .numQuestions = 0,
            .numAnswers = 0,
            .numAuthRR = 0,
            .numAddRR = 0,
        },
        .question = null,
        .answers = ArrayList(Record).empty,
        .authority = ArrayList(Record).empty,
        .additional = ArrayList(Additional).empty,
    };
}

/// Is this message an update request/response?
pub inline fn isUpdate(self: *const Message) bool {
    return self.header.flags.OPCODE == .update;
}

/// Adds the provided question to our message
/// Note: When this message is an update, this refers to ZOCOUNT
pub fn addQuestion(self: *Message, question: Question) !void {
    if (self.question != null) {
        if (self.isUpdate()) {
            return error.ZoneAlreadySet;
        } else {
            return error.QuestionAlreadySet;
        }
    }

    self.header.numQuestions = 1;
    self.question = question;
}

/// Adds the provided answer (record) to our message
/// Note: When this message is an update, this refers to PRCOUNT
pub fn addAnswer(self: *Message, answer: Record) !void {
    try self.answers.append(self.memory.alloc(), answer);
    self.header.numAnswers += 1;
}

/// Adds an authority RR to the message
/// Note: When this message is an update, this refers to UPCOUNT
pub fn addAuthority(self: *Message, authority: Record) !void {
    try self.authority.append(self.memory.alloc(), authority);
    self.header.numAuthRR += 1;
}

/// Adds an additional RR to the message (typically TSIG for authentication)
/// Note: When this message is an update, this refers to ADCOUNT
pub fn addAdditional(self: *Message, additional: Additional) !void {
    try self.additional.append(self.memory.alloc(), additional);
    self.header.numAddRR += 1;
}

pub fn decode(reader: *DNSReader) !Message {
    const alloc = reader.memory.alloc();
    const header = try Header.decode(reader);

    const question = if (header.numQuestions > 1)
        return error.TooManyQuestions
    else if (header.numQuestions == 1)
        try Question.decode(reader)
    else
        null;

    var answers = try parse_records(alloc, reader, header.numAnswers);
    errdefer {
        for (answers.items) |*a| a.deinit();
        answers.deinit(alloc);
    }

    var authorities = try parse_records(alloc, reader, header.numAuthRR);
    errdefer {
        for (authorities.items) |*u| u.deinit();
        authorities.deinit(alloc);
    }

    // TODO: Parse additional section (needs Additional.decode)
    const additional = ArrayList(Additional).empty;

    return Message{
        .memory = reader.memory,
        .header = header,
        .question = question,
        .answers = answers,
        .authority = authorities,
        .additional = additional,
    };
}

/// Parse records from message bytes
/// Note: This must be done AFTER parsing the header and questions
fn parse_records(alloc: Allocator, reader: *DNSReader, count: u16) !ArrayList(Record) {
    var answers = try ArrayList(Record).initCapacity(alloc, count);
    errdefer {
        for (answers.items) |*a| a.deinit();
        answers.deinit(alloc);
    }

    var i: u16 = 0;
    while (i < count) : (i += 1) {
        const a = try Record.decode(reader);
        try answers.append(alloc, a);
    }

    return answers;
}

/// Parse answers from message bytes
/// Note: This must be done AFTER parsing the header, questions, and records
fn parse_additional(alloc: Allocator, reader: *DNSReader, count: u16) !ArrayList(Additional) {
    var additional = try ArrayList(Additional).initCapacity(alloc, count);
    errdefer {
        for (additional.items) |*a| a.deinit();
        additional.deinit(alloc);
    }

    var i: u16 = 0;
    while (i < count) : (i += 1) {
        const a = try Additional.decode(reader);
        try additional.append(alloc, a);
    }

    return additional;
}

pub fn deinit(self: *Message) void {
    if (self.question) |*q| q.deinit();

    for (self.answers.items) |*a| a.deinit();
    self.answers.deinit(self.memory.alloc());

    for (self.authority.items) |*a| a.deinit();
    self.authority.deinit(self.memory.alloc());

    for (self.additional.items) |*a| a.deinit();
    self.additional.deinit(self.memory.alloc());
}

pub fn encode(self: *const Message, writer: *DNSWriter) !void {
    try self.header.encode(writer);
    if (self.question) |*q| {
        try q.encode(writer);
    }
    for (self.answers.items) |*a| {
        try a.encode(writer);
    }
    for (self.authority.items) |*a| {
        try a.encode(writer);
    }
    for (self.additional.items) |*a| {
        try a.encode(writer);
    }
}

//--------------------------------------------------
// DNS Header

/// Header included with all DNS messages
pub const Header = packed struct(u96) {
    /// Transaction ID
    transactionID: u16,

    /// DNS flags indicating the message metadata
    flags: Flags,

    /// Number of Questions
    numQuestions: u16,

    /// Number of Answers
    numAnswers: u16,

    /// Number of Authority RRs
    numAuthRR: u16,

    /// Number of Additional RRs
    numAddRR: u16,

    const LENGTH: u8 = 12;

    /// DNS flags indicating the message metadata
    pub const Flags = packed struct(u16) {
        // ---------------
        // Byte 1

        /// Response code, can be NOERROR (0), FORMERR (1, Format error), SERVFAIL (2), NXDOMAIN (3, Nonexistent domain), etc.
        RCODE: ResponseCode = .noError, // u4

        /// Checking Disabled, in a query, indicates that non-verified data is acceptable in a response.
        CD: bool = false,

        /// Authentic Data, in a response, indicates if the replying DNS server verified the data.
        AD: bool = false,

        /// Zero, reserved for future use.
        Z: u1 = 0,

        /// Recursion Available, in a response, indicates if the replying DNS server supports recursion.
        RA: bool = false,

        // ---------------
        // Byte 0

        /// Recursion Desired, indicates if the client means a recursive query.
        RD: bool = false,

        /// TrunCation, indicates that this message was truncated due to excessive length.
        TC: bool = false,

        /// Authoritative Answer, in a response, indicates if the DNS server is authoritative for the queried hostname.
        AA: bool = false,

        /// The type can be QUERY (standard query, 0), IQUERY (inverse query, 1), or STATUS (server status request, 2).
        OPCODE: Opcode = .query, // u4

        /// Indicates if the message is a query (0) or a reply (1).
        QR: bool = false,
    };

    pub fn decode(reader: *DNSReader) !Header {
        const header = Header{
            .transactionID = reader.reader.takeInt(u16, .big) catch return error.NotEnoughBytes,
            .flags = @bitCast(reader.reader.takeInt(u16, .big) catch return error.NotEnoughBytes),
            .numQuestions = reader.reader.takeInt(u16, .big) catch return error.NotEnoughBytes,
            .numAnswers = reader.reader.takeInt(u16, .big) catch return error.NotEnoughBytes,
            .numAuthRR = reader.reader.takeInt(u16, .big) catch return error.NotEnoughBytes,
            .numAddRR = reader.reader.takeInt(u16, .big) catch return error.NotEnoughBytes,
        };

        // Our message is truncated.
        // Since this is the first thing we decode, short circuit our decode
        // process here so we can switch to TCP.
        if (header.flags.TC) {
            return error.TruncatedMessage;
        }

        if (header.flags.OPCODE == .update) {
            // Update requests can only have a single zone specified.
            if (header.numQuestions > 1) {
                return error.ZoneAlreadySet;
            }

            // We these bits have to be 0 in update headers.
            if ((header.flags.AA == true) or
                (header.flags.RD == true) or
                (header.flags.RA == true) or
                (header.flags.Z != 0) or
                (header.flags.AD == true) or
                (header.flags.CD == true))
            {
                return error.InvalidFlagSettings;
            }
        } else {
            if (header.numQuestions > 1) {
                return error.QuestionAlreadySet;
            }
        }

        return header;
    }

    pub fn encode(header: *const Header, writer: *DNSWriter) !void {
        writer.writer.writeInt(u16, header.transactionID, .big) catch return error.NotEnoughBytes;
        writer.writer.writeInt(u16, @bitCast(header.flags), .big) catch return error.NotEnoughBytes;
        writer.writer.writeInt(u16, header.numQuestions, .big) catch return error.NotEnoughBytes;
        writer.writer.writeInt(u16, header.numAnswers, .big) catch return error.NotEnoughBytes;
        writer.writer.writeInt(u16, header.numAuthRR, .big) catch return error.NotEnoughBytes;
        writer.writer.writeInt(u16, header.numAddRR, .big) catch return error.NotEnoughBytes;
    }

    pub fn basicQuery(transactionID: u16) Header {
        return Header{
            .transactionID = transactionID,
            .flags = .{
                .QR = false,
                .OPCODE = .query,
                .AA = false,
                .TC = false,
                .RD = true,
                .RA = false,
                .Z = 0,
                .AD = true,
                .CD = false,
                .RCODE = .noError,
            },
            .numQuestions = 1,
            .numAnswers = 0,
            .numAuthRR = 0,
            .numAddRR = 0,
        };
    }
};

//--------------------------------------------------
// Tests

const testing = std.testing;
const t = @import("testing.zig");

test "header bit order" {
    var pool = try DNSMemory.init();
    defer pool.deinit();

    var stream = try pool.getReader(.{ .fixed = t.data.query.duckduckgo });
    defer stream.deinit();

    const header = try Header.decode(&stream);

    // Test transaction ID
    try testing.expectEqual(0x3e3c, header.transactionID);

    // Test flags
    try testing.expectEqual(0x0120, @as(u16, @bitCast(header.flags)));
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

test "header write bit order" {
    var pool = try DNSMemory.init();
    defer pool.deinit();

    var stream = try pool.getReader(.{ .fixed = t.data.query.duckduckgo });
    defer stream.deinit();

    const header = try Header.decode(&stream);

    // Test various destination header lengths
    inline for (.{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 56 }) |l| {
        var writeBuf = std.mem.zeroes([l]u8);
        var writer = try pool.getWriter(.{ .fixed = &writeBuf });
        defer writer.deinit();

        if (l < Header.LENGTH) {
            try testing.expectError(error.NotEnoughBytes, header.encode(&writer));
        } else {
            try header.encode(&writer);
        }

        try testing.expectEqualSlices(u8, t.data.query.duckduckgo[0..@min(l, Header.LENGTH)], writer.writer.buffered());
    }
}

test "qname parsing" {
    var pool = try DNSMemory.init();
    defer pool.deinit();

    var stream = try pool.getReader(.{ .fixed = t.data.query.duckduckgo });
    defer stream.deinit();
    // Parse header to make sure reader advances.
    _ = try Header.decode(&stream);

    // Parse our question
    var question = try Question.decode(&stream);
    defer question.deinit();

    // Check the easy stuff first
    try testing.expectEqual(0x0001, @intFromEnum(question.type));
    try testing.expectEqual(0x0001, @intFromEnum(question.class));

    // Make sure we parsed two labels
    const qname = &question.name;
    try testing.expectEqual(2, qname.labelCount());

    const buf = try std.fmt.allocPrint(testing.allocator, "{f}", .{qname});
    defer testing.allocator.free(buf);

    try testing.expectEqualStrings("duckduckgo.com.", buf);
}

test "message parse" {
    var pool = try DNSMemory.init();
    defer pool.deinit();

    var stream = try pool.getReader(.{ .fixed = t.data.query.duckduckgo });
    defer stream.deinit();

    var message = try Message.decode(&stream);
    defer message.deinit();

    try testing.expectEqual(1, message.header.numQuestions);
    try testing.expect(message.question != null);
}

test "basic encode" {
    const Name = @import("Name.zig");

    var pool = try DNSMemory.init();
    defer pool.deinit();

    var buf = std.mem.zeroes([512]u8);
    var writer = try pool.getWriter(.{ .fixed = &buf });
    defer writer.deinit();

    const query = "duckduckgo.com";
    var name = try Name.fromStr(query);
    errdefer name.deinit();

    const q = Question{
        .memory = &pool,
        .name = name,
        .type = .A,
        .class = .IN,
    };

    var message = Message.init(&pool, 0x3e3c, Header.Flags{
        .QR = false,
        .OPCODE = .query,
        .AA = false,
        .TC = false,
        .RD = true,
        .RA = false,
        .Z = 0,
        .AD = true,
        .CD = false,
        .RCODE = .noError,
    });
    defer message.deinit();

    try message.addQuestion(q);

    try message.encode(&writer);

    try testing.expectEqualSlices(u8, t.data.query.duckduckgo_simple, writer.writer.buffered());
}

test "updateRequest - creates correct flags" {
    var pool = try DNSMemory.init();
    defer pool.deinit();

    var message = Message.updateRequest(&pool, 0xABCD);
    defer message.deinit();

    try testing.expectEqual(@as(u16, 0xABCD), message.header.transactionID);
    try testing.expectEqual(false, message.header.flags.QR);
    try testing.expect(message.header.flags.OPCODE == .update);
    try testing.expectEqual(false, message.header.flags.AA);
    try testing.expectEqual(false, message.header.flags.TC);
    try testing.expectEqual(false, message.header.flags.RD);
    try testing.expectEqual(false, message.header.flags.RA);
    try testing.expectEqual(@as(u1, 0), message.header.flags.Z);
    try testing.expectEqual(false, message.header.flags.AD);
    try testing.expectEqual(false, message.header.flags.CD);
    try testing.expect(message.header.flags.RCODE == .noError);
    try testing.expectEqual(true, message.isUpdate());
}

test "updateResponse - creates correct flags" {
    var pool = try DNSMemory.init();
    defer pool.deinit();

    var message = Message.updateResponse(&pool, 0x1234);
    defer message.deinit();

    try testing.expectEqual(@as(u16, 0x1234), message.header.transactionID);
    try testing.expectEqual(true, message.header.flags.QR);
    try testing.expect(message.header.flags.OPCODE == .update);
    try testing.expect(message.header.flags.RCODE == .noError);
    try testing.expectEqual(true, message.isUpdate());
}

test "isUpdate - returns false for regular query" {
    var pool = try DNSMemory.init();
    defer pool.deinit();

    var message = Message.init(&pool, 0x1234, .{});
    defer message.deinit();

    try testing.expectEqual(false, message.isUpdate());
}

test "addQuestion - update rejects multiple zones" {
    const Name = @import("Name.zig");

    var pool = try DNSMemory.init();
    defer pool.deinit();

    var message = Message.updateRequest(&pool, 0x1234);
    defer message.deinit();

    const zone1 = Question{
        .memory = &pool,
        .name = try Name.fromStr("example.com."),
        .type = .SOA,
        .class = .IN,
    };

    var zone2 = Question{
        .memory = &pool,
        .name = try Name.fromStr("other.com."),
        .type = .SOA,
        .class = .IN,
    };
    defer zone2.deinit();

    try message.addQuestion(zone1);
    try testing.expectError(error.ZoneAlreadySet, message.addQuestion(zone2));
}

test "addQuestion - regular query bans multiple questions" {
    const Name = @import("Name.zig");

    var pool = try DNSMemory.init();
    defer pool.deinit();

    var message = Message.init(&pool, 0x1234, .{});
    defer message.deinit();

    const q1 = Question{
        .memory = &pool,
        .name = try Name.fromStr("example.com."),
        .type = .A,
        .class = .IN,
    };

    const q2 = Question{
        .memory = &pool,
        .name = try Name.fromStr("other.com."),
        .type = .A,
        .class = .IN,
    };

    try message.addQuestion(q1);
    try testing.expectEqual(error.QuestionAlreadySet, message.addQuestion(q2));
    try testing.expectEqual(@as(u16, 1), message.header.numQuestions);
}

test "header decode - update with invalid AA flag" {
    var pool = try DNSMemory.init();
    defer pool.deinit();

    // UPDATE header with AA=1 (invalid for UPDATE)
    const invalid_header = [_]u8{
        0x12, 0x34, // Transaction ID
        0x2C, 0x00, // Flags: QR=0, OPCODE=5, AA=1 (invalid)
        0x00, 0x01, // ZOCOUNT: 1
        0x00, 0x00, // PRCOUNT: 0
        0x00, 0x00, // UPCOUNT: 0
        0x00, 0x00, // ADCOUNT: 0
    };

    var reader = try pool.getReader(.{ .fixed = &invalid_header });
    defer reader.deinit();

    try testing.expectError(error.InvalidFlagSettings, Header.decode(&reader));
}

test "header decode - update with invalid RD flag" {
    var pool = try DNSMemory.init();
    defer pool.deinit();

    // UPDATE header with RD=1 (invalid for UPDATE)
    const invalid_header = [_]u8{
        0x12, 0x34, // Transaction ID
        0x29, 0x00, // Flags: QR=0, OPCODE=5, RD=1 (invalid)
        0x00, 0x01, // ZOCOUNT: 1
        0x00, 0x00, // PRCOUNT: 0
        0x00, 0x00, // UPCOUNT: 0
        0x00, 0x00, // ADCOUNT: 0
    };

    var reader = try pool.getReader(.{ .fixed = &invalid_header });
    defer reader.deinit();

    try testing.expectError(error.InvalidFlagSettings, Header.decode(&reader));
}

test "header decode - update with invalid AD flag" {
    var pool = try DNSMemory.init();
    defer pool.deinit();

    // UPDATE header with AD=1 (invalid for UPDATE)
    const invalid_header = [_]u8{
        0x12, 0x34, // Transaction ID
        0x28, 0x20, // Flags: QR=0, OPCODE=5, AD=1 (invalid)
        0x00, 0x01, // ZOCOUNT: 1
        0x00, 0x00, // PRCOUNT: 0
        0x00, 0x00, // UPCOUNT: 0
        0x00, 0x00, // ADCOUNT: 0
    };

    var reader = try pool.getReader(.{ .fixed = &invalid_header });
    defer reader.deinit();

    try testing.expectError(error.InvalidFlagSettings, Header.decode(&reader));
}

test "header decode - update with multiple zones" {
    var pool = try DNSMemory.init();
    defer pool.deinit();

    // UPDATE header with ZOCOUNT=2 (invalid, must be 1)
    const invalid_header = [_]u8{
        0x12, 0x34, // Transaction ID
        0x28, 0x00, // Flags: QR=0, OPCODE=5
        0x00, 0x02, // ZOCOUNT: 2 (invalid)
        0x00, 0x00, // PRCOUNT: 0
        0x00, 0x00, // UPCOUNT: 0
        0x00, 0x00, // ADCOUNT: 0
    };

    var reader = try pool.getReader(.{ .fixed = &invalid_header });
    defer reader.deinit();

    try testing.expectError(error.ZoneAlreadySet, Header.decode(&reader));
}

test "header decode - truncated message" {
    var pool = try DNSMemory.init();
    defer pool.deinit();

    // Header with TC=1
    const truncated_header = [_]u8{
        0x12, 0x34, // Transaction ID
        0x02, 0x00, // Flags: TC=1
        0x00, 0x01, // numQuestions: 1
        0x00, 0x00, // numAnswers: 0
        0x00, 0x00, // numAuthRR: 0
        0x00, 0x00, // numAddRR: 0
    };

    var reader = try pool.getReader(.{ .fixed = &truncated_header });
    defer reader.deinit();

    try testing.expectError(error.TruncatedMessage, Header.decode(&reader));
}

test "header decode - valid update header" {
    var pool = try DNSMemory.init();
    defer pool.deinit();

    // Valid UPDATE request header
    const valid_header = [_]u8{
        0xAB, 0xCD, // Transaction ID
        0x28, 0x00, // Flags: QR=0, OPCODE=5 (UPDATE)
        0x00, 0x01, // ZOCOUNT: 1
        0x00, 0x02, // PRCOUNT: 2
        0x00, 0x03, // UPCOUNT: 3
        0x00, 0x04, // ADCOUNT: 4
    };

    var reader = try pool.getReader(.{ .fixed = &valid_header });
    defer reader.deinit();

    const header = try Header.decode(&reader);

    try testing.expectEqual(@as(u16, 0xABCD), header.transactionID);
    try testing.expect(header.flags.OPCODE == .update);
    try testing.expectEqual(@as(u16, 1), header.numQuestions);
    try testing.expectEqual(@as(u16, 2), header.numAnswers);
    try testing.expectEqual(@as(u16, 3), header.numAuthRR);
    try testing.expectEqual(@as(u16, 4), header.numAddRR);
}

test "header decode - valid update response" {
    var pool = try DNSMemory.init();
    defer pool.deinit();

    // Valid UPDATE response header with RCODE
    const valid_header = [_]u8{
        0xAB, 0xCD, // Transaction ID
        0xA8, 0x05, // Flags: QR=1, OPCODE=5, RCODE=5 (REFUSED)
        0x00, 0x01, // ZOCOUNT: 1
        0x00, 0x00, // PRCOUNT: 0
        0x00, 0x00, // UPCOUNT: 0
        0x00, 0x00, // ADCOUNT: 0
    };

    var reader = try pool.getReader(.{ .fixed = &valid_header });
    defer reader.deinit();

    const header = try Header.decode(&reader);

    try testing.expectEqual(true, header.flags.QR);
    try testing.expect(header.flags.OPCODE == .update);
    try testing.expect(header.flags.RCODE == .refused);
}

test "addAuthority - adds authority RR" {
    const Name = @import("Name.zig");

    var pool = try DNSMemory.init();
    defer pool.deinit();

    var message = Message.updateRequest(&pool, 0x1234);
    defer message.deinit();

    const record = Record{
        .memory = &pool,
        .name = try Name.fromStr("test.example.com."),
        .type = .A,
        .class = .IN,
        .ttl = 3600,
        .rdata = .{ .A = .{ 1, 2, 3, 4 } },
    };

    try message.addAuthority(record);

    try testing.expectEqual(@as(u16, 1), message.header.numAuthRR);
    try testing.expectEqual(@as(usize, 1), message.authority.items.len);
}

test "encode/decode round trip - update message" {
    const Name = @import("Name.zig");

    var pool = try DNSMemory.init();
    defer pool.deinit();

    // Create UPDATE request
    var original = Message.updateRequest(&pool, 0x5678);
    defer original.deinit();

    // Add zone
    const zone = Question{
        .memory = &pool,
        .name = try Name.fromStr("example.com."),
        .type = .SOA,
        .class = .IN,
    };
    try original.addQuestion(zone);

    // Add update RR
    const record = Record{
        .memory = &pool,
        .name = try Name.fromStr("test.example.com."),
        .type = .A,
        .class = .IN,
        .ttl = 3600,
        .rdata = .{ .A = .{ 10, 20, 30, 40 } },
    };
    try original.addAuthority(record);

    // Encode
    var buf: [512]u8 = undefined;
    var writer = try pool.getWriter(.{ .fixed = &buf });
    defer writer.deinit();

    try original.encode(&writer);

    // Decode
    const encoded = writer.writer.buffered();
    var reader = try pool.getReader(.{ .fixed = encoded });
    defer reader.deinit();

    var decoded = try Message.decode(&reader);
    defer decoded.deinit();

    // Verify
    try testing.expectEqual(original.header.transactionID, decoded.header.transactionID);
    try testing.expectEqual(@as(u16, @bitCast(original.header.flags)), @as(u16, @bitCast(decoded.header.flags)));
    try testing.expectEqual(original.header.numQuestions, decoded.header.numQuestions);
    try testing.expectEqual(original.header.numAuthRR, decoded.header.numAuthRR);
    try testing.expectEqual(original.question, decoded.question);
    try testing.expectEqual(original.authority.items.len, decoded.authority.items.len);
}

test "update flags bit layout - OPCODE position" {
    // Verify OPCODE=5 (UPDATE) is correctly positioned
    // UPDATE opcode should produce 0x28 in the high byte
    const flags = Header.Flags{
        .QR = false,
        .OPCODE = .update,
    };

    const flagsInt: u16 = @bitCast(flags);
    try testing.expectEqual(@as(u16, 0x2800), flagsInt);
}

test "update flags bit layout - response with NOTAUTH" {
    // Response with NOTAUTH error: QR=1, OPCODE=5, RCODE=9
    const flags = Header.Flags{
        .QR = true,
        .OPCODE = .update,
        .RCODE = .notAuth,
    };

    const flagsInt: u16 = @bitCast(flags);
    try testing.expectEqual(@as(u16, 0xA809), flagsInt);
}
