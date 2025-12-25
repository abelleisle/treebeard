const std = @import("std");

// IO
const io = std.io;
const Writer = io.Writer;
const Reader = io.Reader;

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

//--------------------------------------------------
// DNS Message
const Message = @This();

allocator: Allocator,

/// Message header
header: Header,

/// List of messages
questions: ArrayList(Question),

/// List of records
answers: ArrayList(Record),

/// Creates an empty Message, use `addQuestion`, or `addAnswer` to actually
/// add content to the message.
pub fn init(alloc: Allocator, transactionID: u16, flags: Header.Flags) Message {
    return Message{
        .allocator = alloc,
        .header = Header{
            .transactionID = transactionID,
            .flags = flags,
            .numQuestions = 0,
            .numAnswers = 0,
            .numAuthRR = 0,
            .numAddRR = 0,
        },
        .questions = ArrayList(Question).empty,
        .answers = ArrayList(Record).empty,
    };
}

/// Adds the provided question to our message
pub fn addQuestion(self: *Message, question: Question) !void {
    try self.questions.append(self.allocator, question);
    self.header.numQuestions += 1;
}

/// Adds the provided answer (record) to our message
pub fn addAnswer(self: *Message, answer: Record) !void {
    try self.answers.append(self.allocator, answer);
    self.header.numAnswers += 1;
}

pub fn decode(alloc: Allocator, reader: *Reader) !Message {
    const header = try Header.decode(reader);

    var questions = try parse_questions(alloc, reader, header.numQuestions);
    errdefer {
        for (questions.items) |*q| q.deinit();
        questions.deinit(alloc);
    }

    var answers = try parse_answers(alloc, reader, header.numAnswers);
    errdefer {
        for (answers.items) |*a| a.deinit();
        answers.deinit(alloc);
    }

    return Message{
        .allocator = alloc,
        .header = header,
        .questions = questions,
        .answers = answers,
    };
}

/// Parse questions from message bytes
/// Note: This must be done AFTER parsing the header
fn parse_questions(alloc: Allocator, reader: *Reader, count: u16) !ArrayList(Question) {
    var questions = try ArrayList(Question).initCapacity(alloc, count);
    errdefer {
        for (questions.items) |*q| q.deinit();
        questions.deinit(alloc);
    }

    var i: u16 = 0;
    while (i < count) : (i += 1) {
        const q = try Question.decode(alloc, reader);
        try questions.append(alloc, q);
    }

    return questions;
}

/// Parse answers from message bytes
/// Note: This must be done AFTER parsing the header and questions
fn parse_answers(alloc: Allocator, reader: *Reader, count: u16) !ArrayList(Record) {
    var answers = try ArrayList(Record).initCapacity(alloc, count);
    errdefer {
        for (answers.items) |*a| a.deinit();
        answers.deinit(alloc);
    }

    var i: u16 = 0;
    while (i < count) : (i += 1) {
        const a = try Record.decode(alloc, reader);
        try answers.append(alloc, a);
    }

    return answers;
}

pub fn deinit(self: *Message) void {
    for (self.questions.items) |*q| q.deinit();
    self.questions.deinit(self.allocator);

    for (self.answers.items) |*a| a.deinit();
    self.answers.deinit(self.allocator);
}

pub fn encode(self: *const Message, writer: *Writer) !void {
    try self.header.encode(writer);
    for (self.questions.items) |q| {
        try q.encode(writer);
    }
    for (self.answers.items) |a| {
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
        RCODE: ResponseCode, // u4

        /// Checking Disabled, in a query, indicates that non-verified data is acceptable in a response.
        CD: bool,

        /// Authentic Data, in a response, indicates if the replying DNS server verified the data.
        AD: bool,

        /// Zero, reserved for future use.
        Z: u1 = 0,

        /// Recursion Available, in a response, indicates if the replying DNS server supports recursion.
        RA: bool,

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
    };

    pub fn decode(reader: *Reader) !Header {
        return Header{
            .transactionID = reader.takeInt(u16, .big) catch return error.NotEnoughBytes,
            .flags = @bitCast(reader.takeInt(u16, .big) catch return error.NotEnoughBytes),
            .numQuestions = reader.takeInt(u16, .big) catch return error.NotEnoughBytes,
            .numAnswers = reader.takeInt(u16, .big) catch return error.NotEnoughBytes,
            .numAuthRR = reader.takeInt(u16, .big) catch return error.NotEnoughBytes,
            .numAddRR = reader.takeInt(u16, .big) catch return error.NotEnoughBytes,
        };
    }

    pub fn encode(header: *const Header, writer: *Writer) !void {
        writer.writeInt(u16, header.transactionID, .big) catch return error.NotEnoughBytes;
        writer.writeInt(u16, @bitCast(header.flags), .big) catch return error.NotEnoughBytes;
        writer.writeInt(u16, header.numQuestions, .big) catch return error.NotEnoughBytes;
        writer.writeInt(u16, header.numAnswers, .big) catch return error.NotEnoughBytes;
        writer.writeInt(u16, header.numAuthRR, .big) catch return error.NotEnoughBytes;
        writer.writeInt(u16, header.numAddRR, .big) catch return error.NotEnoughBytes;
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
    var stream = Reader.fixed(t.data.query.duckduckgo);
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
    var stream = Reader.fixed(t.data.query.duckduckgo);
    const header = try Header.decode(&stream);

    // Test various destination header lengths
    inline for (.{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 56 }) |l| {
        var writeBuf = std.mem.zeroes([l]u8);
        var writer = Writer.fixed(&writeBuf);
        if (l < Header.LENGTH) {
            try testing.expectError(error.NotEnoughBytes, header.encode(&writer));
        } else {
            try header.encode(&writer);
        }

        try testing.expectEqualSlices(u8, t.data.query.duckduckgo[0..@min(l, Header.LENGTH)], writer.buffered());
    }
}

test "qname parsing" {
    const alloc = testing.allocator;

    var stream = Reader.fixed(t.data.query.duckduckgo);
    // Parse header to make sure reader advances.
    _ = try Header.decode(&stream);

    // Parse our question
    var question = try Question.decode(alloc, &stream);
    defer question.deinit();

    // Check the easy stuff first
    try testing.expectEqual(0x0001, @intFromEnum(question.type));
    try testing.expectEqual(0x0001, @intFromEnum(question.class));

    // Make sure we parsed two labels
    const qname = &question.name;
    try testing.expectEqual(2, qname.label_count);

    // Make sure we parsed the correct name
    try testing.expectEqualStrings("duckduckgo.com.", qname.name);
}

test "message parse" {
    const alloc = testing.allocator;

    var stream = Reader.fixed(t.data.query.duckduckgo);

    var message = try Message.decode(alloc, &stream);
    defer message.deinit();

    try testing.expectEqual(1, message.header.numQuestions);
    try testing.expectEqual(1, message.questions.items.len);
}

test "basic encode" {
    const Name = @import("Name.zig");
    const allocator = testing.allocator;

    var buf = std.mem.zeroes([512]u8);
    var writer = Writer.fixed(&buf);

    const query = "duckduckgo.com";
    var name = try Name.fromStr(allocator, query);
    errdefer name.deinit();

    const q = Question{
        .allocator = allocator,
        .name = name,
        .type = .A,
        .class = .IN,
    };

    var message = Message.init(allocator, 0x3e3c, Header.Flags{
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

    try testing.expectEqualSlices(u8, t.data.query.duckduckgo_simple, writer.buffered());
}
