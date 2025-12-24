const std = @import("std");

// IO
const io = std.io;
const Writer = io.Writer;
const Reader = io.Reader;

// Memory
const Allocator = std.mem.Allocator;

// Core
const codes = @import("codes.zig");
const ResponseCode = codes.ResponseCode;
const Opcode = codes.Opcode;
const Question = @import("Question.zig");

//--------------------------------------------------
// DNS Message
const Message = @This();

allocator: Allocator,

/// Message header
header: Header,

/// List of messages
questions: []Question,

pub fn from_reader(alloc: Allocator, reader: *Reader) !Message {
    const header = try Header.from_reader(reader);
    const questions = try parse_questions(alloc, reader, header.numQuestions);
    errdefer alloc.free(questions);

    return Message{ .allocator = alloc, .header = header, .questions = questions };
}

/// Parse questions from message bytes
/// Note: This must be done AFTER parsing the header
fn parse_questions(alloc: Allocator, reader: *Reader, count: u16) ![]Question {
    var questions: []Question = try alloc.alloc(Question, count);
    errdefer {
        for (questions) |*q| {
            q.deinit();
        }
        alloc.free(questions);
    }

    var i: u16 = 0;
    while (i < count) : (i += 1) {
        questions[i] = try Question.from_reader(alloc, reader);
    }

    return questions;
}

pub fn deinit(self: *Message) void {
    for (self.questions) |*q| {
        q.deinit();
    }
    self.allocator.free(self.questions);
}

//--------------------------------------------------
// DNS Header

/// Header included with all DNS messages
pub const Header = packed struct(u96) {
    /// Transaction ID
    transactionID: u16,

    /// DNS flags indicating the message metadata
    flags: packed struct(u16) {
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
    },

    /// Number of Questions
    numQuestions: u16,

    /// Number of Answers
    numAnswers: u16,

    /// Number of Authority RRs
    numAuthRR: u16,

    /// Number of Additional RRs
    numAddRR: u16,

    const LENGTH: u8 = 12;

    pub fn from_reader(reader: *Reader) !Header {
        // zig fmt: off
        return Header{
            .transactionID = reader.takeInt(u16, .big) catch return error.NotEnoughBytes,
            .flags = @bitCast(reader.takeInt(u16, .big) catch return error.NotEnoughBytes),
            .numQuestions = reader.takeInt(u16, .big) catch return error.NotEnoughBytes,
            .numAnswers = reader.takeInt(u16, .big) catch return error.NotEnoughBytes,
            .numAuthRR = reader.takeInt(u16, .big) catch return error.NotEnoughBytes,
            .numAddRR = reader.takeInt(u16, .big) catch return error.NotEnoughBytes
        };
        // zig fmt: on
    }

    pub fn write(header: *const Header, writer: *Writer) !void {
        writer.writeInt(u16, header.transactionID, .big) catch return error.NotEnoughBytes;
        writer.writeInt(u16, @bitCast(header.flags), .big) catch return error.NotEnoughBytes;
        writer.writeInt(u16, header.numQuestions, .big) catch return error.NotEnoughBytes;
        writer.writeInt(u16, header.numAnswers, .big) catch return error.NotEnoughBytes;
        writer.writeInt(u16, header.numAuthRR, .big) catch return error.NotEnoughBytes;
        writer.writeInt(u16, header.numAddRR, .big) catch return error.NotEnoughBytes;
    }
};

//--------------------------------------------------
// Tests

const testing = std.testing;
const t = @import("testing.zig");

test "header bit order" {
    var stream = Reader.fixed(t.data.query.duckduckgo);
    const header = try Header.from_reader(&stream);

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
    const header = try Header.from_reader(&stream);

    // Test various destination header lengths
    inline for (.{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 56 }) |l| {
        var writeBuf = std.mem.zeroes([l]u8);
        var writer = Writer.fixed(&writeBuf);
        if (l < Header.LENGTH) {
            try testing.expectError(error.NotEnoughBytes, header.write(&writer));
        } else {
            try header.write(&writer);
        }

        try testing.expectEqualSlices(u8, t.data.query.duckduckgo[0..@min(l, Header.LENGTH)], writer.buffered());
    }
}

test "qname parsing" {
    const alloc = testing.allocator;

    var stream = Reader.fixed(t.data.query.duckduckgo);
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

test "message parse" {
    const alloc = testing.allocator;

    var stream = Reader.fixed(t.data.query.duckduckgo);

    var message = try Message.from_reader(alloc, &stream);
    defer message.deinit();

    try testing.expectEqual(1, message.header.numQuestions);
    try testing.expectEqual(1, message.questions.len);
}
