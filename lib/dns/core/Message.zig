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

const treebeard = @import("treebeard");
const Context = treebeard.Context;
const DNSWriter = treebeard.DNSWriter;

//--------------------------------------------------
// DNS Message
const Message = @This();

ctx: *Context,

/// Message header
header: Header,

/// List of messages
questions: ArrayList(Question),

/// List of records
answers: ArrayList(Record),

/// Creates an empty Message, use `addQuestion`, or `addAnswer` to actually
/// add content to the message.
pub fn init(ctx: *Context, transactionID: u16, flags: Header.Flags) Message {
    return Message{
        .ctx = ctx,
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
    try self.questions.append(self.ctx.alloc(), question);
    self.header.numQuestions += 1;
}

/// Adds the provided answer (record) to our message
pub fn addAnswer(self: *Message, answer: Record) !void {
    try self.answers.append(self.ctx.alloc(), answer);
    self.header.numAnswers += 1;
}

pub fn decode(ctx: *Context) !Message {
    const alloc = ctx.alloc();
    const header = try Header.decode(ctx);

    var questions = try parse_questions(alloc, ctx, header.numQuestions);
    errdefer {
        for (questions.items) |*q| q.deinit();
        questions.deinit(alloc);
    }

    var answers = try parse_answers(alloc, ctx, header.numAnswers);
    errdefer {
        for (answers.items) |*a| a.deinit();
        answers.deinit(alloc);
    }

    return Message{
        .ctx = ctx,
        .header = header,
        .questions = questions,
        .answers = answers,
    };
}

/// Parse questions from message bytes
/// Note: This must be done AFTER parsing the header
fn parse_questions(alloc: Allocator, ctx: *Context, count: u16) !ArrayList(Question) {
    var questions = try ArrayList(Question).initCapacity(alloc, count);
    errdefer {
        for (questions.items) |*q| q.deinit();
        questions.deinit(alloc);
    }

    var i: u16 = 0;
    while (i < count) : (i += 1) {
        const q = try Question.decode(ctx);
        try questions.append(alloc, q);
    }

    return questions;
}

/// Parse answers from message bytes
/// Note: This must be done AFTER parsing the header and questions
fn parse_answers(alloc: Allocator, ctx: *Context, count: u16) !ArrayList(Record) {
    var answers = try ArrayList(Record).initCapacity(alloc, count);
    errdefer {
        for (answers.items) |*a| a.deinit();
        answers.deinit(alloc);
    }

    var i: u16 = 0;
    while (i < count) : (i += 1) {
        const a = try Record.decode(ctx);
        try answers.append(alloc, a);
    }

    return answers;
}

pub fn deinit(self: *Message) void {
    for (self.questions.items) |*q| q.deinit();
    self.questions.deinit(self.ctx.alloc());

    for (self.answers.items) |*a| a.deinit();
    self.answers.deinit(self.ctx.alloc());
}

pub fn encode(self: *const Message, writer: *DNSWriter) !void {
    try self.header.encode(writer);
    for (self.questions.items) |*q| {
        try q.encode(writer);
    }
    for (self.answers.items) |*a| {
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

    pub fn decode(ctx: *Context) !Header {
        const header = Header{
            .transactionID = ctx.reader.takeInt(u16, .big) catch return error.NotEnoughBytes,
            .flags = @bitCast(ctx.reader.takeInt(u16, .big) catch return error.NotEnoughBytes),
            .numQuestions = ctx.reader.takeInt(u16, .big) catch return error.NotEnoughBytes,
            .numAnswers = ctx.reader.takeInt(u16, .big) catch return error.NotEnoughBytes,
            .numAuthRR = ctx.reader.takeInt(u16, .big) catch return error.NotEnoughBytes,
            .numAddRR = ctx.reader.takeInt(u16, .big) catch return error.NotEnoughBytes,
        };

        if (header.flags.TC) {
            return error.TruncatedMessage;
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
const DNSMemory = treebeard.DNSMemory;

test "header bit order" {
    var tc = try t.TestContext.init(t.data.query.duckduckgo);
    defer tc.deinit();

    const header = try Header.decode(&tc.ctx);

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
    var tc = try t.TestContext.init(t.data.query.duckduckgo);
    defer tc.deinit();

    const header = try Header.decode(&tc.ctx);

    // Test various destination header lengths
    inline for (.{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 56 }) |l| {
        var writeBuf = std.mem.zeroes([l]u8);
        var writer = try tc.pool.getWriter(.{ .fixed = &writeBuf });
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
    var tc = try t.TestContext.init(t.data.query.duckduckgo);
    defer tc.deinit();

    // Parse header to make sure reader advances.
    _ = try Header.decode(&tc.ctx);

    // Parse our question
    var question = try Question.decode(&tc.ctx);
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

    var ctx = try Context.requestFromWireBuf(&pool, t.data.query.duckduckgo);
    defer ctx.deinit();

    var message = try Message.decode(&ctx);
    defer message.deinit();

    try testing.expectEqual(1, message.header.numQuestions);
    try testing.expectEqual(1, message.questions.items.len);
}

test "basic encode" {
    const Name = @import("Name.zig");

    var pool = try DNSMemory.init();
    defer pool.deinit();

    var ctx = try Context.requestFromWireBuf(&pool, &[_]u8{});
    defer ctx.deinit();

    var buf = std.mem.zeroes([512]u8);
    var writer = try pool.getWriter(.{ .fixed = &buf });
    defer writer.deinit();

    const query = "duckduckgo.com";
    var name = try Name.fromStr(query);
    errdefer name.deinit();

    const q = Question{
        .name = name,
        .type = .A,
        .class = .IN,
    };

    var message = Message.init(&ctx, 0x3e3c, Header.Flags{
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
