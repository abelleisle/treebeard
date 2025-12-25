//--------------------------------------------------
// DNS Exports
const codes = @import("core/codes.zig");

pub const Opcode = codes.Opcode;
pub const ResponseCode = codes.ResponseCode;
pub const Type = codes.Type;
pub const QType = codes.QType;
pub const Class = codes.Class;
pub const QClass = codes.QClass;

pub const Message = @import("core/Message.zig");
pub const Header = Message.Header;
pub const Question = @import("core/Question.zig");
pub const Name = @import("core/Name.zig");
pub const Record = @import("core/Record.zig");

//--------------------------------------------------
// Local imports
const std = @import("std");

// Memory
const Allocator = std.mem.Allocator;

//--------------------------------------------------
// DNS Helpers

pub fn buildQuery(allocator: Allocator, query: []const u8, record_type: Type) !Message {
    var name = try Name.fromStr(allocator, query);
    errdefer name.deinit();

    const questions: []Question = try allocator.alloc(Question, 1);
    errdefer {
        for (questions) |*q| q.deinit();
        allocator.free(questions);
    }

    questions[0] = Question{
        .allocator = allocator,
        .class = .IN,
        .type = record_type,
        .name = name,
    };

    const message = Message{
        .allocator = allocator,
        .header = Header.basicQuery(1234),
        .questions = questions,
        .records = try std.ArrayList(Record).initCapacity(allocator, 0),
    };

    return message;
}
