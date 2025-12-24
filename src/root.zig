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
pub const QName = @import("core/QName.zig");

//--------------------------------------------------
// Local imports
const std = @import("std");

// Memory
const Allocator = std.mem.Allocator;

//--------------------------------------------------
// DNS Helpers

pub fn buildQuery(allocator: Allocator, query: []const u8, record_type: Type) !Message {
    var qname = try QName.from_str(allocator, query);
    errdefer qname.deinit();

    const questions: []Question = try allocator.alloc(Question, 1);
    errdefer {
        for (questions) |q| q.deinit();
        allocator.free(questions);
    }

    questions[0] = Question{
        .allocator = allocator,
        .class = .IN,
        .type = record_type,
        .name = qname,
    };

    const message = Message{
        .allocator = allocator,
        .header = Header.basicQuery(1234),
        .questions = questions,
    };

    return message;
}
