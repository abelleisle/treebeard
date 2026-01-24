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

pub const DNSMemory = @import("pool.zig").DNSMemory;
pub const DNSReader = @import("pool.zig").DNSReader;
pub const DNSWriter = @import("pool.zig").DNSWriter;

//--------------------------------------------------
// Local imports
const std = @import("std");

// Memory
const Allocator = std.mem.Allocator;

//--------------------------------------------------
// DNS Helpers

pub fn buildQuery(memory: *DNSMemory, query: []const u8, record_type: Type) !Message {
    var name = try Name.fromStr(memory, query);
    errdefer name.deinit();

    const question = Question{ .memory = memory, .name = name, .class = .IN, .type = record_type };

    const flags = Header.Flags{ .RD = true, .AD = true };

    var message = Message.init(memory, 1234, flags);
    try message.addQuestion(question);

    return message;
}

//--------------------------------------------------
// Test references
// This ensures all tests in these files are run when executing `zig build test`

test {
    _ = @import("core/Name.zig");
    _ = @import("core/Message.zig");
    _ = @import("core/Question.zig");
    _ = @import("core/Record.zig");
    _ = @import("core/codes.zig");
    _ = @import("pool.zig");
    _ = @import("NameTree.zig");
}
