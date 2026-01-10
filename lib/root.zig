//--------------------------------------------------
// DNS Exports
const codes = @import("dns/codes.zig");

pub const Opcode = codes.Opcode;
pub const ResponseCode = codes.ResponseCode;
pub const Type = codes.Type;
pub const QType = codes.QType;
pub const Class = codes.Class;
pub const QClass = codes.QClass;

pub const Message = @import("dns/Message.zig");
pub const Header = Message.Header;
pub const Question = @import("dns/Question.zig");
pub const Name = @import("dns/Name.zig");
pub const Record = @import("dns/Record.zig");

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
    _ = @import("dns/Name.zig");
    _ = @import("dns/Message.zig");
    _ = @import("dns/Question.zig");
    _ = @import("dns/Record.zig");
    _ = @import("dns/codes.zig");
    _ = @import("pool.zig");
    _ = @import("NameTree.zig");
}
