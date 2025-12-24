const std = @import("std");

// IO
const io = std.io;
const Reader = io.Reader;
const Writer = io.Writer;

// Memory
const Allocator = std.mem.Allocator;

//--------------------------------------------------
// DNS Label Type

/// QName label
/// Used to specify a single piece of a domain name.
/// Example:
///   test.example.com is three labels:
///   Label   Length   Data
///    0       4        test
///    1       7        example
///    2       3        com
const Label = @This();
allocator: Allocator,
data: []const u8,

pub const MAX_LEN: u8 = 63;

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

pub fn encode(self: *const Label, writer: *Writer) !void {
    const header = LabelHeader{
        .type = 0,
        .len = @as(u6, @intCast(self.data.len)),
    };

    try writer.writeInt(u8, @bitCast(header), .big);
    const writeLen = try writer.write(self.data);
    if (writeLen != self.data.len) {
        return error.NotEnoughBytes;
    }
}
