const std = @import("std");

// IO
const io = std.io;
const Reader = std.io.Reader;
const Writer = std.io.Writer;

// Memory
const Allocator = std.mem.Allocator;

//--------------------------------------------------
// DNS Name Type

const Name = @This();

const MAX_NAME_BUFFER = 255; // Max buffer length
const MAX_NAME_LENGTH = 253; // Max displayable name length storable in a buffer
const MAX_LABEL_LENGTH: u8 = 63; // Max length of single label

allocator: Allocator,

name: []u8,

/// Label header/type
/// From: https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-10
const LabelHeader = packed struct(u8) {
    len: u6,
    type: u2,
};

pub fn decode(allocator: Allocator, reader: *Reader) !Name {
    const len = try getLengthFromBuffer(reader);

    const buf = try allocator.alloc(u8, len);
    errdefer allocator.free(buf);

    try getStrFromBuffer(reader, buf);

    return Name{
        .allocator = allocator,
        .name = buf,
    };
}

fn getLengthFromBuffer(reader: *Reader) !usize {
    var total: usize = 0;

    const buffer = reader.buffered();
    while ((total < MAX_NAME_BUFFER) and (total < buffer.len)) {
        const header: LabelHeader = @bitCast(buffer[total]);

        switch (header.type) {
            // Standard
            0b00 => {
                const length = header.len;
                if (length == 0) {
                    return total;
                } else if (length > 63) {
                    return error.LabelTooLong;
                } else {
                    total += (1 + length);
                }
            },
            // Pointer
            0b11 => return error.UnsupportedLabelType,
            // Reserved (unused as of now)
            else => return error.InvalidLabelHeader,
        }
    }

    return error.NameTooLong;
}

fn getStrFromBuffer(reader: *Reader, buffer: []u8) !void {
    var offset: usize = 0;

    while ((offset < MAX_NAME_BUFFER) and (offset < buffer.len)) {
        const header_byte = try reader.takeByte();
        const header: LabelHeader = @bitCast(header_byte);

        switch (header.type) {
            // Standard
            0b00 => {
                const length = header.len;
                if (length == 0) {
                    buffer[offset] = '.';
                    return;
                } else if (length > 63) {
                    return error.LabelTooLong;
                } else {
                    const label = try reader.take(length);
                    if (offset != 0) {
                        buffer[offset] = '.';
                        offset += 1;
                    }

                    @memcpy(buffer[offset .. offset + length], label);
                    offset += length;
                }
            },
            // Pointer
            0b11 => return error.UnsupportedLabelType,
            // Reserved (unused as of now)
            else => return error.InvalidLabelHeader,
        }
    }

    return error.NameTooLong;
}

pub fn deinit(self: *Name) void {
    self.allocator.free(self.name);
}

//--------------------------------------------------
// Tests

const testing = std.testing;
const t = @import("testing.zig");

test "length decode" {
    var reader = Reader.fixed(t.data.labels.duckduckgo.encoded);

    const length = try getLengthFromBuffer(&reader);
    try testing.expectEqual(15, length);
}

test "basic decode" {
    const alloc = testing.allocator;

    var reader = Reader.fixed(t.data.labels.duckduckgo.encoded);

    var name = try Name.decode(alloc, &reader);
    defer name.deinit();

    try testing.expectEqualStrings(t.data.labels.duckduckgo.decoded, name.name);
    try testing.expectEqual(t.data.labels.duckduckgo.decoded.len, name.name.len);
}
