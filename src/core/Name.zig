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
label_count: usize,

/// Label header/type
/// From: https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-10
const LabelHeader = packed struct(u8) {
    len: u6,
    type: u2,
};

/// Create an encoded DNS name from human readable string
pub fn fromStr(allocator: Allocator, domain: []const u8) !Name {
    const has_root = domain.len > 0 and domain[domain.len - 1] == '.';
    const final_len = domain.len + @intFromBool(!has_root);

    if (final_len > MAX_NAME_LENGTH) {
        return error.NameTooLong;
    }

    const buf = try allocator.alloc(u8, final_len);
    @memcpy(buf[0..domain.len], domain);

    if (!has_root) {
        buf[domain.len] = '.';
    }

    // Count labels (excluding empty root label)
    var count: usize = 0;
    var iter = std.mem.splitScalar(u8, buf, '.');
    while (iter.next()) |label| {
        if (label.len > 0) {
            count += 1;
        }
    }

    return Name{
        .allocator = allocator,
        .name = buf,
        .label_count = count,
    };
}

/// Given an encoded DNS name buffer, decode it to a human readable version.
pub fn decode(allocator: Allocator, reader: *Reader) !Name {
    const info = try getLengthFromBuffer(reader);

    const buf = try allocator.alloc(u8, info.bytes);
    errdefer allocator.free(buf);

    try getStrFromBuffer(reader, buf);

    return Name{
        .allocator = allocator,
        .name = buf,
        .label_count = info.label_count,
    };
}

/// Encodes the provided name following the DNS NAME encoding spec
pub fn encode(self: *const Name, writer: *Writer) !void {
    var iter = std.mem.splitScalar(u8, self.name, '.');
    while (iter.next()) |label| {
        if (label.len > MAX_LABEL_LENGTH) return error.LabelTooLong;

        try writer.writeInt(u8, @intCast(label.len), .big);
        const written_len = try writer.write(label);
        if (written_len != label.len) {
            return error.NotEnoughBytes;
        }
    }
}

const NameInfo = struct {
    bytes: usize,
    label_count: usize,
};

/// Get the length and label count of the provided name without consuming the buffer.
/// This can be used to determine the buffer length required for `getStrFromBuffer`.
fn getLengthFromBuffer(reader: *const Reader) !NameInfo {
    const buffer = reader.buffer; // Get the raw response
    var offset: usize = reader.seek;
    var total: usize = 0;
    var labels: usize = 0;
    var jumps: usize = 0; // Total number of pointer jumps

    const end = @min(reader.end, buffer.len);

    while ((total < MAX_NAME_BUFFER) and (offset < end) and (jumps < 10)) {
        const header: LabelHeader = @bitCast(buffer[offset]);

        switch (header.type) {
            // Standard Label
            0b00 => {
                const length = header.len;
                if (length == 0) {
                    return .{ .bytes = total, .label_count = labels };
                } else if (length > 63) {
                    return error.LabelTooLong;
                } else {
                    offset += (1 + length);
                    total += (1 + length); // Add label + '.' sep
                    labels += 1;
                }
            },
            // Pointer
            0b11 => {
                if (offset + 1 > buffer.len) return error.InvalidName;
                const pointer_low: u16 = buffer[offset + 1];
                const pointer_high: u16 = header.len;
                const pointer: u16 = (pointer_high << 8) | pointer_low;
                if (pointer > offset) return error.InvalidPointerAddress;
                offset = pointer;
                jumps += 1;
            },
            // Reserved (unused as of now)
            else => return error.InvalidLabelHeader,
        }
    }

    return error.NameTooLong;
}

/// Get the human readable domain name from the encoded buffer.
/// The resulting string will be placed in `out`.
fn getStrFromBuffer(reader: *Reader, out: []u8) !void {
    const buffer = reader.buffer;
    const end = @min(buffer.len, reader.end);

    var parse_offset: usize = reader.seek; // Follows pointers
    var reader_offset: usize = reader.seek; // Tracks read progress
    var write_pos: usize = 0;
    var jumps: usize = 0;

    while ((write_pos < MAX_NAME_BUFFER) and (parse_offset < end) and (jumps < 10)) {
        const header: LabelHeader = @bitCast(buffer[parse_offset]);

        // Only take if we're still following a non-pointer name
        // Note: we want to take this byte early in the case we have
        //       to exit later in the function due to a parsing error.
        if (parse_offset == reader_offset) {
            _ = try reader.take(1);
        }

        switch (header.type) {
            // Standard label
            0b00 => {
                const length = header.len;
                if (length == 0) {
                    return;
                } else if (length > 63) {
                    return error.LabelTooLong;
                } else {
                    // Copy label data into output
                    @memcpy(out[write_pos .. write_pos + length], buffer[parse_offset + 1 .. parse_offset + 1 + length]);
                    out[write_pos + length] = '.';

                    // Only take if we're still following a non-pointer name
                    if (parse_offset == reader_offset) {
                        _ = try reader.take(length);
                        reader_offset += 1 + length;
                    }

                    parse_offset += 1 + length;
                    write_pos += length + 1;
                }
            },
            // Pointer
            0b11 => {
                if (parse_offset + 1 > buffer.len) return error.InvalidName;

                // Only take if we're still following a non-pointer name
                if (parse_offset == reader_offset) {
                    _ = try reader.take(1);
                    // We're now diverging and following a pointer, we can
                    // stop consuming bytes from the reader and
                    // updating `reader_offset`.
                }

                const pointer_low: u16 = buffer[parse_offset + 1];
                const pointer_high: u16 = header.len;
                const pointer: u16 = (pointer_high << 8) | pointer_low;
                if (pointer >= parse_offset) return error.InvalidPointerAddress;

                parse_offset = pointer;
                jumps += 1;
            },
            // Reserved
            else => return error.InvalidLabelHeader,
        }
    }

    return error.NameTooLong;
}

/// Deinits our Name object (frees the name buffer)
pub fn deinit(self: *Name) void {
    self.allocator.free(self.name);
}

//--------------------------------------------------
// Tests

const testing = std.testing;
const t = @import("testing.zig");

test "length decode" {
    var reader = Reader.fixed(t.data.labels.duckduckgo.encoded);

    const info = try getLengthFromBuffer(&reader);
    try testing.expectEqual(15, info.bytes);
    try testing.expectEqual(2, info.label_count);
}

test "basic decode" {
    const alloc = testing.allocator;

    var reader = Reader.fixed(t.data.labels.duckduckgo.encoded);

    var name = try Name.decode(alloc, &reader);
    defer name.deinit();

    try testing.expectEqualStrings(t.data.labels.duckduckgo.decoded, name.name);
    try testing.expectEqual(t.data.labels.duckduckgo.decoded.len, name.name.len);
    try testing.expectEqual(2, name.label_count); // "duckduckgo" and "com"
}

const compressed_data = &[_]u8{ 0xcd, 0xa4, 0x05, 0x1, 0x2, 0x3, 0x4, 0x5, 0x03, 0xaa, 0xbb, 0xcc, 0x04, 0x1a, 0x2b, 0x3c, 0x4d, 0x00, 0x02, 0xab, 0xcd, 0xc0, 0x02 };

test "length decode of simple compression" {
    var reader = Reader.fixed(compressed_data);
    _ = try reader.takeInt(u16, .big);

    // Jump passed the random start data
    try testing.expectEqual(0x0501, try reader.peekInt(u16, .big));

    {
        const info = try getLengthFromBuffer(&reader);
        try testing.expectEqual(15, info.bytes);
        try testing.expectEqual(3, info.label_count);
    }

    _ = try reader.take(16); // Move to end of first strings
    try testing.expectEqual(0x02ab, try reader.peekInt(u16, .big));

    {
        const info = try getLengthFromBuffer(&reader);
        try testing.expectEqual(18, info.bytes);
        try testing.expectEqual(4, info.label_count);
    }
}

test "decode of simple compression" {
    const alloc = testing.allocator;
    var reader = Reader.fixed(compressed_data);
    _ = try reader.takeInt(u16, .big);

    // Jump passed the random start data
    try testing.expectEqual(0x0501, try reader.peekInt(u16, .big));

    {
        var name = try Name.decode(alloc, &reader);
        defer name.deinit();

        const expected = &[_]u8{ 0x1, 0x2, 0x3, 0x4, 0x5, '.', 0xaa, 0xbb, 0xcc, '.', 0x1a, 0x2b, 0x3c, 0x4d, '.' };
        try testing.expectEqualSlices(u8, expected, name.name);
    }

    try testing.expectEqual(0x02ab, try reader.peekInt(u16, .big));

    {
        var name = try Name.decode(alloc, &reader);
        defer name.deinit();

        const expected = &[_]u8{ 0xab, 0xcd, '.', 0x1, 0x2, 0x3, 0x4, 0x5, '.', 0xaa, 0xbb, 0xcc, '.', 0x1a, 0x2b, 0x3c, 0x4d, '.' };
        try testing.expectEqualSlices(u8, expected, name.name);
    }
}

test "basic encode" {
    const alloc = testing.allocator;

    const decode_buf = &[_]u8{ 0xa, 'd', 'u', 'c', 'k', 'd', 'u', 'c', 'k', 'g', 'o', 3, 'c', 'o', 'm', 0 };
    var reader = Reader.fixed(decode_buf);

    var decoded_name = try Name.decode(alloc, &reader);
    defer decoded_name.deinit();

    var encode_buf = std.mem.zeroes([512]u8);
    var writer = Writer.fixed(&encode_buf);

    // Note, we don't deallocate this name since we don't allocate anything
    // var encoded_name = Name{
    //     .allocator = alloc,
    //     .name = "duckduckgo.com."
    // };

    try testing.expectEqualSlices(u8, "duckduckgo.com.", decoded_name.name);

    try decoded_name.encode(&writer);

    try testing.expectEqualSlices(u8, decode_buf, writer.buffered());
}

test "fromStr with root domain" {
    const alloc = testing.allocator;

    var name = try Name.fromStr(alloc, "example.com.");
    defer name.deinit();

    try testing.expectEqualStrings("example.com.", name.name);
    try testing.expectEqual(12, name.name.len);
    try testing.expectEqual(2, name.label_count); // "example" and "com"
}

test "fromStr without root domain" {
    const alloc = testing.allocator;

    var name = try Name.fromStr(alloc, "example.com");
    defer name.deinit();

    try testing.expectEqualStrings("example.com.", name.name);
    try testing.expectEqual(12, name.name.len);
    try testing.expectEqual(2, name.label_count); // "example" and "com"
}
