const std = @import("std");
const builtin = @import("builtin");

// Memory
const Allocator = std.mem.Allocator;

// Core
const treebeard = @import("treebeard");
const DNSMemory = treebeard.DNSMemory;
const DNSReader = treebeard.DNSReader;
const DNSWriter = treebeard.DNSWriter;

//--------------------------------------------------
// DNS Name Type

const Name = @This();

const MAX_NAME_BUFFER: usize = 255; // Max buffer length
const MAX_LABEL_COUNT: usize = 128; // Max number of labels
const MAX_LABEL_LENGTH: usize = 63; // Max length of single label

/// Backing data buffer to store name data.
///
/// There are a few approaches we can use to store names.
/// Initially we used a linked-list system. This used less memory
/// since we pulled labels from a pre-allocated memory pool. The
/// downside of this was memory locality. Pretty cache-inefficent.
///
/// Since DNS names can only be at most 255 characters, we can allow
/// labels to exist on the stack to improve locaility and keep name
/// creation consistently performant.
_data: [MAX_NAME_BUFFER]u8,

/// Backing buffer to store label offset indexes.
_labels: [MAX_LABEL_COUNT]u8,

/// Length of the name data in _data.
_name_len: usize,

/// Number of labels stored in _labels.
_labels_len: usize,

/// Get the name data as a slice.
pub fn name(self: *const Name) []const u8 {
    return self._data[0..self._name_len];
}

/// Get the label offsets as a slice.
pub fn labels(self: *const Name) []const u8 {
    return self._labels[0..self._labels_len];
}

/// Label header/type
/// From: https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-10
const LabelHeader = packed struct(u8) {
    len: u6,
    type: u2,
};

/// Create an encoded DNS name from human readable string
pub fn fromStr(domain: []const u8) !Name {
    var result = Name{
        ._data = std.mem.zeroes([MAX_NAME_BUFFER]u8),
        ._labels = std.mem.zeroes([MAX_LABEL_COUNT]u8),
        ._name_len = 0,
        ._labels_len = 0,
    };

    var offset: usize = 0;
    var num_labels: usize = 0;

    var iter = std.mem.splitScalar(u8, domain, '.');
    while (iter.next()) |label| {
        if (offset > domain.len) {
            return error.InvalidName;
        }

        if (label.len > MAX_LABEL_LENGTH) {
            return error.LabelTooLong;
        } else if (label.len > 0) {
            if (num_labels >= MAX_LABEL_COUNT) {
                return error.TooManyLabels;
            }
            // Set the label offset table
            result._labels[num_labels] = @intCast(offset);
            num_labels += 1;

            // Copy label to our buffer
            result._data[offset] = @intCast(label.len); // This is safe since
            // we know len < 63
            @memcpy(result._data[offset + 1 .. offset + label.len + 1], label);

            offset += (label.len + 1);
        }
    }

    // Add root label
    result._data[offset] = 0;
    offset += 1;

    result._name_len = offset;
    result._labels_len = num_labels;

    return result;
}

/// Encodes the provided name following the DNS NAME encoding spec
pub fn encode(self: *const Name, writer: *DNSWriter) !void {
    const name_data = self.name();
    const written_len = try writer.writer.write(name_data);
    if (written_len != name_data.len) {
        return error.NotEnoughBytes;
    }
}

pub fn decode(reader: *DNSReader) !Name {
    var result = Name{
        ._data = std.mem.zeroes([MAX_NAME_BUFFER]u8),
        ._labels = std.mem.zeroes([MAX_LABEL_COUNT]u8),
        ._name_len = 0,
        ._labels_len = 0,
    };

    const buffer = reader.reader.buffer;
    const end = @min(buffer.len, reader.reader.end);

    var parse_offset: usize = reader.reader.seek; // Follows pointers
    var reader_offset: usize = reader.reader.seek; // Tracks read progress
    var write_pos: usize = 0;
    var label_pos: usize = 0;
    var jumps: usize = 0;

    while ((write_pos < MAX_NAME_BUFFER) and (parse_offset < end) and (jumps < 10)) {
        const header: LabelHeader = @bitCast(buffer[parse_offset]);

        // Only take if we're still following a non-pointer name
        // Note: we want to take this byte early in the case we have
        //       to exit later in the function due to a parsing error.
        if (parse_offset == reader_offset) {
            _ = try reader.reader.take(1);
        }

        switch (header.type) {
            // Standard label
            0b00 => {
                const length = header.len;
                // We hit the root label
                if (length == 0) {
                    result._data[write_pos] = 0;

                    result._name_len = write_pos + 1;
                    result._labels_len = label_pos;
                    return result;
                    // Individual label is too long (not really possible with our)
                    // 6 bit length
                } else if (length > 63) {
                    return error.LabelTooLong;
                    // Normal label
                } else {
                    const buf = buffer[parse_offset + 1 .. parse_offset + 1 + length];
                    result._data[write_pos] = length;
                    @memcpy(result._data[write_pos + 1 .. write_pos + length + 1], buf);
                    result._labels[label_pos] = @intCast(write_pos);

                    // Only take if we're still following a non-pointer name
                    if (parse_offset == reader_offset) {
                        _ = try reader.reader.take(length);
                        reader_offset += 1 + length;
                    }

                    parse_offset += 1 + length;
                    write_pos += length + 1;
                    label_pos += 1;
                }
            },
            // Pointer
            0b11 => {
                if (parse_offset + 1 > buffer.len) return error.InvalidName;

                // Only take if we're still following a non-pointer name
                if (parse_offset == reader_offset) {
                    _ = try reader.reader.take(1);
                    // We're now diverging and following a pointer, we can
                    // stop consuming bytes from the reader and
                    // updating `reader_offset`.
                }

                const pointer_low: u16 = buffer[parse_offset + 1];
                const pointer_high: u16 = header.len;
                const pointer: u16 = (pointer_high << 8) | pointer_low;
                // We can only point to previously read names
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

pub fn encodeLength(self: *const Name) usize {
    return self._name_len;
}

pub inline fn label_count(self: *const Name) usize {
    return self._labels_len;
}

pub fn format(self: *const Name, writer: anytype) !void {
    const name_data = self.name();
    const labels_data = self.labels();
    for (labels_data) |offset| {
        const len: usize = name_data[offset];
        const text: []const u8 = name_data[offset + 1 .. offset + len + 1];
        try writer.print("{s}.", .{text});
    }
}

/// Info about the Name.
const NameInfo = struct {
    /// Length of name in bytes (including root domain).
    bytes: usize,

    /// How many labels is this name made up of?
    label_count: usize,
};

/// Get the length and label count of the provided name without consuming the buffer.
/// This can be used to determine the buffer length required for `getStrFromBuffer`.
fn getLengthFromBuffer(reader: *const DNSReader) !NameInfo {
    const buffer = reader.reader.buffer; // Get the raw response
    var offset: usize = reader.reader.seek;
    var total: usize = 0;
    var num_labels: usize = 0;
    var jumps: usize = 0; // Total number of pointer jumps

    const end = @min(reader.reader.end, buffer.len);

    while ((total < MAX_NAME_BUFFER) and (offset < end) and (jumps < 10)) {
        const header: LabelHeader = @bitCast(buffer[offset]);

        switch (header.type) {
            // Standard Label
            0b00 => {
                const length = header.len;
                if (length == 0) {
                    return .{ .bytes = total, .label_count = num_labels };
                } else if (length > 63) {
                    return error.LabelTooLong;
                } else {
                    offset += (1 + length);
                    total += (1 + length); // Add label + '.' sep
                    num_labels += 1;
                }
            },
            // Pointer
            0b11 => {
                if (offset + 1 > buffer.len) return error.InvalidName;
                const pointer_low: u16 = buffer[offset + 1];
                const pointer_high: u16 = header.len;
                const pointer: u16 = (pointer_high << 8) | pointer_low;
                // We can only point to previously read names
                if (pointer >= offset) return error.InvalidPointerAddress;
                offset = pointer;
                jumps += 1;
            },
            // Reserved (unused as of now)
            else => return error.InvalidLabelHeader,
        }
    }

    return error.NameTooLong;
}

/// Deinits our Name object (frees the name buffer)
pub fn deinit(self: *Name) void {
    _ = self;
}

//--------------------------------------------------
// Tests

const testing = std.testing;
const t = @import("testing.zig");

fn expectEqualText(expected: []const u8, dns_name: Name) !void {
    const buf = try std.fmt.allocPrint(testing.allocator, "{f}", .{dns_name});
    defer testing.allocator.free(buf);

    try testing.expectEqualSlices(u8, expected, buf);
    try testing.expectEqual(expected.len, buf.len);
}

test "length decode" {
    var pool = try DNSMemory.init();
    defer pool.deinit();

    var reader = try pool.getReader(.{ .fixed = t.data.labels.duckduckgo.encoded });
    defer reader.deinit();

    const info = try getLengthFromBuffer(&reader);
    try testing.expectEqual(15, info.bytes);
    try testing.expectEqual(2, info.label_count);
}

test "basic decode" {
    var pool = try DNSMemory.init();
    defer pool.deinit();

    var reader = try pool.getReader(.{ .fixed = t.data.labels.duckduckgo.encoded });
    defer reader.deinit();

    var dns_name = try Name.decode(&reader);
    defer dns_name.deinit();

    try expectEqualText(t.data.labels.duckduckgo.decoded, dns_name);
    try testing.expectEqual(2, dns_name.label_count()); // "duckduckgo" and "com"
}

const compressed_data = &[_]u8{ 0xcd, 0xa4, 0x05, 0x1, 0x2, 0x3, 0x4, 0x5, 0x03, 0xaa, 0xbb, 0xcc, 0x04, 0x1a, 0x2b, 0x3c, 0x4d, 0x00, 0x02, 0xab, 0xcd, 0xc0, 0x02 };

test "length decode of simple compression" {
    var pool = try DNSMemory.init();
    defer pool.deinit();

    var reader = try pool.getReader(.{ .fixed = compressed_data });
    defer reader.deinit();

    _ = try reader.reader.takeInt(u16, .big);

    // Jump passed the random start data
    try testing.expectEqual(0x0501, try reader.reader.peekInt(u16, .big));

    {
        const info = try getLengthFromBuffer(&reader);
        try testing.expectEqual(15, info.bytes);
        try testing.expectEqual(3, info.label_count);
    }

    _ = try reader.reader.take(16); // Move to end of first strings
    try testing.expectEqual(0x02ab, try reader.reader.peekInt(u16, .big));

    {
        const info = try getLengthFromBuffer(&reader);
        try testing.expectEqual(18, info.bytes);
        try testing.expectEqual(4, info.label_count);
    }
}

test "decode of simple compression" {
    var pool = try DNSMemory.init();
    defer pool.deinit();

    var reader = try pool.getReader(.{ .fixed = compressed_data });
    defer reader.deinit();

    _ = try reader.reader.takeInt(u16, .big);

    // Jump passed the random start data
    try testing.expectEqual(0x0501, try reader.reader.peekInt(u16, .big));

    {
        var dns_name = try Name.decode(&reader);
        defer dns_name.deinit();

        const expected = &[_]u8{ 0x1, 0x2, 0x3, 0x4, 0x5, '.', 0xaa, 0xbb, 0xcc, '.', 0x1a, 0x2b, 0x3c, 0x4d, '.' };
        try expectEqualText(expected, dns_name);
    }

    try testing.expectEqual(0x02ab, try reader.reader.peekInt(u16, .big));

    {
        var dns_name = try Name.decode(&reader);
        defer dns_name.deinit();

        const expected = &[_]u8{ 0xab, 0xcd, '.', 0x1, 0x2, 0x3, 0x4, 0x5, '.', 0xaa, 0xbb, 0xcc, '.', 0x1a, 0x2b, 0x3c, 0x4d, '.' };
        try expectEqualText(expected, dns_name);
    }
}

test "basic encode" {
    var pool = try DNSMemory.init();
    defer pool.deinit();

    const decode_buf = &[_]u8{ 0xa, 'd', 'u', 'c', 'k', 'd', 'u', 'c', 'k', 'g', 'o', 3, 'c', 'o', 'm', 0 };
    var reader = try pool.getReader(.{ .fixed = decode_buf });
    defer reader.deinit();

    var decoded_name = try Name.decode(&reader);
    defer decoded_name.deinit();

    var encode_buf = std.mem.zeroes([512]u8);
    var writer = try pool.getWriter(.{ .fixed = &encode_buf });
    defer reader.deinit();

    // Note, we don't deallocate this name since we don't allocate anything
    // var encoded_name = Name{
    //     .allocator = alloc,
    //     .name = "duckduckgo.com."
    // };

    try expectEqualText("duckduckgo.com.", decoded_name);

    try decoded_name.encode(&writer);

    try testing.expectEqualSlices(u8, decode_buf, writer.writer.buffered());
}

test "fromStr with root domain" {
    var dns_name = try Name.fromStr("example.com.");
    defer dns_name.deinit();

    try expectEqualText("example.com.", dns_name);
    try testing.expectEqual(2, dns_name.label_count()); // "example" and "com"
}

test "fromStr without root domain" {
    var dns_name = try Name.fromStr("example.com");
    defer dns_name.deinit();

    try expectEqualText("example.com.", dns_name);
    try testing.expectEqual(2, dns_name.label_count()); // "example" and "com"
}

// test "pointer encode, no prefix" {
//     var pool = try DNSMemory.init();
//     defer pool.deinit();
//
//     var target = try Name.fromStr("example.com.");
//     defer target.deinit();
//
//     var pointer = try Name.fromPtr(&pool, null, &target);
//     defer pointer.deinit();
//
//     var encode_buf = std.mem.zeroes([512]u8);
//     var writer = try pool.getWriter(.{ .fixed = &encode_buf });
//     defer writer.deinit();
//
//     try writer.writer.writeInt(u16, 0xfb3c, .big);
//
//     try target.encode(&writer);
//     try pointer.encode(&writer);
//
//     const encoded = &[_]u8{ 0xfb, 0x3c, 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0, 0xc0, 0x02 };
//     try testing.expectEqualSlices(u8, encoded, writer.writer.buffered());
// }

// test "pointer encode, prefix" {
//     var pool = try DNSMemory.init();
//     defer pool.deinit();
//
//     var target = try Name.fromStr("example.com.");
//     defer target.deinit();
//
//     var pointer = try Name.fromPtr(&pool, "static.site.", &target);
//     defer pointer.deinit();
//
//     var encode_buf = std.mem.zeroes([512]u8);
//     var writer = try pool.getWriter(.{ .fixed = &encode_buf });
//     defer writer.deinit();
//
//     try writer.writer.writeInt(u16, 0xfb3c, .big);
//     try target.encode(&writer);
//
//     try writer.writer.writeInt(u16, 0x9876, .big);
//     try pointer.encode(&writer);
//
//     const encoded = &[_]u8{ 0xfb, 0x3c, 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0, 0x98, 0x76, 6, 's', 't', 'a', 't', 'i', 'c', 4, 's', 'i', 't', 'e', 0xC0, 0x02 };
//     try testing.expectEqualSlices(u8, encoded, writer.writer.buffered());
// }

test "encode length" {
    var pool = try DNSMemory.init();
    defer pool.deinit();

    {
        var dns_name = try Name.fromStr("example.com.");
        defer dns_name.deinit();

        try testing.expectEqual(13, dns_name.encodeLength());
    }

    // TODO add this back
    // {
    //     var target = try Name.fromStr("example.com.");
    //     defer target.deinit();
    //
    //     var dns_name = try Name.fromPtr(&pool, "schmaple", &target);
    //     defer dns_name.deinit();
    //
    //     try testing.expectEqual(11, dns_name.encodeLength());
    // }

    {
        var dns_name = try Name.fromStr(".");
        defer dns_name.deinit();

        try testing.expectEqual(1, dns_name.encodeLength());
    }
}
