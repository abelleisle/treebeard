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
/// downside of this was memory locality. Pretty cache-inefficient.
///
/// Since DNS names can only be at most 255 characters, we can allow
/// labels to exist on the stack to improve locality and keep name
/// creation consistently performant.
_data: [MAX_NAME_BUFFER]u8,

/// Backing buffer to store label offset indexes.
_labels: [MAX_LABEL_COUNT]u8,

/// Length of the name data in _data.
_name_len: usize,

/// Number of labels stored in _labels.
_labels_len: usize,

//--------------------------------------------------
// Subtypes

/// Label header/type
const LabelHeader = packed struct(u8) {
    len: u6,
    type: u2,
};

/// Info about the Name.
const NameInfo = struct {
    /// Length of name in bytes (including root domain).
    bytes: usize,

    /// How many labels is this name made up of?
    label_count: usize,
};

//--------------------------------------------------
// Decoding functions

/// Create an encoded DNS name from human readable string
pub fn fromStr(domain: []const u8) !Name {
    var result = Name{
        ._data = std.mem.zeroes([MAX_NAME_BUFFER]u8),
        ._labels = std.mem.zeroes([MAX_LABEL_COUNT]u8),
        ._name_len = 0,
        ._labels_len = 0,
    };
    errdefer result.deinit();

    var offset: usize = 0;
    var num_labels: usize = 0;

    var i = std.mem.splitScalar(u8, domain, '.');
    while (i.next()) |label| {
        if (offset > domain.len) {
            return error.InvalidName;
        }

        // Validate label, will throw error if label is invalid
        try validateLabel(label, num_labels, offset);

        if (label.len > 0) {
            if (num_labels >= MAX_LABEL_COUNT) {
                return error.TooManyLabels;
            }
            // Set the label offset table
            result._labels[num_labels] = @intCast(offset);
            num_labels += 1;

            // This is safe since we know len < 63
            result._data[offset] = @intCast(label.len);
            // Copy label to our buffer
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

pub fn decode(reader: *DNSReader) !Name {
    var result = Name{
        ._data = std.mem.zeroes([MAX_NAME_BUFFER]u8),
        ._labels = std.mem.zeroes([MAX_LABEL_COUNT]u8),
        ._name_len = 0,
        ._labels_len = 0,
    };
    errdefer result.deinit();

    const buffer = reader.reader.buffer;
    const end = @min(buffer.len, reader.reader.end);

    var parse_offset: usize = reader.reader.seek; // Follows pointers
    var reader_offset: usize = reader.reader.seek; // Tracks read progress
    var write_pos: usize = 0;
    var label_pos: usize = 0;

    while ((write_pos < MAX_NAME_BUFFER) and (parse_offset < end)) {
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
                    if (parse_offset + length + 1 > end) return error.LabelHeaderOverrunBuf;
                    const buf = buffer[parse_offset + 1 .. parse_offset + 1 + length];

                    // Validate label, will throw error if label is invalid
                    try validateLabel(buf, label_pos, write_pos);

                    result._data[write_pos] = length;
                    @memcpy(result._data[write_pos + 1 .. write_pos + length + 1], buf);
                    result._labels[label_pos] = @intCast(write_pos);

                    // Only take if we're still following a non-pointer name
                    if (parse_offset == reader_offset) {
                        _ = try reader.reader.take(length);
                        reader_offset += 1 + length;
                    }

                    parse_offset += length + 1;
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
            },
            // Reserved
            else => return error.InvalidLabelHeader,
        }
    }

    // This typically happens if the decoded buf has no root label
    if (parse_offset >= end) {
        return error.NoRootLabel;
    }
    return error.NameTooLong;
}

//--------------------------------------------------
// Encoding functions

/// Encodes the provided name following the DNS NAME encoding spec
pub fn encode(self: *const Name, writer: *DNSWriter) !void {
    const name_data = self.name();
    const written_len = try writer.writer.write(name_data);
    if (written_len != name_data.len) {
        return error.NotEnoughBytes;
    }
}

pub fn format(self: *const Name, writer: anytype) !void {
    // Root only name
    if (self._labels_len == 0) {
        try writer.print(".", .{});
        // Multi-label domain
    } else {
        var i = self.iter();
        while (i.next()) |label| {
            try writer.print("{s}.", .{label});
        }
    }
}

/// Get the length and label count of the provided name without consuming the buffer.
/// This can be used to determine the buffer length required for `getStrFromBuffer`.
fn getLengthFromBuffer(reader: *const DNSReader) !NameInfo {
    const buffer = reader.reader.buffer; // Get the raw response
    var offset: usize = reader.reader.seek;
    var total: usize = 0;
    var num_labels: usize = 0;

    const end = @min(reader.reader.end, buffer.len);

    while ((total < MAX_NAME_BUFFER) and (offset < end)) {
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
// Misc functions

/// Validate that this name is valid as per RFC1035
fn validateLabel(label: []const u8, index: usize, currentLen: usize) !void {
    // Check label lengths
    if (label.len > MAX_LABEL_LENGTH) {
        return error.LabelTooLong;
    } else if (label.len == 0) {
        return; // We can't validate empty labels
    }

    // Make sure we have less than 128 labels
    if (index >= (MAX_LABEL_COUNT - 1)) return error.TooManyLabels;

    // Make sure total name length (including label headers) isn't greater than
    // the maximum allowed name length.
    //
    // We need to check for (MAX_NAME_BUFFER - 2) because we need to store the
    // root label at the end (1 byte).
    if (1 + label.len + currentLen > (MAX_NAME_BUFFER - 1)) return error.NameTooLong;

    // This label has a wildcard
    if (std.mem.indexOf(u8, label, "*")) |pos| {
        if (label.len == 1 and pos == 0) {
            // Wildcard labels must be the first label
            // e.g. `*.example.com` is valid
            //      `sub.*.example.com` is invalid
            if (index > 0) return error.WildcardNotFirst;
        } else {
            // Wildcard can't be part of a label
            // e.g. sub*.example.com
            //      *test.example.com
            return error.WildcardNotAlone;
        }
    }
}

/// Get the name data as a slice.
pub fn name(self: *const Name) []const u8 {
    return self._data[0..self._name_len];
}

/// Get the label offsets as a slice.
pub fn labels(self: *const Name) []const u8 {
    return self._labels[0..self._labels_len];
}

/// Length of encoded name
pub fn encodeLength(self: *const Name) usize {
    return self._name_len;
}

/// Number of labels (excluding root label)
pub inline fn labelCount(self: *const Name) usize {
    return self._labels_len;
}

//--------------------------------------------------
// Iterator

pub const Iterator = struct {
    name: *const Name,
    forward: bool,
    idx: ?usize,

    pub fn next(self: *Iterator) ?[]const u8 {
        // We've started iterating, go to the
        // next index.
        if (self.idx) |*idx| {
            // Iterating from sub to root (->)
            if (self.forward) {
                if (idx.* < (self.name._labels_len - 1)) {
                    idx.* += 1;
                } else {
                    return null;
                }
                // Iterating from root to sub (<-)
            } else {
                if (idx.* > 0) {
                    idx.* -= 1;
                } else {
                    return null;
                }
            }

            // This is our first time calling `next()`.
            // Set idx.
        } else {
            if (self.name._labels_len > 0) {
                if (self.forward) {
                    self.idx = 0;
                } else {
                    self.idx = self.name._labels_len - 1;
                }
            } else {
                return null;
            }
        }

        // Return slice pointing to label
        const offset = self.name._labels[self.idx.?];
        const len = self.name._data[offset];
        return self.name._data[offset + 1 .. offset + len + 1];
    }

    // Go back to the previous value
    pub fn prev(self: *Iterator) ?[]const u8 {
        self.forward = !self.forward;
        const result = self.next();
        self.forward = !self.forward;

        return result;
    }

    /// Is the iterator pointing to the last item in the list?
    ///
    /// Note: This obeys iteration direction. This is `true` if
    /// the next call to `next` will return `null` AND iteration
    /// has already begun.
    pub fn last(self: *const Iterator) bool {
        if (self.idx) |idx| {
            if (self.forward) {
                return idx >= (self.name._labels_len - 1);
            } else {
                return idx == 0;
            }
        } else {
            return false;
        }
    }
};

/// Get label iterator.
///
/// Can be used to iterate through labels (text).
pub fn iter(self: *const Name) Iterator {
    return Iterator{
        .name = self,
        .forward = true,
        .idx = null,
    };
}

/// Get reversed label iterator.
///
/// Can be used to iterate through labels, starting from root.
pub fn iterReverse(self: *const Name) Iterator {
    return Iterator{
        .name = self,
        .forward = false,
        .idx = null,
    };
}

/// Get reverse label iterator for iterating through a context.
///
/// Example use: Iterate through the subdomains of a zone.
/// e.g. web.site.example.com -> iterContext("example.com")
///                                       |
///                                       v
///                                    web.site
///                                          ^ Iterator points here
///                                             <- Iterates this way
///
/// If the target name is an exact domin of the context, `null` is returned.
/// If the target name is not a subdomain at all, error.NotASubdomain is
/// returned.
pub fn iterContext(sub: *const Name, context: *const Name) !?Iterator {
    // Our subdomain can't have fewer labels than our context
    //
    // example.com cannot be a (sub)domain of site.example.com
    if (sub.labelCount() < context.labelCount) return null;

    var subIter = sub.iterReverse();
    var contextIter = context.iterReverse();

    while (contextIter.next()) |contextLabel| {
        if (std.mem.eql(u8, contextLabel, "*")) {
            return subIter;
        }

        if (subIter.next()) |subLabel| {
            if (std.mem.eql(u8, contextLabel, subLabel)) {
                continue;
            } else {
                return error.NotASubdomain;
            }
        } else {
            unreachable;
        }
    }

    return subIter;
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
    try testing.expectEqual(2, dns_name.labelCount()); // "duckduckgo" and "com"
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

test "decode rejects forward pointer" {
    var pool = try DNSMemory.init();
    defer pool.deinit();

    {
        // Pointer at offset 0 points forward to offset 5 (invalid - must point backwards)
        const forward_pointer_data = &[_]u8{
            0xc0, 0x05, // Pointer to offset 5 (forward reference)
            0x00, 0x00, 0x00, // Padding
            0x03, 'c', 'o', 'm', 0x00, // Label at offset 5
        };

        var reader = try pool.getReader(.{ .fixed = forward_pointer_data });
        defer reader.deinit();

        try testing.expectError(error.InvalidPointerAddress, Name.decode(&reader));
    }

    {
        // Pointer at offset 0 points to itself
        const self_ref_data = &[_]u8{
            0xc0, 0x00, // Pointer to offset 0 (self-reference)
        };

        var reader = try pool.getReader(.{ .fixed = self_ref_data });
        defer reader.deinit();

        try testing.expectError(error.InvalidPointerAddress, Name.decode(&reader));
    }
}

test "decode rejects reserved label headers" {
    var pool = try DNSMemory.init();
    defer pool.deinit();

    var reserved_data: [9]u8 = .{
        0x03, 'w', 'w', 'w', // Valid label "www"
        0xc0, 'b', 'a', 'd', // Invalid: 0b01000000 header
        0x00,
    };

    {
        // 0b01xxxxxx (0x40-0x7F) is reserved
        reserved_data[4] = 0x40;

        var reader = try pool.getReader(.{ .fixed = &reserved_data });
        defer reader.deinit();

        try testing.expectError(error.InvalidLabelHeader, Name.decode(&reader));
    }

    {
        // 0b10xxxxxx (0x80-0xBF) is reserved
        reserved_data[4] = 0x80;

        var reader = try pool.getReader(.{ .fixed = &reserved_data });
        defer reader.deinit();

        try testing.expectError(error.InvalidLabelHeader, Name.decode(&reader));
    }
}

test "infinite loop rejection" {
    var pool = try DNSMemory.init();
    defer pool.deinit();

    {
        const loop_data = &[_]u8{
            0x03, 'w', 'w', 'w', // Valid label "www"
            0xc0, 'b', 'a', 'd', // Point to "www"
            0x00,
        };

        var reader = try pool.getReader(.{ .fixed = loop_data });
        defer reader.deinit();

        try testing.expectError(error.InvalidPointerAddress, Name.decode(&reader));
    }

    {
        const loop_data = &[_]u8{
            0x03, 'w', 'w', 'w', 0x00, // Valid label "www"
            0xc0, 0x05, // Point to ourselves
        };

        var reader = try pool.getReader(.{ .fixed = loop_data });
        defer reader.deinit();

        // Decode the www
        const www = try Name.decode(&reader);
        try expectEqualText("www.", www);

        // Make sure we can't point to ourselves
        try testing.expectError(error.InvalidPointerAddress, Name.decode(&reader));
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
    try testing.expectEqual(2, dns_name.labelCount()); // "example" and "com"
}

test "fromStr without root domain" {
    var dns_name = try Name.fromStr("example.com");
    defer dns_name.deinit();

    try expectEqualText("example.com.", dns_name);
    try testing.expectEqual(2, dns_name.labelCount()); // "example" and "com"
}

test "fromStr root domain only" {
    var dns_name = try Name.fromStr(".");
    defer dns_name.deinit();

    try expectEqualText(".", dns_name);
    try testing.expectEqual(0, dns_name.labelCount()); // no labels (only root)
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

test "iter basic" {
    {
        const n = try Name.fromStr("example.com");
        var i = n.iter();

        try testing.expectEqual(null, i.idx);
        try testing.expectEqual(true, i.forward);

        const a = i.next() orelse unreachable;
        try testing.expectEqual(0, i.idx.?);
        try testing.expectEqualStrings("example", a);

        const b = i.next() orelse unreachable;
        try testing.expectEqual(1, i.idx.?);
        try testing.expectEqualStrings("com", b);

        const c = i.next();
        try testing.expectEqual(1, i.idx.?); // We don't increase idx
        try testing.expectEqual(null, c);
    }

    {
        const n = try Name.fromStr(".");
        var i = n.iter();

        try testing.expectEqual(null, i.idx);
        try testing.expectEqual(true, i.forward);

        const a = i.next();
        try testing.expectEqual(null, i.idx);
        try testing.expectEqual(null, a);
    }
}

test "reverse iter" {
    {
        const n = try Name.fromStr("example.com");
        var i = n.iterReverse();

        try testing.expectEqual(null, i.idx);
        try testing.expectEqual(false, i.forward);

        const a = i.next() orelse unreachable;
        try testing.expectEqual(1, i.idx.?);
        try testing.expectEqualStrings("com", a);

        const b = i.next() orelse unreachable;
        try testing.expectEqual(0, i.idx.?);
        try testing.expectEqualStrings("example", b);

        const c = i.next();
        try testing.expectEqual(0, i.idx.?); // We don't decrease idx
        try testing.expectEqual(null, c);
    }

    {
        const n = try Name.fromStr(".");
        var i = n.iterReverse();

        try testing.expectEqual(null, i.idx);
        try testing.expectEqual(false, i.forward);

        const a = i.next();
        try testing.expectEqual(null, i.idx);
        try testing.expectEqual(null, a);
    }
}

test "name validate - wildcards" {
    const valid = try Name.fromStr("*.example.com");
    try testing.expectEqual(3, valid.labelCount()); // Just double check that this is a valid name

    const invalidCases = .{
        .{ .str = "sub.*.example.com", .expected = error.WildcardNotFirst },
        .{ .str = "*.*.example.com", .expected = error.WildcardNotFirst },
        .{ .str = "*sub.example.com", .expected = error.WildcardNotAlone },
        .{ .str = "z*.example.com", .expected = error.WildcardNotAlone },
    };

    inline for (invalidCases) |case| {
        const invalid = Name.fromStr(case.str);
        try testing.expectError(case.expected, invalid);
    }
}

test "name validate - labels too long" {
    const label: []const u8 = "X" ** 63;
    const valid = try Name.fromStr(label);
    try testing.expectEqual(1, valid.labelCount());

    const labelLong: []const u8 = "X" ** 64;
    const invalid = Name.fromStr(labelLong);
    try testing.expectError(error.LabelTooLong, invalid);
}

test "name validate - too many labels" {
    // 127 labels should succeed
    const labels_127 = "a." ** 127;
    const valid = try Name.fromStr(labels_127);
    try testing.expectEqual(127, valid.labelCount());

    // MAX_LABEL_COUNT is 128 (including root), so 128 labels should fail
    const labels_128 = "a." ** 128;
    const invalid = Name.fromStr(labels_128);
    try testing.expectError(error.TooManyLabels, invalid);
}

test "name validate - total length too long" {
    // MAX_NAME_BUFFER is 255, but valid DNS names are max 253 chars + root null = 254
    // Each "XX." adds 3 chars to the string but 3 bytes encoded (1 len + 2 chars)
    // To exceed 255 bytes encoded, we need many labels
    // 63 labels of "XXX" = 63 * (1 + 3) = 252 bytes + 1 root = 253 (valid)
    // 64 labels of "XXX" = 64 * (1 + 3) = 256 bytes + 1 root = 257 (invalid)
    const valid_str = "XXX." ** 63;
    const valid_name = try Name.fromStr(valid_str);
    try testing.expectEqual(63, valid_name.labelCount());

    const invalid_str = "XXX." ** 64;
    const invalid_name = Name.fromStr(invalid_str);
    try testing.expectError(error.NameTooLong, invalid_name);

    // Ensure exactly 254 non-root bytes can get stored but not 255
    {
        // We can only store 254 non-root bytes
        const one_too_long =
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa." ++ // 32
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb." ++ // 64
            "ccccccccccccccccccccccccccccccc." ++ // 96
            "ddddddddddddddddddddddddddddddd." ++ // 128
            "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeee." ++ // 160
            "fffffffffffffffffffffffffffffff." ++ // 192
            "ggggggggggggggggggggggggggggggg." ++ // 224
            "0123456789abcdef01234567890abc"; // 255
        const one_too_long_name = Name.fromStr(one_too_long);
        try testing.expectError(error.NameTooLong, one_too_long_name);

        const close_but_no_cigar_str = one_too_long[0..253]; // Length = 254
        const close_but_no_cigar_name = try Name.fromStr(close_but_no_cigar_str);
        try testing.expectEqual(8, close_but_no_cigar_name.labelCount());
        // Includes root label length
        try testing.expectEqual(255, close_but_no_cigar_name.name().len);
    }

    // Same as above, but test wire decoding
    {
        var pool = try DNSMemory.init();
        defer pool.deinit();

        // We can only store 254 non-root bytes
        const one_too_long =
            "\x1Faaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" ++ // 32
            "\x1Fbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" ++ // 64
            "\x1Fccccccccccccccccccccccccccccccc" ++ // 96
            "\x1Fddddddddddddddddddddddddddddddd" ++ // 128
            "\x1Feeeeeeeeeeeeeeeeeeeeeeeeeeeeeee" ++ // 160
            "\x1Ffffffffffffffffffffffffffffffff" ++ // 192
            "\x1Fggggggggggggggggggggggggggggggg" ++ // 224
            "\x1E0123456789abcdef01234567890abc"; // 255
        var reader_invalid = try pool.getReader(.{ .fixed = one_too_long });
        defer reader_invalid.deinit();
        const one_too_long_name = Name.decode(&reader_invalid);
        try testing.expectError(error.NameTooLong, one_too_long_name);

        const close_but_no_cigar_str =
            "\x1Faaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" ++ // 32
            "\x1Fbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" ++ // 64
            "\x1Fccccccccccccccccccccccccccccccc" ++ // 96
            "\x1Fddddddddddddddddddddddddddddddd" ++ // 128
            "\x1Feeeeeeeeeeeeeeeeeeeeeeeeeeeeeee" ++ // 160
            "\x1Ffffffffffffffffffffffffffffffff" ++ // 192
            "\x1Fggggggggggggggggggggggggggggggg" ++ // 224
            "\x1D0123456789abcdef01234567890ab\x00"; // 255

        try testing.expectEqual(255, close_but_no_cigar_str.len);

        var reader_valid = try pool.getReader(.{ .fixed = close_but_no_cigar_str });
        defer reader_valid.deinit();
        const close_but_no_cigar_name = try Name.decode(&reader_valid);

        try testing.expectEqual(8, close_but_no_cigar_name.labelCount());
        // Includes root label length
        try testing.expectEqual(255, close_but_no_cigar_name.name().len);
    }

    // Test to make sure our wire encoded names have a root label
    {
        var pool = try DNSMemory.init();
        defer pool.deinit();

        const no_root_str =
            "\x1Faaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" ++ // 32
            "\x1Fbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" ++ // 64
            "\x1Fccccccccccccccccccccccccccccccc" ++ // 96
            "\x1Fddddddddddddddddddddddddddddddd" ++ // 128
            "\x1Feeeeeeeeeeeeeeeeeeeeeeeeeeeeeee" ++ // 160
            "\x1Ffffffffffffffffffffffffffffffff" ++ // 192
            "\x1Fggggggggggggggggggggggggggggggg" ++ // 224
            "\x1D0123456789abcdef01234567890ab"; // 255

        try testing.expectEqual(254, no_root_str.len);

        var reader_valid = try pool.getReader(.{ .fixed = no_root_str });
        defer reader_valid.deinit();
        const no_root_name = Name.decode(&reader_valid);

        try testing.expectError(error.NoRootLabel, no_root_name);
    }
}
