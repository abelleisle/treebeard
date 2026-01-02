const std = @import("std");

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

const MAX_NAME_BUFFER = 255; // Max buffer length
const MAX_NAME_LENGTH = 253; // Max displayable name length storable in a buffer
const MAX_LABEL_LENGTH: u8 = 63; // Max length of single label

memory: *DNSMemory,

labels: LabelList,

label_count: usize,
total_length: usize,

encode_loc: ?u14 = null,

const LabelBody = union(enum) {
    root,
    text: []const u8,
    ptr: *Name,
};

pub const Label = struct {
    body: LabelBody,
    next: ?*Label,
    prev: ?*Label,
};

const LabelList = struct {
    front: *Label,
    back: *Label,

    pub fn init(memory: *DNSMemory, body: LabelBody) !LabelList {
        const front = try memory.pools.label.borrow();
        front.* = Label{
            .body = body,
            .next = null,
            .prev = null,
        };

        return LabelList{
            .front = front,
            .back = front,
        };
    }

    pub fn deinit(self: *LabelList, memory: *DNSMemory) void {
        var i: ?*Label = self.front;
        while (i) |label| {
            i = label.next;
            memory.pools.label.giveback(label);
        }
    }

    pub fn push(self: *LabelList, memory: *DNSMemory, body: LabelBody) !void {
        const end = try memory.pools.label.borrow();
        end.* = Label{
            .body = body,
            .next = null,
            .prev = self.back,
        };
        self.back.next = end;
        self.back = end;
    }

    pub fn iter(self: *const LabelList) LabelListIterator {
        return LabelListIterator{
            .ptr = null,
            .list = self,
        };
    }

    pub const LabelListIterator = struct {
        /// What node are we pointing to? If the value is none,
        /// we haven't started iterating yet.
        ptr: ?*Label,
        list: *const LabelList,

        pub fn next(self: *LabelListIterator) ?*LabelBody {
            // We've started iterating
            if (self.ptr) |p| {
                if (p.next) |nx| {
                    self.ptr = nx;
                    return &nx.body;
                } else {
                    return null;
                }
            } else {
                self.ptr = self.list.front;
                return &self.list.front.body;
            }
        }
    };
};

const NameData = union(enum) {
    text: []u8,
    ptr: struct {
        prefix: ?[]u8,
        name: *Name,
    },

    pub fn format(self: *const NameData, writer: anytype) !void {
        switch (self.*) {
            .text => |text| {
                try writer.print("{s}", .{text});
            },
            .ptr => |ptr| {
                if (ptr.prefix) |pfx| {
                    try writer.print("{s}.", .{pfx});
                }
                try ptr.name.name.format(writer);
            },
        }
    }
};

/// Label header/type
/// From: https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-10
const LabelHeader = packed struct(u8) {
    len: u6,
    type: u2,
};

/// Create an encoded DNS name from human readable string
pub fn fromStr(memory: *DNSMemory, domain: []const u8) !Name {
    var labels: ?LabelList = null;

    // Count labels (excluding empty root label)
    var length: usize = 0;
    var count: usize = 0;
    var iter = std.mem.splitScalar(u8, domain, '.');
    while (iter.next()) |label| {
        if (label.len > 0) {
            // We're on following labels
            if (labels) |*l| {
                try l.push(memory, .{ .text = label });
                // We're on the first label of the name
            } else {
                labels = try LabelList.init(memory, .{ .text = label });
            }
            count += 1;
            length += label.len;
        }
    }

    // Add root label
    if (labels) |*l| {
        try l.push(memory, .root);
    } else {
        labels = try LabelList.init(memory, .root);
    }

    return Name{
        .memory = memory,
        .labels = labels.?, // We know label exists since we just created it
        .label_count = count,
        .total_length = length,
    };
}

pub fn fromPtr(memory: *DNSMemory, prefix: ?[]const u8, target: *Name) !Name {
    if (prefix) |pfx| {
        var labels: ?LabelList = null;

        // Count labels (excluding empty root label)
        var length: usize = target.total_length;
        var count: usize = target.label_count;
        var iter = std.mem.splitScalar(u8, pfx, '.');
        while (iter.next()) |label| {
            if (label.len > 0) {
                // We're on following labels
                if (labels) |*l| {
                    try l.push(memory, .{ .text = label });
                    // We're on the first label of the name
                } else {
                    labels = try LabelList.init(memory, .{ .text = label });
                }
                count += 1;
                length += label.len;
            }
        }

        if (labels) |*l| {
            try l.push(memory, .{ .ptr = target });
        } else {
            labels = try LabelList.init(memory, .{ .ptr = target });
        }

        const name = Name{
            .memory = memory,
            .labels = labels.?, // We know label exists since we just created it
            .label_count = count,
            .total_length = length,
        };

        return name;
    } else {
        const labels = try LabelList.init(memory, .{ .ptr = target });
        return Name{
            .memory = memory,
            .labels = labels,
            .label_count = target.label_count,
            .total_length = target.total_length,
        };
    }
}

/// Given an encoded DNS name buffer, decode it to a human readable version.
pub fn decode(reader: *DNSReader) !Name {
    const info = try getLengthFromBuffer(reader);

    // const buf = try allocator.alloc(u8, info.bytes);
    // errdefer allocator.free(buf);

    const labels = try getLabelsFromBuffer(reader);

    return Name{
        .memory = reader.memory,
        .labels = labels,
        .label_count = info.label_count,
        .total_length = info.bytes,
    };
}

/// Encodes the provided name following the DNS NAME encoding spec
pub fn encode(self: *Name, writer: *DNSWriter) !void {
    self.encode_loc = @intCast(writer.writer.end);

    var iter = self.labels.iter();
    while (iter.next()) |label| {
        switch (label.*) {
            .root => try writer.writer.writeInt(u8, 0, .big),
            .text => |l| {
                if (l.len > MAX_LABEL_LENGTH) return error.LabelTooLong;
                try writer.writer.writeInt(u8, @intCast(l.len), .big);
                const written_len = try writer.writer.write(l);
                if (written_len != l.len) {
                    return error.NotEnoughBytes;
                }
            },
            .ptr => |ptr| {
                if (ptr.encode_loc) |loc| {
                    const header: u16 = 0xC000 | @as(u16, @intCast(loc));
                    try writer.writer.writeInt(u16, header, .big);
                } else {
                    try ptr.encode(writer);
                }
            },
        }
    }

    // switch (self.name) {
    //     .text => |text| {
    //         self.encode_loc = @intCast(writer.end);
    //         var iter = std.mem.splitScalar(u8, text, '.');
    //         while (iter.next()) |label| {
    //             if (label.len > MAX_LABEL_LENGTH) return error.LabelTooLong;
    //
    //             try writer.writeInt(u8, @intCast(label.len), .big);
    //             const written_len = try writer.write(label);
    //             if (written_len != label.len) {
    //                 return error.NotEnoughBytes;
    //             }
    //         }
    //     },
    //     .ptr => |*ptr| {
    //         self.encode_loc = @intCast(writer.end);
    //         if (ptr.prefix) |prefix| {
    //             // We don't want to write the root domain of a prefix
    //
    //             var iter = std.mem.splitScalar(u8, prefix, '.');
    //             while (iter.next()) |label| {
    //                 if (label.len > MAX_LABEL_LENGTH) return error.LabelTooLong;
    //                 if (label.len == 0) continue;
    //
    //                 try writer.writeInt(u8, @intCast(label.len), .big);
    //                 const written_len = try writer.write(label);
    //                 if (written_len != label.len) {
    //                     return error.NotEnoughBytes;
    //                 }
    //             }
    //         }
    //
    //         if (ptr.name.encode_loc) |loc| {
    //             const header: u16 = 0xC000 | @as(u16, @intCast(loc));
    //             try writer.writeInt(u16, header, .big);
    //         } else {
    //             try ptr.name.encode(writer);
    //         }
    //     },
    // }
}

pub fn format(self: *const Name, writer: anytype) !void {
    var iter = self.labels.iter();
    var first = true;
    while (iter.next()) |label| {
        switch (label.*) {
            // TODO we may not want to print anything here.
            // Technically, if our pointed to label is also a root, it
            // will print '.' as well even though it isn't first label.
            .root => if (first) try writer.print(".", .{}),
            .text => |text| try writer.print("{s}.", .{text}),
            .ptr => |ptr| try writer.print("{f}", .{ptr}),
        }
        first = false;
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
    var labels: usize = 0;
    var jumps: usize = 0; // Total number of pointer jumps

    const end = @min(reader.reader.end, buffer.len);

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

/// Get the human readable domain name from the encoded buffer.
/// The resulting string will be placed in `out`.
fn getLabelsFromBuffer(reader: *DNSReader) !LabelList {
    var labels: ?LabelList = null;
    errdefer if (labels) |*l| l.deinit(reader.memory);

    const buffer = reader.reader.buffer;
    const end = @min(buffer.len, reader.reader.end);

    var parse_offset: usize = reader.reader.seek; // Follows pointers
    var reader_offset: usize = reader.reader.seek; // Tracks read progress
    var write_pos: usize = 0;
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
                    if (labels) |*l| {
                        try l.push(reader.memory, .root);
                    } else {
                        labels = try LabelList.init(reader.memory, .root);
                    }
                    return labels.?;
                    // Individual label is too long (not really possible with our)
                    // 6 bit length
                } else if (length > 63) {
                    return error.LabelTooLong;
                    // Normal label
                } else {
                    const buf = buffer[parse_offset + 1 .. parse_offset + 1 + length];
                    const body: LabelBody = .{ .text = buf };
                    if (labels) |*l| {
                        try l.push(reader.memory, body);
                    } else {
                        labels = try LabelList.init(reader.memory, body);
                    }

                    // Only take if we're still following a non-pointer name
                    if (parse_offset == reader_offset) {
                        _ = try reader.reader.take(length);
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

/// Deinits our Name object (frees the name buffer)
pub fn deinit(self: *Name) void {
    // switch (self.name) {
    //     .text => |txt| self.allocator.free(txt),
    //     .ptr => |*ptr| {
    //         if (ptr.prefix) |p| self.allocator.free(p);
    //     },
    // }
    self.labels.deinit(self.memory);
}

//--------------------------------------------------
// Tests

const testing = std.testing;
const t = @import("testing.zig");

fn expectEqualText(expected: []const u8, name: Name) !void {
    const buf = try std.fmt.allocPrint(testing.allocator, "{f}", .{name});
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

    var name = try Name.decode(&reader);
    defer name.deinit();

    try expectEqualText(t.data.labels.duckduckgo.decoded, name);
    try testing.expectEqual(2, name.label_count); // "duckduckgo" and "com"
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
        var name = try Name.decode(&reader);
        defer name.deinit();

        const expected = &[_]u8{ 0x1, 0x2, 0x3, 0x4, 0x5, '.', 0xaa, 0xbb, 0xcc, '.', 0x1a, 0x2b, 0x3c, 0x4d, '.' };
        try expectEqualText(expected, name);
    }

    try testing.expectEqual(0x02ab, try reader.reader.peekInt(u16, .big));

    {
        var name = try Name.decode(&reader);
        defer name.deinit();

        const expected = &[_]u8{ 0xab, 0xcd, '.', 0x1, 0x2, 0x3, 0x4, 0x5, '.', 0xaa, 0xbb, 0xcc, '.', 0x1a, 0x2b, 0x3c, 0x4d, '.' };
        try expectEqualText(expected, name);
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
    var pool = try DNSMemory.init();
    defer pool.deinit();

    var name = try Name.fromStr(&pool, "example.com.");
    defer name.deinit();

    try expectEqualText("example.com.", name);
    try testing.expectEqual(2, name.label_count); // "example" and "com"
}

test "fromStr without root domain" {
    var pool = try DNSMemory.init();
    defer pool.deinit();

    var name = try Name.fromStr(&pool, "example.com");
    defer name.deinit();

    try expectEqualText("example.com.", name);
    try testing.expectEqual(2, name.label_count); // "example" and "com"
}

test "pointer encode, no prefix" {
    var pool = try DNSMemory.init();
    defer pool.deinit();

    var target = try Name.fromStr(&pool, "example.com.");
    defer target.deinit();

    var pointer = try Name.fromPtr(&pool, null, &target);
    defer pointer.deinit();

    var encode_buf = std.mem.zeroes([512]u8);
    var writer = try pool.getWriter(.{ .fixed = &encode_buf });
    defer writer.deinit();

    try writer.writer.writeInt(u16, 0xfb3c, .big);

    try target.encode(&writer);
    try pointer.encode(&writer);

    const encoded = &[_]u8{ 0xfb, 0x3c, 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0, 0xc0, 0x02 };
    try testing.expectEqualSlices(u8, encoded, writer.writer.buffered());
}

test "pointer encode, prefix" {
    var pool = try DNSMemory.init();
    defer pool.deinit();

    var target = try Name.fromStr(&pool, "example.com.");
    defer target.deinit();

    var pointer = try Name.fromPtr(&pool, "static.site.", &target);
    defer pointer.deinit();

    var encode_buf = std.mem.zeroes([512]u8);
    var writer = try pool.getWriter(.{ .fixed = &encode_buf });
    defer writer.deinit();

    try writer.writer.writeInt(u16, 0xfb3c, .big);
    try target.encode(&writer);

    try writer.writer.writeInt(u16, 0x9876, .big);
    try pointer.encode(&writer);

    const encoded = &[_]u8{ 0xfb, 0x3c, 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0, 0x98, 0x76, 6, 's', 't', 'a', 't', 'i', 'c', 4, 's', 'i', 't', 'e', 0xC0, 0x02 };
    try testing.expectEqualSlices(u8, encoded, writer.writer.buffered());
}
