const std = @import("std");

// Core
const treebeard = @import("treebeard");
const DNSMemory = treebeard.DNSMemory;
const DNSReader = treebeard.DNSReader;
const DNSWriter = treebeard.DNSWriter;

const Name = treebeard.Name;
const Record = treebeard.Record;
const Message = treebeard.Message;
const ExtendedResponseCode = treebeard.ExtendedResponseCode;

//--------------------------------------------------
// DNS Additional Record

const Additional = @This();

_inner: Record,

_adata: AData,

memory: *DNSMemory,

pub const AData = union(enum) {
    TSIG: struct {
        algorithm: Name,
        timeSigned: u48,
        fudge: u16,
        mac: []u8,
        originalID: u16,
        rcode: ExtendedResponseCode,
        otherLen: u16,
    },
};

pub fn TSIG(memory: *DNSMemory, keyname: []const u8, algorithm: []const u8, fudge: u16, mac: []u8, transactionID: u16) !Additional {
    // TODO sign when we create response not when we create TSIG
    const now: u48 = @intCast(std.time.timestamp());

    const mac_dupe = try memory.alloc().dupe(u8, mac);
    errdefer memory.alloc().free(mac_dupe);

    return Additional{
        .memory = memory,
        ._inner = Record{
            .memory = memory,
            .class = .ANY,
            .type = .TSIG,
            .ttl = 0,
            .name = try Name.fromStr(keyname),
            .rdata = .Other,
        },
        ._adata = .{ .TSIG = .{
            .algorithm = try Name.fromStr(algorithm),
            .timeSigned = now,
            .fudge = fudge,
            .mac = mac_dupe,
            .originalID = transactionID,
            .rcode = .noError,
            .otherLen = 0,
        } },
    };
}

pub fn encode(self: *Additional, writer: *DNSWriter) !void {
    try self._inner.encode(writer);
    switch (self._adata) {
        .TSIG => |*data| {
            // Write RDATA Length
            // Note: We use explicit byte sizes here instead of @sizeOf because
            // @sizeOf(u48) returns 8 (padded) but we write exactly 6 bytes
            const rdata_len =
                data.algorithm.encodeLength() +
                6 + // timeSigned: u48 writes 6 bytes
                2 + // fudge: u16
                2 + // MAC length field: u16
                data.mac.len +
                2 + // originalID: u16
                2 + // rcode: u16 (ExtendedResponseCode)
                2; // otherLen: u16
            try writer.writer.writeInt(u16, @intCast(rdata_len), .big);

            // Write RDATA
            try data.algorithm.encode(writer);
            try writer.writer.writeInt(u48, data.timeSigned, .big);
            try writer.writer.writeInt(u16, data.fudge, .big);
            try writer.writer.writeInt(u16, @intCast(data.mac.len), .big);
            const mac_write_len = try writer.writer.write(data.mac);
            if (mac_write_len != data.mac.len) {
                return error.NotEnoughBytes;
            }
            try writer.writer.writeInt(u16, data.originalID, .big);
            try data.rcode.encode(writer);
            try writer.writer.writeInt(u16, data.otherLen, .big);
        },
    }
}

pub fn decode(reader: *DNSReader) !Additional {
    var record = try Record.decode(reader);
    errdefer record.deinit();

    if (record.class != .ANY) {
        return error.IncorrectClass;
    }

    if (record.rdata != .Other) {
        return error.InvalidDataType;
    }

    const adata: AData = switch (record.type) {
        .TSIG => blk: {
            var algorithm = try Name.decode(reader);
            errdefer algorithm.deinit();

            const time = reader.reader.takeInt(u48, .big) catch return error.NotEnoughBytes;
            const fudge = reader.reader.takeInt(u16, .big) catch return error.NotEnoughBytes;
            const macLen = reader.reader.takeInt(u16, .big) catch return error.NotEnoughBytes;
            const mac_slice = reader.reader.take(macLen) catch return error.NotEnoughBytes;

            // Duplicate the MAC so we own it
            const mac = try reader.memory.alloc().dupe(u8, mac_slice);
            errdefer reader.memory.alloc().free(mac);

            const id = reader.reader.takeInt(u16, .big) catch return error.NotEnoughBytes;
            const rcode = try ExtendedResponseCode.decode(reader);
            const otherLen = reader.reader.takeInt(u16, .big) catch return error.NotEnoughBytes;

            break :blk AData{ .TSIG = .{
                .algorithm = algorithm,
                .timeSigned = time,
                .fudge = fudge,
                .mac = mac,
                .originalID = id,
                .rcode = rcode,
                .otherLen = otherLen,
            } };
        },
        else => return error.UnsupportedAdditionalType,
    };

    return .{
        .memory = reader.memory,
        ._inner = record,
        ._adata = adata,
    };
}

pub fn deinit(self: *Additional) void {
    switch (self._adata) {
        .TSIG => |*data| {
            data.algorithm.deinit();
            self.memory.alloc().free(data.mac);
        },
    }

    self._inner.deinit();
}

//--------------------------------------------------
// Tests

const testing = std.testing;

/// Helper to create an Additional with a specific timeSigned value for deterministic testing
fn createTSIGWithTime(
    memory: *DNSMemory,
    keyname: []const u8,
    algorithm: []const u8,
    fudge: u16,
    mac: []u8,
    transactionID: u16,
    timeSigned: u48,
    rcode: ExtendedResponseCode,
) !Additional {
    const mac_dupe = try memory.alloc().dupe(u8, mac);
    errdefer memory.alloc().free(mac_dupe);

    return Additional{
        .memory = memory,
        ._inner = Record{
            .memory = memory,
            .class = .ANY,
            .type = .TSIG,
            .ttl = 0,
            .name = try Name.fromStr(keyname),
            .rdata = .Other,
        },
        ._adata = .{ .TSIG = .{
            .algorithm = try Name.fromStr(algorithm),
            .timeSigned = timeSigned,
            .fudge = fudge,
            .mac = mac_dupe,
            .originalID = transactionID,
            .rcode = rcode,
            .otherLen = 0,
        } },
    };
}

test "TSIG encode - hmac-sha256 with 32-byte MAC" {
    var memory = try DNSMemory.init();
    defer memory.deinit();

    // 32-byte MAC (SHA-256 output size)
    var mac = [_]u8{
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
        0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
    };

    var additional = try createTSIGWithTime(
        &memory,
        "mykey.",
        "hmac-sha256.",
        300, // 5 minute fudge
        &mac,
        0xABCD, // transaction ID
        0x0000_65A1_B2C3, // fixed timestamp for testing
        .noError,
    );
    defer additional.deinit();

    var buf: [512]u8 = undefined;
    var writer = try memory.getWriter(.{ .fixed = &buf });
    defer writer.deinit();

    try additional.encode(&writer);

    const written = writer.writer.buffered();

    // Verify the key name "mykey." is encoded correctly
    // 5 'm' 'y' 'k' 'e' 'y' 0 = 7 bytes
    try testing.expectEqual(@as(u8, 5), written[0]); // length of "mykey"
    try testing.expectEqualSlices(u8, "mykey", written[1..6]);
    try testing.expectEqual(@as(u8, 0), written[6]); // root label

    // TYPE = TSIG (250) at offset 7
    try testing.expectEqual(@as(u16, 250), std.mem.readInt(u16, written[7..9], .big));

    // CLASS = ANY (255) at offset 9
    try testing.expectEqual(@as(u16, 255), std.mem.readInt(u16, written[9..11], .big));

    // TTL = 0 at offset 11
    try testing.expectEqual(@as(u32, 0), std.mem.readInt(u32, written[11..15], .big));

    // RDLENGTH at offset 15
    // algorithm (13) + timeSigned (6) + fudge (2) + macSize (2) + mac (32) + origID (2) + error (2) + otherLen (2) = 61
    const expected_rdlength: u16 = 13 + 6 + 2 + 2 + 32 + 2 + 2 + 2;
    try testing.expectEqual(expected_rdlength, std.mem.readInt(u16, written[15..17], .big));

    // Algorithm name "hmac-sha256." at offset 17
    // 11 'h' 'm' 'a' 'c' '-' 's' 'h' 'a' '2' '5' '6' 0 = 13 bytes
    try testing.expectEqual(@as(u8, 11), written[17]);
    try testing.expectEqualSlices(u8, "hmac-sha256", written[18..29]);
    try testing.expectEqual(@as(u8, 0), written[29]); // root label

    // Time signed (48-bit) at offset 30
    const time_bytes = written[30..36];
    const time_high: u48 = @as(u48, time_bytes[0]) << 40 |
        @as(u48, time_bytes[1]) << 32 |
        @as(u48, time_bytes[2]) << 24 |
        @as(u48, time_bytes[3]) << 16 |
        @as(u48, time_bytes[4]) << 8 |
        @as(u48, time_bytes[5]);
    try testing.expectEqual(@as(u48, 0x0000_65A1_B2C3), time_high);

    // Fudge at offset 36
    try testing.expectEqual(@as(u16, 300), std.mem.readInt(u16, written[36..38], .big));

    // MAC size at offset 38
    try testing.expectEqual(@as(u16, 32), std.mem.readInt(u16, written[38..40], .big));

    // MAC at offset 40
    try testing.expectEqualSlices(u8, &mac, written[40..72]);

    // Original ID at offset 72
    try testing.expectEqual(@as(u16, 0xABCD), std.mem.readInt(u16, written[72..74], .big));

    // Error (rcode) at offset 74
    try testing.expectEqual(@as(u16, 0), std.mem.readInt(u16, written[74..76], .big));

    // Other length at offset 76
    try testing.expectEqual(@as(u16, 0), std.mem.readInt(u16, written[76..78], .big));

    // Total length should be 78 bytes
    try testing.expectEqual(@as(usize, 78), written.len);
}

test "TSIG encode - hmac-md5.sig-alg.reg.int algorithm name" {
    var memory = try DNSMemory.init();
    defer memory.deinit();

    // 16-byte MAC (MD5 output size)
    var mac = [_]u8{
        0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe,
        0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0,
    };

    var additional = try createTSIGWithTime(
        &memory,
        "update-key.example.com.",
        "hmac-md5.sig-alg.reg.int.",
        300,
        &mac,
        0x1234,
        0x0000_12345678,
        .noError,
    );
    defer additional.deinit();

    var buf: [512]u8 = undefined;
    var writer = try memory.getWriter(.{ .fixed = &buf });
    defer writer.deinit();

    try additional.encode(&writer);

    const written = writer.writer.buffered();

    // Key name "update-key.example.com." should be:
    // 10 'u' 'p' 'd' 'a' 't' 'e' '-' 'k' 'e' 'y' 7 'e' 'x' 'a' 'm' 'p' 'l' 'e' 3 'c' 'o' 'm' 0
    try testing.expectEqual(@as(u8, 10), written[0]); // "update-key" length
    try testing.expectEqualSlices(u8, "update-key", written[1..11]);
    try testing.expectEqual(@as(u8, 7), written[11]); // "example" length
    try testing.expectEqualSlices(u8, "example", written[12..19]);
    try testing.expectEqual(@as(u8, 3), written[19]); // "com" length
    try testing.expectEqualSlices(u8, "com", written[20..23]);
    try testing.expectEqual(@as(u8, 0), written[23]); // root label

    // TYPE = TSIG (250) at offset 24
    try testing.expectEqual(@as(u16, 250), std.mem.readInt(u16, written[24..26], .big));

    // CLASS = ANY (255)
    try testing.expectEqual(@as(u16, 255), std.mem.readInt(u16, written[26..28], .big));
}

test "TSIG encode - error response with BADSIG" {
    var memory = try DNSMemory.init();
    defer memory.deinit();

    // Empty MAC for error responses (per RFC 2845)
    var mac = [_]u8{};

    var additional = try createTSIGWithTime(
        &memory,
        "key.",
        "hmac-sha256.",
        300,
        &mac,
        0x5678,
        0x0000_AABBCCDD,
        .badSig, // BADSIG = 16
    );
    defer additional.deinit();

    var buf: [512]u8 = undefined;
    var writer = try memory.getWriter(.{ .fixed = &buf });
    defer writer.deinit();

    try additional.encode(&writer);

    const written = writer.writer.buffered();

    // Find the error field (after MAC, which is empty)
    // key name (5) + type (2) + class (2) + ttl (4) + rdlen (2) +
    // algorithm (13) + time (6) + fudge (2) + maclen (2) + mac (0) = 38
    const error_offset = 5 + 2 + 2 + 4 + 2 + 13 + 6 + 2 + 2 + 0;

    // Original ID
    try testing.expectEqual(@as(u16, 0x5678), std.mem.readInt(u16, written[error_offset..][0..2], .big));

    // Error code = BADSIG (16)
    try testing.expectEqual(@as(u16, 16), std.mem.readInt(u16, written[error_offset + 2 ..][0..2], .big));

    // MAC size should be 0
    const mac_size_offset = 5 + 2 + 2 + 4 + 2 + 13 + 6 + 2;
    try testing.expectEqual(@as(u16, 0), std.mem.readInt(u16, written[mac_size_offset..][0..2], .big));
}

test "TSIG encode - error response with BADKEY" {
    var memory = try DNSMemory.init();
    defer memory.deinit();

    var mac = [_]u8{};

    var additional = try createTSIGWithTime(
        &memory,
        "unknown-key.",
        "hmac-sha256.",
        300,
        &mac,
        0x9999,
        0x0000_11111111,
        .badKey, // BADKEY = 17
    );
    defer additional.deinit();

    var buf: [512]u8 = undefined;
    var writer = try memory.getWriter(.{ .fixed = &buf });
    defer writer.deinit();

    try additional.encode(&writer);

    const written = writer.writer.buffered();

    // Key name is "unknown-key." = 12 bytes (11 + label len + root)
    // 11 'u' 'n' 'k' 'n' 'o' 'w' 'n' '-' 'k' 'e' 'y' 0 = 13 bytes
    const error_offset = 13 + 2 + 2 + 4 + 2 + 13 + 6 + 2 + 2 + 0;
    try testing.expectEqual(@as(u16, 17), std.mem.readInt(u16, written[error_offset + 2 ..][0..2], .big));
}

test "TSIG encode - error response with BADTIME" {
    var memory = try DNSMemory.init();
    defer memory.deinit();

    var mac = [_]u8{};

    var additional = try createTSIGWithTime(
        &memory,
        "key.",
        "hmac-sha256.",
        300,
        &mac,
        0x1111,
        0x0000_22222222,
        .badTime, // BADTIME = 18
    );
    defer additional.deinit();

    var buf: [512]u8 = undefined;
    var writer = try memory.getWriter(.{ .fixed = &buf });
    defer writer.deinit();

    try additional.encode(&writer);

    const written = writer.writer.buffered();

    const error_offset = 5 + 2 + 2 + 4 + 2 + 13 + 6 + 2 + 2 + 0;
    try testing.expectEqual(@as(u16, 18), std.mem.readInt(u16, written[error_offset + 2 ..][0..2], .big));
}

test "TSIG encode - maximum fudge value" {
    var memory = try DNSMemory.init();
    defer memory.deinit();

    var mac = [_]u8{ 0x00, 0x01, 0x02, 0x03 };

    var additional = try createTSIGWithTime(
        &memory,
        "k.",
        "hmac-sha256.",
        0xFFFF, // max u16 fudge
        &mac,
        0x0000,
        0x0000_00000000,
        .noError,
    );
    defer additional.deinit();

    var buf: [512]u8 = undefined;
    var writer = try memory.getWriter(.{ .fixed = &buf });
    defer writer.deinit();

    try additional.encode(&writer);

    const written = writer.writer.buffered();

    // Fudge is after: keyname (3) + type (2) + class (2) + ttl (4) + rdlen (2) + algo (13) + time (6) = 32
    const fudge_offset = 3 + 2 + 2 + 4 + 2 + 13 + 6;
    try testing.expectEqual(@as(u16, 0xFFFF), std.mem.readInt(u16, written[fudge_offset..][0..2], .big));
}

test "TSIG encode - timestamp at epoch boundary" {
    var memory = try DNSMemory.init();
    defer memory.deinit();

    var mac = [_]u8{0x42};

    // Test with timestamp 0 (Unix epoch)
    var additional = try createTSIGWithTime(
        &memory,
        "k.",
        "hmac-sha256.",
        300,
        &mac,
        0x1234,
        0, // epoch
        .noError,
    );
    defer additional.deinit();

    var buf: [512]u8 = undefined;
    var writer = try memory.getWriter(.{ .fixed = &buf });
    defer writer.deinit();

    try additional.encode(&writer);

    const written = writer.writer.buffered();

    // Time is after: keyname (3) + type (2) + class (2) + ttl (4) + rdlen (2) + algo (13) = 26
    const time_offset = 3 + 2 + 2 + 4 + 2 + 13;
    const time_bytes = written[time_offset..][0..6];
    try testing.expectEqualSlices(u8, &[_]u8{ 0, 0, 0, 0, 0, 0 }, time_bytes);
}

test "TSIG encode - timestamp at max 48-bit value" {
    var memory = try DNSMemory.init();
    defer memory.deinit();

    var mac = [_]u8{0x42};

    // Test with max 48-bit timestamp
    var additional = try createTSIGWithTime(
        &memory,
        "k.",
        "hmac-sha256.",
        300,
        &mac,
        0x1234,
        0xFFFF_FFFFFFFF, // max u48
        .noError,
    );
    defer additional.deinit();

    var buf: [512]u8 = undefined;
    var writer = try memory.getWriter(.{ .fixed = &buf });
    defer writer.deinit();

    try additional.encode(&writer);

    const written = writer.writer.buffered();

    const time_offset = 3 + 2 + 2 + 4 + 2 + 13;
    const time_bytes = written[time_offset..][0..6];
    try testing.expectEqualSlices(u8, &[_]u8{ 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF }, time_bytes);
}

test "TSIG encode - single label key name" {
    var memory = try DNSMemory.init();
    defer memory.deinit();

    var mac = [_]u8{0x00};

    var additional = try createTSIGWithTime(
        &memory,
        "x.",
        "hmac-sha256.",
        300,
        &mac,
        0x0001,
        0x0000_00000001,
        .noError,
    );
    defer additional.deinit();

    var buf: [512]u8 = undefined;
    var writer = try memory.getWriter(.{ .fixed = &buf });
    defer writer.deinit();

    try additional.encode(&writer);

    const written = writer.writer.buffered();

    // Single char label "x." = 1 'x' 0 = 3 bytes
    try testing.expectEqual(@as(u8, 1), written[0]);
    try testing.expectEqual(@as(u8, 'x'), written[1]);
    try testing.expectEqual(@as(u8, 0), written[2]);
}

test "TSIG encode - deeply nested key name" {
    var memory = try DNSMemory.init();
    defer memory.deinit();

    var mac = [_]u8{0xAB};

    var additional = try createTSIGWithTime(
        &memory,
        "a.b.c.d.e.f.example.com.",
        "hmac-sha256.",
        300,
        &mac,
        0xFFFF,
        0x0000_DEADBEEF,
        .noError,
    );
    defer additional.deinit();

    var buf: [512]u8 = undefined;
    var writer = try memory.getWriter(.{ .fixed = &buf });
    defer writer.deinit();

    try additional.encode(&writer);

    const written = writer.writer.buffered();

    // Verify structure of deeply nested name
    // 1 'a' 1 'b' 1 'c' 1 'd' 1 'e' 1 'f' 7 'example' 3 'com' 0
    var offset: usize = 0;
    const expected_labels = [_][]const u8{ "a", "b", "c", "d", "e", "f", "example", "com" };
    for (expected_labels) |label| {
        try testing.expectEqual(@as(u8, @intCast(label.len)), written[offset]);
        try testing.expectEqualSlices(u8, label, written[offset + 1 .. offset + 1 + label.len]);
        offset += 1 + label.len;
    }
    try testing.expectEqual(@as(u8, 0), written[offset]); // root label
}

test "TSIG encode - hmac-sha512 with 64-byte MAC" {
    var memory = try DNSMemory.init();
    defer memory.deinit();

    // 64-byte MAC (SHA-512 output size)
    var mac: [64]u8 = undefined;
    for (&mac, 0..) |*byte, i| {
        byte.* = @intCast(i);
    }

    var additional = try createTSIGWithTime(
        &memory,
        "sha512-key.",
        "hmac-sha512.",
        600,
        &mac,
        0xBEEF,
        0x0000_CAFEBABE,
        .noError,
    );
    defer additional.deinit();

    var buf: [512]u8 = undefined;
    var writer = try memory.getWriter(.{ .fixed = &buf });
    defer writer.deinit();

    try additional.encode(&writer);

    const written = writer.writer.buffered();

    // Verify MAC is present and correct
    // keyname (12) + type (2) + class (2) + ttl (4) + rdlen (2) + algo (13) + time (6) + fudge (2) + maclen (2) = 45
    const mac_offset = 12 + 2 + 2 + 4 + 2 + 13 + 6 + 2 + 2;
    try testing.expectEqualSlices(u8, &mac, written[mac_offset..][0..64]);

    // Verify MAC length field
    const mac_len_offset = 12 + 2 + 2 + 4 + 2 + 13 + 6 + 2;
    try testing.expectEqual(@as(u16, 64), std.mem.readInt(u16, written[mac_len_offset..][0..2], .big));
}

test "TSIG encode - rdlength calculation correctness" {
    var memory = try DNSMemory.init();
    defer memory.deinit();

    // Test with varying MAC sizes to ensure RDLENGTH is calculated correctly
    const mac_sizes = [_]usize{ 0, 1, 16, 20, 32, 64, 128 };

    for (mac_sizes) |mac_size| {
        var mac_buf: [128]u8 = undefined;
        const mac = mac_buf[0..mac_size];
        for (mac) |*byte| {
            byte.* = 0xAA;
        }

        var additional = try createTSIGWithTime(
            &memory,
            "key.",
            "hmac-sha256.",
            300,
            mac,
            0x1234,
            0x0000_11223344,
            .noError,
        );
        defer additional.deinit();

        var buf: [512]u8 = undefined;
        var writer = try memory.getWriter(.{ .fixed = &buf });
        defer writer.deinit();

        try additional.encode(&writer);

        const written = writer.writer.buffered();

        // RDLENGTH is at offset: keyname (5) + type (2) + class (2) + ttl (4) = 13
        const rdlength = std.mem.readInt(u16, written[13..15], .big);

        // Expected RDLENGTH: algo (13) + time (6) + fudge (2) + maclen (2) + mac + origID (2) + error (2) + otherlen (2)
        const expected: u16 = @intCast(13 + 6 + 2 + 2 + mac_size + 2 + 2 + 2);
        try testing.expectEqual(expected, rdlength);
    }
}

test "TSIG encode - verify wire format matches RFC 2845" {
    var memory = try DNSMemory.init();
    defer memory.deinit();

    // Create a TSIG with known values to verify exact wire format
    var mac = [_]u8{ 0xDE, 0xAD, 0xBE, 0xEF };

    var additional = try createTSIGWithTime(
        &memory,
        "test.",
        "hmac-sha256.",
        300,
        &mac,
        0x1234,
        0x0000_00000001, // timestamp = 1
        .noError,
    );
    defer additional.deinit();

    var buf: [512]u8 = undefined;
    var writer = try memory.getWriter(.{ .fixed = &buf });
    defer writer.deinit();

    try additional.encode(&writer);

    const written = writer.writer.buffered();

    // Build expected wire format manually
    const expected = [_]u8{
        // Key name "test."
        4,    't',  'e',  's',  't',  0,
        // TYPE = TSIG (250)
        0x00, 0xFA,
        // CLASS = ANY (255)
        0x00, 0xFF,
        // TTL = 0
        0x00, 0x00,
        0x00, 0x00,
        // RDLENGTH = 13 + 6 + 2 + 2 + 4 + 2 + 2 + 2 = 33
        0x00, 0x21,
        // Algorithm "hmac-sha256."
        11,   'h',
        'm',  'a',  'c',  '-',  's',  'h',
        'a',  '2',  '5',  '6',  0,
        // Time signed (48-bit big-endian)
           0x00,
        0x00, 0x00, 0x00, 0x00,
        0x01,
        // Fudge
        0x01, 0x2C, // 300
        // MAC size
        0x00, 0x04,
        // MAC
        0xDE, 0xAD,
        0xBE, 0xEF,
        // Original ID
        0x12, 0x34,
        // Error
        0x00, 0x00,
        // Other length
        0x00, 0x00,
    };

    try testing.expectEqualSlices(u8, &expected, written);
}

test "TSIG encode - transaction ID boundary values" {
    var memory = try DNSMemory.init();
    defer memory.deinit();

    const ids = [_]u16{ 0x0000, 0x0001, 0x7FFF, 0x8000, 0xFFFE, 0xFFFF };

    for (ids) |id| {
        var mac = [_]u8{0x00};

        var additional = try createTSIGWithTime(
            &memory,
            "k.",
            "hmac-sha256.",
            0,
            &mac,
            id,
            0,
            .noError,
        );
        defer additional.deinit();

        var buf: [512]u8 = undefined;
        var writer = try memory.getWriter(.{ .fixed = &buf });
        defer writer.deinit();

        try additional.encode(&writer);

        const written = writer.writer.buffered();

        // Original ID is at: keyname (3) + type (2) + class (2) + ttl (4) + rdlen (2) + algo (13) + time (6) + fudge (2) + maclen (2) + mac (1) = 37
        const id_offset = 3 + 2 + 2 + 4 + 2 + 13 + 6 + 2 + 2 + 1;
        try testing.expectEqual(id, std.mem.readInt(u16, written[id_offset..][0..2], .big));
    }
}

//--------------------------------------------------
// Decode Tests

// Test data for TSIG decoding
const tsig_test_data = struct {
    // TSIG record with hmac-sha256, 4-byte MAC
    // keyname: "test.", algorithm: "hmac-sha256.", fudge: 300, mac: 0xDEADBEEF
    // originalID: 0x1234, rcode: NOERROR, otherLen: 0
    const basic_tsig = [_]u8{
        // Key name "test."
        4,    't',  'e',  's',  't',  0,
        // TYPE = TSIG (250)
        0x00, 0xFA,
        // CLASS = ANY (255)
        0x00, 0xFF,
        // TTL = 0
        0x00, 0x00,
        0x00, 0x00,
        // RDLENGTH = 33
        0x00, 0x21,
        // Algorithm "hmac-sha256."
        11,   'h',
        'm',  'a',  'c',  '-',  's',  'h',
        'a',  '2',  '5',  '6',  0,
        // Time signed (48-bit): 0x000000000001
           0x00,
        0x00, 0x00, 0x00, 0x00, 0x01,
        // Fudge: 300
        0x01,
        0x2C,
        // MAC size: 4
        0x00, 0x04,
        // MAC
        0xDE, 0xAD, 0xBE,
        0xEF,
        // Original ID
        0x12, 0x34,
        // Error: NOERROR (0)
        0x00, 0x00,
        // Other length: 0
        0x00,
        0x00,
    };

    // TSIG with BADSIG error and empty MAC
    const error_tsig = [_]u8{
        // Key name "key."
        3,    'k',  'e',  'y',  0,
        // TYPE = TSIG (250)
        0x00, 0xFA,
        // CLASS = ANY (255)
        0x00, 0xFF,
        // TTL = 0
        0x00,
        0x00, 0x00, 0x00,
        // RDLENGTH = 29 (no MAC)
        0x00, 0x1D,
        // Algorithm "hmac-sha256."
        11,   'h',  'm',  'a',  'c',
        '-',  's',  'h',  'a',  '2',
        '5',  '6',  0,
        // Time signed
           0x00, 0x00,
        0x65, 0xA1, 0xB2, 0xC3,
        // Fudge: 300
        0x01,
        0x2C,
        // MAC size: 0
        0x00, 0x00,
        // (no MAC data)
        // Original ID
        0xAB, 0xCD,
        // Error: BADSIG (16)
        0x00, 0x10,
        // Other length: 0
        0x00, 0x00,
    };

    // TSIG with 32-byte MAC (SHA-256)
    const sha256_tsig = [_]u8{
        // Key name "mykey."
        5,    'm',  'y',  'k',  'e',  'y',  0,
        // TYPE = TSIG (250)
        0x00, 0xFA,
        // CLASS = ANY (255)
        0x00, 0xFF,
        // TTL = 0
        0x00, 0x00, 0x00,
        0x00,
        // RDLENGTH = 61
        0x00, 0x3D,
        // Algorithm "hmac-sha256."
        11,   'h',  'm',  'a',
        'c',  '-',  's',  'h',  'a',  '2',  '5',
        '6',  0,
        // Time signed
           0x00, 0x00, 0x00, 0x00, 0x00,
        0x01,
        // Fudge: 300
        0x01, 0x2C,
        // MAC size: 32
        0x00, 0x20,
        // MAC (32 bytes)
        0x01, 0x02,
        0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
        0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E,
        0x1F, 0x20,
        // Original ID
        0xBE, 0xEF,
        // Error: NOERROR (0)
        0x00, 0x00,
        // Other length: 0
        0x00,
        0x00,
    };
};

test "TSIG decode - basic TSIG record" {
    var memory = try DNSMemory.init();
    defer memory.deinit();

    var reader = try memory.getReader(.{ .fixed = &tsig_test_data.basic_tsig });
    defer reader.deinit();

    var additional = try Additional.decode(&reader);
    defer additional.deinit();

    // Verify inner record
    try testing.expect(additional._inner.type == .TSIG);
    try testing.expect(additional._inner.class == .ANY);
    try testing.expectEqual(@as(u32, 0), additional._inner.ttl);

    // Verify key name
    const keyName = try std.fmt.allocPrint(testing.allocator, "{f}", .{&additional._inner.name});
    defer testing.allocator.free(keyName);
    try testing.expectEqualStrings("test.", keyName);

    // Verify TSIG data
    switch (additional._adata) {
        .TSIG => |tsig| {
            // Verify algorithm
            const algoName = try std.fmt.allocPrint(testing.allocator, "{f}", .{&tsig.algorithm});
            defer testing.allocator.free(algoName);
            try testing.expectEqualStrings("hmac-sha256.", algoName);

            try testing.expectEqual(@as(u48, 1), tsig.timeSigned);
            try testing.expectEqual(@as(u16, 300), tsig.fudge);
            try testing.expectEqualSlices(u8, &[_]u8{ 0xDE, 0xAD, 0xBE, 0xEF }, tsig.mac);
            try testing.expectEqual(@as(u16, 0x1234), tsig.originalID);
            try testing.expect(tsig.rcode == .noError);
            try testing.expectEqual(@as(u16, 0), tsig.otherLen);
        },
    }
}

test "TSIG decode - error response with BADSIG" {
    var memory = try DNSMemory.init();
    defer memory.deinit();

    var reader = try memory.getReader(.{ .fixed = &tsig_test_data.error_tsig });
    defer reader.deinit();

    var additional = try Additional.decode(&reader);
    defer additional.deinit();

    switch (additional._adata) {
        .TSIG => |tsig| {
            try testing.expectEqual(@as(usize, 0), tsig.mac.len);
            try testing.expectEqual(@as(u16, 0xABCD), tsig.originalID);
            try testing.expect(tsig.rcode == .badSig);
            try testing.expectEqual(@as(u48, 0x0000_65A1_B2C3), tsig.timeSigned);
        },
    }
}

test "TSIG decode - 32-byte MAC" {
    var memory = try DNSMemory.init();
    defer memory.deinit();

    var reader = try memory.getReader(.{ .fixed = &tsig_test_data.sha256_tsig });
    defer reader.deinit();

    var additional = try Additional.decode(&reader);
    defer additional.deinit();

    // Verify key name
    const keyName = try std.fmt.allocPrint(testing.allocator, "{f}", .{&additional._inner.name});
    defer testing.allocator.free(keyName);
    try testing.expectEqualStrings("mykey.", keyName);

    switch (additional._adata) {
        .TSIG => |tsig| {
            try testing.expectEqual(@as(usize, 32), tsig.mac.len);
            try testing.expectEqual(@as(u16, 0xBEEF), tsig.originalID);

            // Verify MAC contents
            const expected_mac = [_]u8{
                0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
                0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
                0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20,
            };
            try testing.expectEqualSlices(u8, &expected_mac, tsig.mac);
        },
    }
}

test "TSIG decode/encode round trip" {
    var memory = try DNSMemory.init();
    defer memory.deinit();

    // Decode
    var reader = try memory.getReader(.{ .fixed = &tsig_test_data.basic_tsig });
    defer reader.deinit();

    var additional = try Additional.decode(&reader);
    defer additional.deinit();

    // Encode
    var buf: [512]u8 = undefined;
    var writer = try memory.getWriter(.{ .fixed = &buf });
    defer writer.deinit();

    try additional.encode(&writer);

    // Compare
    try testing.expectEqualSlices(u8, &tsig_test_data.basic_tsig, writer.writer.buffered());
}

test "TSIG decode/encode round trip - error response" {
    var memory = try DNSMemory.init();
    defer memory.deinit();

    // Decode
    var reader = try memory.getReader(.{ .fixed = &tsig_test_data.error_tsig });
    defer reader.deinit();

    var additional = try Additional.decode(&reader);
    defer additional.deinit();

    // Encode
    var buf: [512]u8 = undefined;
    var writer = try memory.getWriter(.{ .fixed = &buf });
    defer writer.deinit();

    try additional.encode(&writer);

    // Compare
    try testing.expectEqualSlices(u8, &tsig_test_data.error_tsig, writer.writer.buffered());
}

test "TSIG decode/encode round trip - 32-byte MAC" {
    var memory = try DNSMemory.init();
    defer memory.deinit();

    // Decode
    var reader = try memory.getReader(.{ .fixed = &tsig_test_data.sha256_tsig });
    defer reader.deinit();

    var additional = try Additional.decode(&reader);
    defer additional.deinit();

    // Encode
    var buf: [512]u8 = undefined;
    var writer = try memory.getWriter(.{ .fixed = &buf });
    defer writer.deinit();

    try additional.encode(&writer);

    // Compare
    try testing.expectEqualSlices(u8, &tsig_test_data.sha256_tsig, writer.writer.buffered());
}
