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

pub fn encode(self: *const Additional, writer: *DNSWriter) !void {
    try self._inner.encode(writer);
    switch (self._adata) {
        .TSIG => |*data| {
            // Write RDATA Length
            const rdata_len =
                data.algorithm.encodeLength() +
                @sizeOf(@TypeOf(data.timeSigned)) +
                @sizeOf(@TypeOf(data.fudge)) +
                @sizeOf(u16) + // u16 for MAC length
                data.mac.len +
                @sizeOf(@TypeOf(data.originalID)) +
                @sizeOf(@TypeOf(data.rcode)) +
                @sizeOf(@TypeOf(data.otherLen));
            try writer.writer.writeInt(u16, rdata_len, .big);

            // Write RDATA
            try data.algorithm.encode(writer);
            try writer.writer.writeInt(u48, data.timeSigned, .big);
            try writer.writer.writeInt(u16, data.fudge, .big);
            try writer.writer.writeInt(u16, data.mac.len, .big);
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
