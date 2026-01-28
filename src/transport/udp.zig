// std
const std = @import("std");

// networking
const net = std.net;
const posix = std.posix;

// Core
const treebeard = @import("treebeard");

const Message = treebeard.Message;
const Record = treebeard.Record;
const Name = treebeard.Name;

const DNSMemory = treebeard.DNSMemory;
const Zone = treebeard.Zone;
const RecordList = treebeard.RecordList;

//--------------------------------------------------
// DNS UDP Recv functions

// recv packets in a loop and ack them until we recv an EoT
pub fn recv_loop(memory: *DNSMemory) !void {
    const baseName = try Name.fromStr("");
    var zone = try Zone.initDict(memory, baseName);
    defer zone.deinit();

    // IPv4 Records
    {
        var com = try zone.backend.dict.records.IN.A.addChild("com", null);
        var google = try com.addChild("google", try RecordList.initCapacity(memory.alloc(), 1));

        {
            const record = Record{
                .memory = memory,
                .class = .IN,
                .type = .A,
                .name = try Name.fromStr("google.com"),
                .ttl = 300,
                .rdata = .{ .A = .{ 1, 2, 3, 4 } },
            };

            try google.value.?.append(memory.alloc(), record);
        }
        {
            const record = Record{
                .memory = memory,
                .class = .IN,
                .type = .A,
                .name = try Name.fromStr("google.com"),
                .ttl = 400,
                .rdata = .{ .A = .{ 1, 2, 3, 5 } },
            };

            try google.value.?.append(memory.alloc(), record);
        }
    }
    // IPv6 Records
    {
        var com = try zone.backend.dict.records.IN.AAAA.addChild("com", null);
        var google = try com.addChild("google", try RecordList.initCapacity(memory.alloc(), 1));

        {
            const record = Record{
                .memory = memory,
                .class = .IN,
                .type = .AAAA,
                .name = try Name.fromStr("google.com"),
                .ttl = 300,
                .rdata = .{ .AAAA = .{
                    0x20, 0x01, 0x0d, 0xb8,
                    0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x12, 0x34,
                } },
            };

            try google.value.?.append(memory.alloc(), record);
        }
        {
            const record = Record{
                .memory = memory,
                .class = .IN,
                .type = .AAAA,
                .name = try Name.fromStr("google.com"),
                .ttl = 400,
                .rdata = .{ .AAAA = .{
                    0x20, 0x01, 0x0d, 0xb8,
                    0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x12, 0x35,
                } },
            };

            try google.value.?.append(memory.alloc(), record);
        }
    }

    // const receiver = try net.Address.parseIp6("::1", 9091);
    const receiver = net.Address.initIp4(.{ 127, 0, 0, 1 }, 9091);
    // const receiver = try net.Address.parseIp6("::1", 9091);
    const sock = try posix.socket(
        posix.AF.INET,
        posix.SOCK.DGRAM,
        posix.IPPROTO.UDP,
    );

    try std.posix.bind(sock, @ptrCast(&receiver.any), receiver.in.getOsSockLen());

    // var expected_seq: u32 = 0;

    var addr: std.posix.sockaddr = undefined;
    var addr_len: std.posix.socklen_t = @sizeOf(std.posix.sockaddr);

    var requests: usize = 0;
    while (true) {
        var reader = try memory.getReader(.udp);
        defer reader.deinit();
        const buf = reader.reader.buffer;

        const ret = try posix.recvfrom(sock, @constCast(buf), 0, &addr, &addr_len);
        if (ret == 0) {
            // This shouldn't be possible since the socket is blocking, but lets just be safe.
            continue;
        }

        var message = try Message.decode(&reader);
        defer message.deinit();

        var writer = try memory.getWriter(.udp);
        defer writer.deinit();

        handle_message(memory, &zone, &message) catch |err| {
            if (err == error.TruncatedMessage) {
                message.header.flags.TC = true;
            } else if (err == error.NoDomain) {
                message.header.flags.RCODE = .nxDomain;
            } else {
                message.header.flags.RCODE = .servFail;
            }
        };

        try message.encode(&writer);
        _ = posix.sendto(sock, writer.writer.buffered(), 0, &addr, addr_len) catch |e| {
            return e;
        };

        requests += 1;
        std.debug.print("\rRequests: {d}", .{requests});
    }
}

fn handle_message(memory: *DNSMemory, zone: *Zone, message: *Message) !void {
    _ = memory;
    message.header.flags.QR = true;
    message.header.flags.RA = true;
    message.header.flags.AD = false;
    message.header.numAddRR = 0;
    if (message.header.flags.RD) {
        for (message.questions.items) |*question| {
            const answers = try zone.query(&question.name, question.type, question.class);
            if (answers) |answer| {
                for (answer.items) |a| {
                    try message.addAnswer(a);
                }
            } else {
                return error.NoDomain;
            }
        }
    }
}
