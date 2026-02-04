// std
const std = @import("std");

// networking
const net = std.Io.net;
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
    var threaded: std.Io.Threaded = .init(memory.alloc(), .{
        .environ = .empty,
    });
    defer threaded.deinit();

    const io = threaded.io();

    const baseName = try Name.fromStr("");
    var zone = try Zone.initDict(memory, baseName);
    defer zone.deinit();

    // IPv4 Records
    {
        {
            const record = Record{
                .memory = memory,
                .class = .IN,
                .type = .A,
                .name = try Name.fromStr("*.com"),
                .ttl = 300,
                .rdata = .{ .A = .{ 1, 1, 1, 1 } },
            };

            try zone.backend.dict.records.IN.A.add(&record);
        }
        {
            const record = Record{
                .memory = memory,
                .class = .IN,
                .type = .A,
                .name = try Name.fromStr("google.com"),
                .ttl = 300,
                .rdata = .{ .A = .{ 1, 2, 3, 4 } },
            };

            try zone.backend.dict.records.IN.A.add(&record);
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

            try zone.backend.dict.records.IN.A.add(&record);
        }
    }
    // IPv6 Records
    {
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

            try zone.backend.dict.records.IN.AAAA.add(&record);
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

            try zone.backend.dict.records.IN.AAAA.add(&record);
        }
    }

    // const receiver = try net.Address.parseIp6("::1", 9091);
    const receiver = net.Ip4Address{ .bytes = .{ 127, 0, 0, 1 }, .port = 9091 };
    const ip = net.IpAddress{ .ip4 = receiver };
    const sock = try ip.bind(io, .{ .ip6_only = false, .mode = .dgram, .protocol = .udp });

    defer sock.close(io);

    // var expected_seq: u32 = 0;

    var requests: usize = 0;
    while (true) {
        var reader = try memory.getReader(.udp);
        defer reader.deinit();
        const buf = reader.reader.buffer;

        const incoming = try sock.receive(io, buf);
        if (incoming.data.len == 0) continue;

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
        try sock.send(io, &incoming.from, writer.writer.buffered());

        requests += 1;
        std.debug.print("\rRequests: {d}", .{requests});
    }
}

fn handle_message(memory: *DNSMemory, zone: *Zone, message: *Message) !void {
    message.header.flags.QR = true;
    message.header.flags.RA = true;
    message.header.flags.AD = false;
    message.header.numAddRR = 0;
    if (message.header.flags.RD) {
        for (message.questions.items) |*question| {
            const answers = try zone.query(&question.name, question.type, question.class);
            if (answers) |answer| {
                const len = answer.items.len;
                const start = memory.randRange(usize, 0, len);
                for (answer.items[start..len]) |a| {
                    try message.addAnswer(a);
                    // TODO this is hacky
                    message.answers.items[message.answers.items.len - 1].name = question.name;
                }
                for (answer.items[0..start]) |a| {
                    try message.addAnswer(a);
                    // TODO this is hacky
                    message.answers.items[message.answers.items.len - 1].name = question.name;
                }
            } else {
                return error.NoDomain;
            }
        }
    }
}
