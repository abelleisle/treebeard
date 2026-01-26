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

//--------------------------------------------------
// DNS UDP Recv functions

// recv packets in a loop and ack them until we recv an EoT
pub fn recv_loop(memory: *DNSMemory) !void {
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

        handle_message(memory, &message) catch |err| {
            if (err == error.TruncatedMessage) {
                message.header.flags.TC = true;
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

fn handle_message(memory: *DNSMemory, message: *Message) !void {
    message.header.flags.QR = true;
    message.header.flags.RA = true;
    message.header.flags.AD = false;
    message.header.numAddRR = 0;
    if (message.header.flags.RD) {
        for (message.questions.items) |*question| {
            switch (question.class) {
                .IN => {
                    switch (question.type) {
                        .A => {
                            const record = Record{
                                .name = question.name,
                                .type = .A,
                                .class = .IN,
                                .ttl = 300,
                                .memory = memory,
                                .rdata = Record.RData{ .A = .{ 1, 2, 3, 4 } },
                            };
                            try message.addAnswer(record);
                        },
                        .AAAA => {
                            const record = Record{
                                .name = question.name,
                                .type = .AAAA,
                                .class = .IN,
                                .ttl = 300,
                                .memory = memory,
                                .rdata = Record.RData{ .AAAA = .{ 0x20, 0x01, 0x4, 0x70, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x12, 0x34 } },
                            };
                            try message.addAnswer(record);
                        },
                        else => {
                            return error.UnsupportedType;
                        },
                    }
                },
                else => {
                    return error.UnsupportedClass;
                },
            }
        }
    }
}
