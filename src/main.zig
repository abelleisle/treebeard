const builtin = @import("builtin");
const std = @import("std");

// IO
const io = std.io;
const Writer = io.Writer;
const Reader = io.Reader;

//--------------------------------------------------
// DNS Helpers
const treebeard = @import("treebeard");

pub fn main() !void {
    const allocator = std.heap.page_allocator;
    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    var pool = try treebeard.DNSMemory.init();
    defer pool.deinit();

    const domain = if (args.len > 1) args[1] else "bitcicle.com";
    std.debug.print("Querying DNS records for: {s}\n", .{domain});

    inline for (.{
        treebeard.Type.A,
        treebeard.Type.AAAA,
        treebeard.Type.MX,
        treebeard.Type.TXT,
    }) |rtype| {
        const name = @tagName(rtype);
        std.debug.print("\n=== {s} Records ===\n", .{name});
        queryDNS(&pool, domain, rtype) catch |err| {
            std.debug.print("Query failed: {}\n", .{err});
        };
    }
}

fn queryDNS(memory: *treebeard.DNSMemory, domain: []const u8, record: treebeard.Type) !void {
    var message = try treebeard.buildQuery(memory, domain, record);
    defer message.deinit();

    // Try UDP first
    queryDNS_UDP(memory, &message) catch |err| {
        if (err == error.TruncatedMessage) {
            std.debug.print("Message truncated, retrying with TCP...\n", .{});
            try queryDNS_TCP(memory, &message);
        } else {
            return err;
        }
    };
}

fn queryDNS_UDP(memory: *treebeard.DNSMemory, message: *treebeard.Message) !void {
    var writer = try memory.getWriter(.udp);
    defer writer.deinit();

    try message.encode(&writer);

    // Get the written slice
    const written_data = writer.writer.buffered();
    // Send over UDP
    const address = try std.net.Address.parseIp("127.0.0.1", 53);
    const socket = try std.posix.socket(address.any.family, std.posix.SOCK.DGRAM, std.posix.IPPROTO.UDP);
    defer std.posix.close(socket);

    var reader = try memory.getReader(.udp);
    defer reader.deinit();

    _ = try std.posix.sendto(socket, written_data, 0, &address.any, address.getOsSockLen());
    const recv_len = try std.posix.recv(socket, reader.reader.buffer, 0);

    printHex(reader.reader.buffer[0..recv_len]);

    var msg = try treebeard.Message.decode(&reader);
    defer msg.deinit();

    for (msg.answers.items) |a| {
        try a.display();
    }
}

fn queryDNS_TCP(memory: *treebeard.DNSMemory, message: *treebeard.Message) !void {
    const address = try std.net.Address.parseIp("127.0.0.1", 53);
    const stream = try std.net.tcpConnectToAddress(address);
    defer stream.close();

    // Encode message to buffer first (need to know length for TCP)
    var writer = try memory.getWriter(.allocating);
    defer writer.deinit();

    try message.encode(&writer);
    const message_data = writer.writer.buffered();

    // DNS over TCP requires a 2-byte length prefix
    // Build the complete TCP message: [2-byte length][DNS message]
    var tcp_buf = std.mem.zeroes([4098]u8);
    var tcp_writer = Writer.fixed(&tcp_buf);
    try tcp_writer.writeInt(u16, @intCast(message_data.len), .big);
    try tcp_writer.writeAll(message_data);

    // Send the complete message
    _ = try stream.write(tcp_writer.buffered());

    // Read response: first 2 bytes are length
    var len_buf: [2]u8 = undefined;
    const len_read = try stream.read(&len_buf);
    if (len_read != 2) return error.IncompleteRead;
    var len_reader = Reader.fixed(&len_buf);
    const response_len = try len_reader.takeInt(u16, .big);

    // Read the actual DNS message
    const response = try memory.alloc().alloc(u8, response_len);
    defer memory.alloc().free(response);
    var total_read: usize = 0;
    while (total_read < response_len) {
        const n = try stream.read(response[total_read..]);
        if (n == 0) return error.ConnectionClosed;
        total_read += n;
    }

    printHex(response);

    var reader = try memory.getReader(.{ .fixed = response });
    defer reader.deinit();
    var msg = try treebeard.Message.decode(&reader);
    defer msg.deinit();

    for (msg.answers.items) |a| {
        try a.display();
    }
}

fn printHex(data: []const u8) void {
    var i: u16 = 0;
    for (data) |b| {
        if (i != 0 and @mod(i, 8) == 0) std.debug.print("  ", .{});
        if (i != 0 and @mod(i, 16) == 0) std.debug.print("\n", .{});
        std.debug.print(" {x:0>2}", .{b});
        i += 1;
    }
    std.debug.print("\n", .{});
}
