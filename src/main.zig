const builtin = @import("builtin");
const std = @import("std");

//--------------------------------------------------
// DNS Helpers
const treebeard = @import("treebeard");
const udp = @import("transport/udp.zig");

pub fn main() !void {
    const allocator = std.heap.page_allocator;
    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    var pool = try treebeard.DNSMemory.init();
    defer pool.deinit();

    try pool.preheat(.{
        .udp = 1024,
    });

    try udp.recv_loop(&pool);

    // const domain = if (args.len > 1) args[1] else "bitcicle.com";
    // std.debug.print("Querying DNS records for: {s}\n", .{domain});
    //
    // inline for (.{
    //     treebeard.Type.A,
    //     treebeard.Type.AAAA,
    //     treebeard.Type.MX,
    //     treebeard.Type.TXT,
    // }) |rtype| {
    //     const name = @tagName(rtype);
    //     std.debug.print("\n=== {s} Records ===\n", .{name});
    //     queryDNS(&pool, domain, rtype) catch |err| {
    //         std.debug.print("Query failed: {}\n", .{err});
    //     };
    // }
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

    var tcp_writer = try memory.getWriter(.allocating);
    defer tcp_writer.deinit();

    // DNS over TCP requires a 2-byte length prefix
    // Build the complete TCP message: [2-byte length][DNS message]
    // For now, but a placeholder length
    try tcp_writer.writer.writeInt(u16, 0x1234, .big);
    try message.encode(&tcp_writer);

    const len: u16 = @intCast(tcp_writer.writer.end - 2); // Remove the 2 byte
    // length header
    tcp_writer.writer.buffer[0] = @intCast((len & 0xFF00) >> 8);
    tcp_writer.writer.buffer[1] = @intCast((len & 0x00FF));

    // Send the complete message
    const written = try stream.write(tcp_writer.writer.buffered());
    if (written != (len + 2)) {
        return error.TCPPacketNotFullyWritten;
    }

    // Read response: first 2 bytes are length
    var len_buf: [2]u8 = undefined;
    const len_read = try stream.read(&len_buf);
    if (len_read != 2) return error.IncompleteRead;
    var len_reader = try memory.getReader(.{ .fixed = &len_buf });
    defer len_reader.deinit();
    const response_len = try len_reader.reader.takeInt(u16, .big);

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

//--------------------------------------------------
// Test references
// This ensures all tests in these files are run when executing `zig build test`

test {
    _ = @import("treebeard");
}
