const builtin = @import("builtin");
const std = @import("std");

// IO
const io = std.io;
const Writer = io.Writer;
const Reader = io.Reader;

//--------------------------------------------------
// DNS Helpers
const treebeard = @import("root.zig");

pub fn main() !void {
    const allocator = std.heap.page_allocator;
    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

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
        queryDNS(domain, rtype) catch |err| {
            std.debug.print("Query failed: {}\n", .{err});
        };
    }
}

fn queryDNS(domain: []const u8, record: treebeard.Type) !void {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var message = try treebeard.buildQuery(allocator, domain, record);
    defer message.deinit();

    var buf = std.mem.zeroes([512]u8);
    var writer = Writer.fixed(&buf);

    try message.encode(&writer);

    // Get the written slice
    const written_data = writer.buffered();
    // Send over UDP
    const address = try std.net.Address.parseIp("127.0.0.1", 53); // example: DNS port
    const socket = try std.posix.socket(address.any.family, std.posix.SOCK.DGRAM, std.posix.IPPROTO.UDP);
    defer std.posix.close(socket);

    var response = std.mem.zeroes([512]u8);
    _ = try std.posix.sendto(socket, written_data, 0, &address.any, address.getOsSockLen());
    const recv_len = try std.posix.recv(socket, &response, 0);

    var i: u16 = 0;
    for (response[0..recv_len]) |b| {
        // std.debug.print(" {d:0>3}", .{b});
        if (i != 0 and @mod(i, 8) == 0) std.debug.print("  ", .{});
        if (i != 0 and @mod(i, 16) == 0) std.debug.print("\n", .{});
        std.debug.print(" {x:0>2}", .{b});
        i += 1;
    }
    std.debug.print("\n", .{});

    var reader = Reader.fixed(response[0..recv_len]);
    var msg = try treebeard.Message.decode(allocator, &reader);
    defer msg.deinit();

    for (msg.answers.items) |a| {
        try a.display();
    }
}
