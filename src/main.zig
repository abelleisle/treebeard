const builtin = @import("builtin");
const std = @import("std");
const treebeard = @import("root.zig");

pub fn main() !void {
    const allocator = std.heap.page_allocator;
    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    const domain = if (args.len > 1) args[1] else "bitcicle.com";
    std.debug.print("Querying DNS records for: {s}\n", .{domain});

    inline for (.{ treebeard.Type.A, treebeard.Type.AAAA, treebeard.Type.MX }) |rtype| {
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
}
