/// ip.zig
/// Gets a list of all ip addresses on a system, which interface they belong to,
/// and what type of address it is (dynamic/static).
///
/// To run: `zig run util/ip.zig -lc`
const std = @import("std");
const linux = std.os.linux;
const posix = std.posix;
const c = @cImport({
    @cInclude("net/if.h");
});

const BUFFER_SIZE = 8192;

const ifaddrmsg = extern struct {
    family: u8,
    prefixlen: u8,
    flags: u8,
    scope: u8,
    index: u32,
};

const rtattr = extern struct {
    len: c_ushort,
    type: c_ushort,
};

const IFA_ADDRESS = 1;
const IFA_LOCAL = 2;

const IFA_F_PERMANENT = 0x80;
const IFA_F_TEMPORARY = 0x01;

fn RTA_ALIGN(len: usize) usize {
    return (len + 3) & ~@as(usize, 3);
}

fn RTA_OK(rta: *align(1) const rtattr, len: usize) bool {
    return len >= @sizeOf(rtattr) and rta.len >= @sizeOf(rtattr) and rta.len <= len;
}

fn RTA_NEXT(rta: *align(1) const rtattr, len: *usize) *align(1) const rtattr {
    const aligned_len = RTA_ALIGN(rta.len);
    len.* -= aligned_len;
    return @ptrFromInt(@intFromPtr(rta) + aligned_len);
}

fn RTA_DATA(rta: *align(1) const rtattr) [*]const u8 {
    return @ptrFromInt(@intFromPtr(rta) + RTA_ALIGN(@sizeOf(rtattr)));
}

pub fn main() !void {
    const stdout_file = std.fs.File.stdout();
    var stdout_buf: [4096]u8 = undefined;
    var file_writer = std.fs.File.Writer.init(stdout_file, &stdout_buf);
    const stdout = &file_writer.interface;

    // Create netlink socket
    const sock = try posix.socket(linux.AF.NETLINK, linux.SOCK.RAW, linux.NETLINK.ROUTE);
    defer posix.close(sock);

    // Prepare request for all addresses
    const Request = extern struct {
        nlh: linux.nlmsghdr,
        ifa: ifaddrmsg,
    };

    var req = std.mem.zeroes(Request);
    req.nlh.len = @sizeOf(linux.nlmsghdr) + @sizeOf(ifaddrmsg);
    req.nlh.type = linux.NetlinkMessageType.RTM_GETADDR;
    req.nlh.flags = linux.NLM_F_REQUEST | linux.NLM_F_DUMP;
    req.ifa.family = linux.AF.UNSPEC;

    // Send request
    _ = try posix.send(sock, std.mem.asBytes(&req), 0);

    // Receive and parse response
    var buffer: [BUFFER_SIZE]u8 = undefined;

    outer: while (true) {
        const len = try posix.recv(sock, &buffer, 0);
        if (len == 0) break;

        var remaining: usize = len;
        var nlh: *align(1) linux.nlmsghdr = @ptrCast(&buffer);

        while (remaining >= @sizeOf(linux.nlmsghdr) and nlh.len >= @sizeOf(linux.nlmsghdr) and nlh.len <= remaining) {
            if (nlh.type == .DONE) {
                break :outer;
            }

            if (nlh.type == .ERROR) {
                std.debug.print("Netlink error\n", .{});
                return error.NetlinkError;
            }

            if (nlh.type == .RTM_NEWADDR) {
                const ifa: *align(1) ifaddrmsg = @ptrFromInt(@intFromPtr(nlh) + @sizeOf(linux.nlmsghdr));

                // Calculate RTA start and length
                var rta_len: usize = nlh.len - @sizeOf(linux.nlmsghdr) - @sizeOf(ifaddrmsg);
                var rta: *align(1) const rtattr = @ptrFromInt(@intFromPtr(ifa) + RTA_ALIGN(@sizeOf(ifaddrmsg)));

                var addr: ?[*]const u8 = null;

                // Parse attributes
                while (RTA_OK(rta, rta_len)) {
                    if (rta.type == IFA_ADDRESS or rta.type == IFA_LOCAL) {
                        addr = RTA_DATA(rta);
                    }
                    rta = RTA_NEXT(rta, &rta_len);
                }

                // Get interface name from index
                var if_name_buf: [c.IFNAMSIZ]u8 = undefined;
                const interface_name: []const u8 = if (c.if_indextoname(ifa.index, &if_name_buf)) |name|
                    std.mem.sliceTo(name, 0)
                else
                    "unknown";

                if (addr) |a| {
                    if (ifa.family == linux.AF.INET) {
                        try stdout.print("IPv4: {}.{}.{}.{} on {s} ", .{ a[0], a[1], a[2], a[3], interface_name });
                    } else if (ifa.family == linux.AF.INET6) {
                        // Format IPv6 as hex pairs with colons
                        try stdout.print("IPv6: {x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2} on {s} ", .{
                            a[0],           a[1], a[2],  a[3],  a[4],  a[5],  a[6],  a[7],
                            a[8],           a[9], a[10], a[11], a[12], a[13], a[14], a[15],
                            interface_name,
                        });
                    } else {
                        continue;
                    }

                    // Check flags to determine if DHCP/SLAAC
                    if (ifa.flags & IFA_F_PERMANENT != 0) {
                        try stdout.print("[STATIC/PERMANENT]\n", .{});
                    } else if (ifa.flags & IFA_F_TEMPORARY != 0) {
                        try stdout.print("[SLAAC PRIVACY/TEMPORARY]\n", .{});
                    } else {
                        try stdout.print("[DYNAMIC/RUNTIME]\n", .{});
                    }
                }
            }

            // Move to next message
            const aligned_len = (nlh.len + 3) & ~@as(u32, 3);
            if (aligned_len >= remaining) break;
            remaining -= aligned_len;
            nlh = @ptrFromInt(@intFromPtr(nlh) + aligned_len);
        }
    }

    try file_writer.interface.flush();
}
