const std = @import("std");

// Memory
const Allocator = std.mem.Allocator;

// IO
const Io = std.Io;
const Reader = Io.Reader;
const Writer = Io.Writer;
const Socket = Io.net.Socket;
const Protocol = Io.net.Protocol;

// DNS
const treebeard = @import("treebeard");
const DNSMemory = treebeard.DNSMemory;

const Message = treebeard.Message;

//--------------------------------------------------
// DNS Context
const Context = @This();

/// Our context's DNS memory
memory: *DNSMemory,

/// Request buffer
requestBuf: union(enum) {
    owned: []u8,
    borrowed: []const u8,
},

/// Response buffer
responseBuf: []u8,

/// Reader used to decode input
reader: Reader,

/// Writer used to encode output
writer: Writer,

/// Creates a request context
pub fn requestFromWire(memory: *DNSMemory, length: ?usize) !Context {
    // TODO store 512 in a constant
    const rBuf = try memory.alloc().alloc(u8, length orelse 512);
    return Context{
        .memory = memory,
        .requestBuf = .{ .owned = rBuf },
        .responseBuf = &[_]u8{},
        .reader = Reader.fixed(rBuf),
        .writer = Writer.fixed(&[_]u8{}),
    };
}

/// Creates a request context from a buffer
pub fn requestFromWireBuf(memory: *DNSMemory, buf: []const u8) !Context {
    return Context{
        .memory = memory,
        .requestBuf = .{ .borrowed = buf },
        .responseBuf = &[_]u8{},
        .reader = Reader.fixed(buf),
        .writer = Writer.fixed(&[_]u8{}),
    };
}

/// De-inits our context and returns the allocated buffers back
/// to the memory pools
pub fn deinit(ctx: *Context) void {
    // Try to free our buffers. Zero length bufs will be a no-op.
    switch (ctx.requestBuf) {
        .owned => |o| ctx.memory.alloc().free(o),
        .borrowed => {},
    }
    ctx.memory.alloc().free(ctx.responseBuf);

    // Reset our reader + writer to point to a "null" slice.
    ctx.reader = Reader.fixed(&[_]u8{});
    ctx.writer = Writer.fixed(&[_]u8{});
}

/// Get the allocator for use with this context
pub inline fn alloc(ctx: *const Context) Allocator {
    return ctx.memory.alloc();
}

//--------------------------------------------------
// Testing
const testing = std.testing;

test "confirm 0 length buffer" {
    // Owned request
    {
        var pool = try DNSMemory.init();
        defer pool.deinit();

        var req = try Context.requestFromWire(&pool, null);
        defer req.deinit();

        try testing.expectEqual(512, req.requestBuf.owned.len);
        try testing.expectEqual(0, req.responseBuf.len);
    }

    // Borrowed request
    {
        const testBuf = "thisisatestbufferlol";

        var pool = try DNSMemory.init();
        defer pool.deinit();

        var req = try Context.requestFromWireBuf(&pool, testBuf);
        defer req.deinit();

        try testing.expectEqual(testBuf.len, req.requestBuf.borrowed.len);
        try testing.expectEqual(0, req.responseBuf.len);
    }
}
