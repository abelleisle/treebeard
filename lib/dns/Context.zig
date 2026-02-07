const std = @import("std");

// IO
const io = std.Io;
const Reader = io.Reader;
const Writer = io.Writer;

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
requestBuf: []u8,

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
        .requestBuf = rBuf,
        .responseBuf = &[_]u8{},
        .reader = Reader.fixed(rBuf),
        .writer = Writer.fixed(&[_]u8{}),
    };
}

/// De-inits our context and returns the allocated buffers back
/// to the memory pools
pub fn deinit(ctx: *Context) void {
    // Try to free our buffers. Zero length bufs will be a no-op.
    ctx.memory.alloc().free(ctx.requestBuf);
    ctx.memory.alloc().free(ctx.responseBuf);

    // Reset our reader + writer to point to a "null" slice.
    ctx.reader = Reader.fixed(&[_]u8{});
    ctx.writer = Writer.fixed(&[_]u8{});
}

//--------------------------------------------------
// Testing
const testing = std.testing;

test "confirm 0 length buffer" {
    // Requests
    {
        var pool = try DNSMemory.init();
        defer pool.deinit();

        var req = try Context.requestFromWire(&pool, null);
        defer req.deinit();

        try testing.expectEqual(512, req.requestBuf.len);
        try testing.expectEqual(0, req.responseBuf.len);
    }
}
