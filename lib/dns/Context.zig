const std = @import("std");

// IO
const io = std.Io;
const Reader = io.Reader;
const Writer = io.Writer;

// DNS
const treebeard = @import("treebeard");
const DNSMemory = treebeard.DNSMemory;

//--------------------------------------------------
// DNS Context
const Context = @This();

/// Our context's DNS memory
memory: *DNSMemory,

/// Request buffer
_requestBuf: []u8,

/// Response buffer
_responseBuf: []u8,

/// Reader used to decode input
reader: Reader,

/// Writer used to encode output
writer: Writer,

/// Creates a request context
pub fn request(memory: *DNSMemory, length: ?usize) !Context {
    // TODO store 512 in a constant
    const rBuf = try memory.alloc().alloc(u8, length orelse 512);
    return Context{
        .memory = memory,
        .request = rBuf,
        .response = &[_]u8{},
        .read = Reader.fixed(rBuf),
        .write = Writer.fixed(&[_]u8{}),
    };
}
