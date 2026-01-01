/// pool.zig
/// This is a set of memory pools that we use to fetch memory for use around
/// our DNS library. The point of us doing this is that we have nearly zero cost
/// allocations for use during en/decoding of DNS packets.

// std
const std = @import("std");

// IO
const Io = std.Io;
const Reader = Io.Reader;
const Writer = Io.Writer;

// Memory
const mem = std.mem;
const Allocator = mem.Allocator;

// Heap
const heap = std.heap;
const ArenaAllocator = heap.ArenaAllocator;

// DNS
const transport = @import("transport/memory.zig");

//--------------------------------------------------
// Types
const UDPMessageBuffer = [512]u8;
const LabelPointer = []const u8;

const UDPBufPool = std.heap.MemoryPool(UDPMessageBuffer);
const LabelBufPool = std.heap.MemoryPool(LabelPointer);

const PoolType = union(enum) {
    UDP,
};

//--------------------------------------------------
// Pools

/// UDP message buffers
const UDPMessagePool = struct {
    pool: UDPBufPool,

    pub fn init(allocator: Allocator) UDPMessagePool {
        return UDPMessagePool{ .pool = UDPBufPool.init(allocator) };
    }

    pub fn deinit(self: *UDPMessagePool) void {
        self.pool.deinit();
    }

    /// Allocate multiple UDP message buffers at once
    /// Returns a slice of pointers to the allocated buffers
    /// Caller must call destroyMany() to free
    pub fn createMany(self: *UDPMessagePool, allocator: Allocator, count: usize) ![]*align(8) UDPMessageBuffer {
        const buffers = try allocator.alloc(*align(8) UDPMessageBuffer, count);
        errdefer allocator.free(buffers);

        var i: usize = 0;
        errdefer {
            // Clean up any allocated buffers on failure
            for (buffers[0..i]) |buf| {
                self.pool.destroy(buf);
            }
        }

        while (i < count) : (i += 1) {
            buffers[i] = try self.pool.create();
        }

        return buffers;
    }

    /// Free multiple UDP message buffers at once
    pub fn destroyMany(self: *UDPMessagePool, allocator: Allocator, buffers: []*align(8) UDPMessageBuffer) void {
        for (buffers) |buf| {
            self.pool.destroy(buf);
        }
        allocator.free(buffers);
    }
};

const LabelPool = struct {
    pool: LabelBufPool,

    pub fn init(allocator: Allocator) LabelPool {
        return LabelPool{ .pool = LabelBufPool.init(allocator) };
    }

    pub fn deinit(self: *LabelPool) void {
        self.pool.deinit();
    }
};

/// Master DNS pool.
/// This is used to handle all "child" pools, a memory context of sorts.
const DNSMemory = struct {
    // Global allocator for general allocations
    arena: ArenaAllocator,

    // Pools
    pools: struct {
        udp: UDPMessagePool,
        label: LabelPool,
    },

    pub fn init() !DNSMemory {
        // Use page_allocator for arena backing
        var arena = ArenaAllocator.init(std.heap.page_allocator);
        errdefer arena.deinit();

        // Pools need an allocator that supports individual frees,
        // so use page_allocator directly
        const pool_allocator = std.heap.page_allocator;

        return DNSMemory{
            .arena = arena,
            .pools = .{
                .udp = UDPMessagePool.init(pool_allocator),
                .label = LabelPool.init(pool_allocator),
            },
        };
    }

    pub fn deinit(self: *DNSMemory) void {
        // Free child pools
        self.pools.udp.deinit();
        self.pools.label.deinit();

        // Free arena allocator
        self.arena.deinit();
    }

    pub fn getReader(self: *DNSMemory, readerType: PoolType) !DNSReader {
        switch (readerType) {
            .UDP => {
                const buf = try self.pools.udp.pool.create();
                return DNSReader{
                    .reader = Reader.fixed(buf),
                    .readerType = ReaderType{ .udp = buf },
                };
            },
        }
    }

    /// Return (destroy) the allocated reader.
    /// Note: passing `reader` transfers ownership back to our DNSMemory
    /// object.
    pub fn returnReader(self: *DNSMemory, reader: *DNSReader) void {
        switch (reader.readerType) {
            .udp => |buf| self.pools.udp.pool.destroy(buf),
            .fixed => |buf| self.arena.allocator().free(buf),
        }
    }

    pub fn getWriter(self: *DNSMemory, writerType: PoolType) !DNSWriter {
        switch (writerType) {
            .UDP => {
                const buf = try self.pools.udp.pool.create();
                return DNSWriter{
                    .writer = Writer.fixed(buf),
                    .writerType = WriterType{ .udp = buf },
                };
            },
        }
    }

    /// Return (destroy) the allocated writer.
    /// Note: passing `writer` transfers ownership back to our DNSMemory
    /// object.
    pub fn returnWriter(self: *DNSMemory, writer: *DNSWriter) void {
        switch (writer.writerType) {
            .udp => |buf| self.pools.udp.pool.destroy(buf),
            .fixed => |buf| self.arena.allocator().free(buf),
            .allocating => |*alloc| alloc.deinit(),
        }
    }
};

const ReaderType = union(enum) {
    fixed: []u8,
    udp: *align(8) UDPMessageBuffer,
};

const WriterType = union(enum) {
    fixed: []u8,
    udp: *align(8) UDPMessageBuffer,
    allocating: Writer.Allocating,
};

pub const DNSReader = struct {
    reader: Reader,
    readerType: ReaderType,
};

pub const DNSWriter = struct {
    writer: Writer,
    writerType: WriterType,
};

//--------------------------------------------------
// Testing
const testing = std.testing;
const t = @import("dns/testing.zig");
const Message = @import("dns/Message.zig");

test "create main pool" {
    var pool = try DNSMemory.init();
    defer pool.deinit();
}

test "udp pool create two buffers with test allocator" {
    var udp_pool = UDPBufPool.init(testing.allocator);
    defer udp_pool.deinit();

    const buf1 = try udp_pool.create();
    buf1[0] = 42;
    try testing.expectEqual(42, buf1[0]);

    const buf2 = try udp_pool.create();
    buf2[0] = 43;
    try testing.expectEqual(43, buf2[0]);

    udp_pool.destroy(buf1);
    udp_pool.destroy(buf2);
}

test "udp pool create many buffers" {
    var pool = try DNSMemory.init();
    defer pool.deinit();

    // Allocate 5 buffers at once
    const buffers = try pool.pools.udp.createMany(pool.arena.allocator(), 5);
    defer pool.pools.udp.destroyMany(pool.arena.allocator(), buffers);

    // Verify we got 5 buffers
    try testing.expectEqual(5, buffers.len);

    // Write different values to each buffer
    for (buffers, 0..) |buf, i| {
        buf[0] = @intCast(i + 10);
    }

    // Verify the values
    for (buffers, 0..) |buf, i| {
        try testing.expectEqual(@as(u8, @intCast(i + 10)), buf[0]);
    }
}

test "udp pool create two buffers" {
    var pool = try DNSMemory.init();
    defer pool.deinit();

    const buf1 = try pool.pools.udp.pool.create();
    buf1[0] = 42;
    try testing.expectEqual(42, buf1[0]);

    const buf2 = try pool.pools.udp.pool.create();
    buf2[0] = 43;
    try testing.expectEqual(43, buf2[0]);

    pool.pools.udp.pool.destroy(buf1);
    pool.pools.udp.pool.destroy(buf2);
}

test "udp reader and writer" {
    var pool = try DNSMemory.init();
    defer pool.deinit();

    var reader = try pool.getReader(.UDP);
    defer pool.returnReader(&reader);

    // This is pretty hacky and I don't love it
    @memcpy(reader.reader.buffer[0..t.data.query.duckduckgo_simple.len], t.data.query.duckduckgo_simple);

    var message = try Message.decode(pool.arena.allocator(), &reader.reader);
    defer message.deinit();

    var writer = try pool.getWriter(.UDP);
    defer pool.returnWriter(&writer);

    try message.encode(&writer.writer);
}
