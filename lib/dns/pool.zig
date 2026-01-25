/// pool.zig
/// This is a set of memory pools that we use to fetch memory for use around
/// our DNS library. The point of us doing this is that we have nearly zero cost
/// allocations for use during en/decoding of DNS packets.

// std
const std = @import("std");
const builtin = @import("builtin");

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

//--------------------------------------------------
// Types
const UDPMessageBuffer = [512]u8;

const UDPBufPool = std.heap.MemoryPool(UDPMessageBuffer);

const PoolType = union(enum) {
    UDP,
    fixed: []const u8,
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

const PreheatOptions = struct {
    udp: u32,
};

/// Master DNS pool.
/// This is used to handle all "child" pools, a memory context of sorts.
pub const DNSMemory = struct {
    // Global allocator for general allocations
    arena: ArenaAllocator,
    _allocator: Allocator, // Only used to access base allocator during testing

    // Pools
    pools: struct {
        udp: UDPMessagePool,
    },

    preheated: bool,

    pub fn init() !DNSMemory {
        // Use testing allocator in test mode, page_allocator otherwise
        const base_allocator = if (builtin.is_test)
            std.testing.allocator
        else
            std.heap.page_allocator;

        var arena = ArenaAllocator.init(base_allocator);
        errdefer arena.deinit();

        // Pools need an allocator that supports individual frees,
        // so use the same base allocator
        const pool_allocator = base_allocator;

        return DNSMemory{
            .arena = arena,
            ._allocator = base_allocator,
            .pools = .{
                .udp = UDPMessagePool.init(pool_allocator),
            },
            .preheated = false,
        };
    }

    pub fn deinit(self: *DNSMemory) void {
        // Free child pools
        self.pools.udp.deinit();

        // Free arena allocator
        self.arena.deinit();
    }

    pub fn preheat(self: *DNSMemory, options: PreheatOptions) !void {
        if (self.preheated) {
            return error.AlreadyPreheated;
        }
        self.preheated = true;

        try self.pools.udp.pool.preheat(options.udp);
    }

    pub inline fn alloc(self: *DNSMemory) Allocator {
        return if (builtin.is_test)
            self._allocator
        else
            self.arena.allocator();
    }

    pub fn getReader(self: *DNSMemory, readerType: ReaderType) !DNSReader {
        switch (readerType) {
            .udp => {
                const buf = try self.pools.udp.pool.create();
                return DNSReader{
                    .reader = Reader.fixed(buf),
                    .readerType = ReaderInnerType{ .udp = buf },
                    .memory = self,
                };
            },
            .fixed => |buf| {
                return DNSReader{
                    .reader = Reader.fixed(buf),
                    .readerType = ReaderInnerType{ .fixed = buf },
                    .memory = self,
                };
            },
        }
    }

    pub fn getWriter(self: *DNSMemory, writerType: WriterType) !DNSWriter {
        switch (writerType) {
            .udp => {
                const buf = try self.pools.udp.pool.create();
                return DNSWriter{
                    .writer = Writer.fixed(buf),
                    .writerType = WriterInnerType{ .udp = buf },
                    .memory = self,
                };
            },
            .fixed => |buf| {
                return DNSWriter{
                    .writer = Writer.fixed(buf),
                    .writerType = WriterInnerType{ .fixed = buf },
                    .memory = self,
                };
            },
            .allocating => {
                const allocator = try Writer.Allocating.initCapacity(self.alloc(), 4096);
                return DNSWriter{
                    .writer = allocator.writer,
                    .writerType = WriterInnerType{ .allocating = allocator },
                    .memory = self,
                };
            },
        }
    }
};

const ReaderType = union(enum) {
    fixed: []const u8,
    udp,
};

const ReaderInnerType = union(enum) {
    fixed: []const u8,
    udp: *align(8) UDPMessageBuffer,
};

pub const DNSReader = struct {
    reader: Reader,
    readerType: ReaderInnerType,

    memory: *DNSMemory,

    /// Return (destroy) the allocated reader.
    /// Note: passing `reader` transfers ownership back to our DNSMemory
    /// object.
    pub fn deinit(self: *DNSReader) void {
        switch (self.readerType) {
            .udp => |buf| self.memory.pools.udp.pool.destroy(buf),
            // .fixed => |buf| self.memory.arena.allocator().free(buf),
            .fixed => {},
        }
    }
};

const WriterType = union(enum) {
    fixed: []u8,
    udp,
    allocating,
};

const WriterInnerType = union(enum) {
    fixed: []u8,
    udp: *align(8) UDPMessageBuffer,
    allocating: Writer.Allocating,
};

pub const DNSWriter = struct {
    writer: Writer,
    writerType: WriterInnerType,

    memory: *DNSMemory,

    /// Return (destroy) the allocated writer.
    /// Note: passing `writer` transfers ownership back to our DNSMemory
    /// object.
    pub fn deinit(self: *DNSWriter) void {
        switch (self.writerType) {
            .udp => |buf| self.memory.pools.udp.pool.destroy(buf),
            // .fixed => |buf| self.memory.arena.allocator().free(buf),
            .fixed => {},
            .allocating => |*alloc| alloc.deinit(),
        }
    }
};

//--------------------------------------------------
// Testing
const testing = std.testing;
const t = @import("core/testing.zig");
const Message = @import("core/Message.zig");

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
    const buffers = try pool.pools.udp.createMany(pool.alloc(), 5);
    defer pool.pools.udp.destroyMany(pool.alloc(), buffers);

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

    var reader = try pool.getReader(.udp);
    defer reader.deinit();

    // This is pretty hacky and I don't love it
    @memcpy(reader.reader.buffer[0..t.data.query.duckduckgo_simple.len], t.data.query.duckduckgo_simple);

    var message = try Message.decode(&reader);
    defer message.deinit();

    var writer = try pool.getWriter(.udp);
    defer writer.deinit();

    try message.encode(&writer);
}
