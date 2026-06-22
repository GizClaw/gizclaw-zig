const giznet = @import("giznet");
const glib = @import("glib");

const Rpc = @import("Rpc.zig");
const service = @import("service.zig");

pub const peer_stream_event_version: i64 = 1;
pub const stamped_opus_version: u8 = 1;
pub const stamped_opus_header_size: usize = 8;
const stamped_opus_timestamp_mask: u64 = (1 << 56) - 1;

pub const PeerStreamEventType = enum {
    bos,
    eos,
    text_delta,
    text_done,

    pub fn jsonStringify(self: PeerStreamEventType, writer: anytype) !void {
        try writer.print("{s}", .{switch (self) {
            .bos => "\"bos\"",
            .eos => "\"eos\"",
            .text_delta => "\"text.delta\"",
            .text_done => "\"text.done\"",
        }});
    }
};

pub const PeerStreamKind = enum {
    audio,
    mixed,
    text,
    video,

    pub fn jsonStringify(self: PeerStreamKind, writer: anytype) !void {
        try writer.print("{s}", .{switch (self) {
            .audio => "\"audio\"",
            .mixed => "\"mixed\"",
            .text => "\"text\"",
            .video => "\"video\"",
        }});
    }
};

pub const PeerStreamEvent = struct {
    v: i64 = peer_stream_event_version,
    type: PeerStreamEventType,
    kind: ?PeerStreamKind = null,
    stream_id: ?[]const u8 = null,
    label: ?[]const u8 = null,
    mime_type: ?[]const u8 = null,
    seq: ?i64 = null,
    timestamp: ?i64 = null,
    text: ?[]const u8 = null,
    @"error": ?[]const u8 = null,

    pub fn jsonStringify(self: PeerStreamEvent, writer: anytype) !void {
        try writer.beginObject();
        try writer.objectField("v");
        try writer.write(self.v);
        try writer.objectField("type");
        try writer.write(self.type);
        if (self.kind) |value| {
            try writer.objectField("kind");
            try writer.write(value);
        }
        if (self.stream_id) |value| {
            try writer.objectField("stream_id");
            try writer.write(value);
        }
        if (self.label) |value| {
            try writer.objectField("label");
            try writer.write(value);
        }
        if (self.mime_type) |value| {
            try writer.objectField("mime_type");
            try writer.write(value);
        }
        if (self.seq) |value| {
            try writer.objectField("seq");
            try writer.write(value);
        }
        if (self.timestamp) |value| {
            try writer.objectField("timestamp");
            try writer.write(value);
        }
        if (self.text) |value| {
            try writer.objectField("text");
            try writer.write(value);
        }
        if (self.@"error") |value| {
            try writer.objectField("error");
            try writer.write(value);
        }
        try writer.endObject();
    }
};

pub const PeerStreamChunk = union(enum) {
    event: PeerStreamEvent,
    stamped_opus: StampedOpusFrame,
};

pub const StampedOpusFrame = struct {
    timestamp: u64,
    frame: []const u8,
};

pub const OpenPeerStreamOptions = struct {
    read_timeout: ?glib.time.duration.Duration = null,
};

pub const PeerAudioTurnOptions = struct {
    stream_id: []const u8 = "audio",
    label: ?[]const u8 = null,
    timestamp: ?i64 = null,
    @"error": ?[]const u8 = null,
};

pub const StampedOpusSubscribeOptions = struct {
    read_timeout: ?glib.time.duration.Duration = null,
};

pub fn make(comptime grt: type) type {
    const Allocator = grt.std.mem.Allocator;
    const RpcRuntime = Rpc.make(grt);

    return struct {
        pub const PeerEventStream = struct {
            allocator: Allocator,
            stream: giznet.Stream,
            closed: bool = false,

            pub fn read(self: *PeerEventStream) !grt.std.json.Parsed(PeerStreamEvent) {
                return try @import("peer_stream.zig").readPeerStreamEvent(grt, self.allocator, self.stream);
            }

            pub fn write(self: *PeerEventStream, event: PeerStreamEvent) !void {
                try @import("peer_stream.zig").writePeerStreamEvent(grt, self.allocator, self.stream, event);
            }

            pub fn close(self: *PeerEventStream) void {
                if (self.closed) return;
                self.closed = true;
                self.stream.close() catch {};
            }

            pub fn deinit(self: *PeerEventStream) void {
                self.close();
                self.stream.deinit();
                self.* = undefined;
            }
        };

        pub const StampedOpusSubscriber = struct {
            conn: giznet.Conn,
            read_timeout: ?glib.time.duration.Duration = null,

            pub fn read(self: *StampedOpusSubscriber, buf: []u8) !StampedOpusFrame {
                return try @import("peer_stream.zig").readStampedOpus(grt, self.conn, buf, self.read_timeout);
            }
        };

        pub const PeerStreamChunkReadResult = struct {
            event: ?grt.std.json.Parsed(PeerStreamEvent) = null,
            stamped_opus: ?StampedOpusFrame = null,

            pub fn chunk(self: *const PeerStreamChunkReadResult) PeerStreamChunk {
                if (self.event) |event| return .{ .event = event.value };
                return .{ .stamped_opus = self.stamped_opus.? };
            }

            pub fn deinit(self: *PeerStreamChunkReadResult) void {
                if (self.event) |*event| event.deinit();
                self.* = undefined;
            }
        };

        pub const PeerStream = struct {
            event_stream: PeerEventStream,
            subscriber: StampedOpusSubscriber,

            pub fn readEvent(self: *PeerStream) !grt.std.json.Parsed(PeerStreamEvent) {
                return try self.event_stream.read();
            }

            pub fn readStampedOpus(self: *PeerStream, buf: []u8) !StampedOpusFrame {
                return try self.subscriber.read(buf);
            }

            pub fn readChunk(self: *PeerStream, buf: []u8) !PeerStreamChunkReadResult {
                if (self.readEvent()) |event| {
                    return .{ .event = event };
                } else |err| switch (err) {
                    error.Timeout, error.EndOfStream => {},
                    else => return err,
                }
                return .{ .stamped_opus = try self.readStampedOpus(buf) };
            }

            pub fn readAudio(self: *PeerStream, buf: []u8) !StampedOpusFrame {
                return try self.readStampedOpus(buf);
            }

            pub fn writeEvent(self: *PeerStream, event: PeerStreamEvent) !void {
                try self.event_stream.write(event);
            }

            pub fn writeStampedOpus(self: *PeerStream, frame: StampedOpusFrame) !void {
                try @import("peer_stream.zig").writeStampedOpus(grt, self.event_stream.allocator, self.subscriber.conn, frame);
            }

            pub fn beginAudio(self: *PeerStream, options: PeerAudioTurnOptions) !void {
                try @import("peer_stream.zig").writePeerAudioBegin(grt, self.event_stream.allocator, self.event_stream.stream, options);
            }

            pub fn writeAudio(self: *PeerStream, frame: StampedOpusFrame) !void {
                try self.writeStampedOpus(frame);
            }

            pub fn endAudio(self: *PeerStream, options: PeerAudioTurnOptions) !void {
                try @import("peer_stream.zig").writePeerAudioEnd(grt, self.event_stream.allocator, self.event_stream.stream, options);
            }

            pub fn close(self: *PeerStream) void {
                self.event_stream.close();
            }

            pub fn deinit(self: *PeerStream) void {
                self.event_stream.deinit();
                self.* = undefined;
            }
        };

        pub fn openPeerEventStream(allocator: Allocator, conn: giznet.Conn) !PeerEventStream {
            return .{
                .allocator = allocator,
                .stream = try conn.openStream(service.event),
            };
        }

        pub fn readPeerStreamEvent(allocator: Allocator, stream: giznet.Stream) !grt.std.json.Parsed(PeerStreamEvent) {
            return try @import("peer_stream.zig").readPeerStreamEvent(grt, allocator, stream);
        }

        pub fn writePeerStreamEvent(allocator: Allocator, stream: giznet.Stream, event: PeerStreamEvent) !void {
            try @import("peer_stream.zig").writePeerStreamEvent(grt, allocator, stream, event);
        }

        pub fn subscribeStampedOpus(conn: giznet.Conn, options: StampedOpusSubscribeOptions) StampedOpusSubscriber {
            return .{
                .conn = conn,
                .read_timeout = options.read_timeout,
            };
        }

        pub fn readStampedOpus(conn: giznet.Conn, buf: []u8, read_timeout: ?glib.time.duration.Duration) !StampedOpusFrame {
            return try @import("peer_stream.zig").readStampedOpus(grt, conn, buf, read_timeout);
        }

        pub fn writeStampedOpus(allocator: Allocator, conn: giznet.Conn, frame: StampedOpusFrame) !void {
            try @import("peer_stream.zig").writeStampedOpus(grt, allocator, conn, frame);
        }

        pub fn writePeerAudioBegin(allocator: Allocator, stream: giznet.Stream, options: PeerAudioTurnOptions) !void {
            try @import("peer_stream.zig").writePeerAudioBegin(grt, allocator, stream, options);
        }

        pub fn writePeerAudioEnd(allocator: Allocator, stream: giznet.Stream, options: PeerAudioTurnOptions) !void {
            try @import("peer_stream.zig").writePeerAudioEnd(grt, allocator, stream, options);
        }

        pub fn packStampedOpus(allocator: Allocator, frame: StampedOpusFrame) ![]u8 {
            return try @import("peer_stream.zig").packStampedOpus(allocator, frame);
        }

        pub fn unpackStampedOpus(payload: []const u8) !StampedOpusFrame {
            return try @import("peer_stream.zig").unpackStampedOpus(payload);
        }

        pub fn openPeerStream(allocator: Allocator, conn: giznet.Conn, options: OpenPeerStreamOptions) !PeerStream {
            return .{
                .event_stream = try openPeerEventStream(allocator, conn),
                .subscriber = subscribeStampedOpus(conn, .{
                    .read_timeout = options.read_timeout,
                }),
            };
        }

        pub fn writePeerStreamChunk(allocator: Allocator, conn: giznet.Conn, stream: giznet.Stream, chunk: PeerStreamChunk) !void {
            switch (chunk) {
                .event => |event| try @import("peer_stream.zig").writePeerStreamEvent(grt, allocator, stream, event),
                .stamped_opus => |frame| try @import("peer_stream.zig").writeStampedOpus(grt, allocator, conn, frame),
            }
        }

        pub const rpc = RpcRuntime;
    };
}

pub fn readPeerStreamEvent(comptime grt: type, allocator: grt.std.mem.Allocator, stream: giznet.Stream) !grt.std.json.Parsed(PeerStreamEvent) {
    const RpcRuntime = Rpc.make(grt);
    var frame = try RpcRuntime.readFrame(allocator, stream);
    defer frame.deinit(allocator);
    if (frame.type == .eos) return error.EndOfStream;
    if (frame.type != .json) return error.ExpectedRpcJsonFrame;

    const WireEvent = struct {
        v: i64 = peer_stream_event_version,
        type: []const u8,
        kind: ?[]const u8 = null,
        stream_id: ?[]const u8 = null,
        label: ?[]const u8 = null,
        mime_type: ?[]const u8 = null,
        seq: ?i64 = null,
        timestamp: ?i64 = null,
        text: ?[]const u8 = null,
        @"error": ?[]const u8 = null,
    };
    var wire = try grt.std.json.parseFromSlice(WireEvent, allocator, frame.payload, .{
        .allocate = .alloc_always,
        .ignore_unknown_fields = true,
    });
    errdefer wire.deinit();
    return grt.std.json.Parsed(PeerStreamEvent){
        .arena = wire.arena,
        .value = .{
            .v = wire.value.v,
            .type = try parsePeerStreamEventType(grt, wire.value.type),
            .kind = if (wire.value.kind) |kind| try parsePeerStreamKind(grt, kind) else null,
            .stream_id = wire.value.stream_id,
            .label = wire.value.label,
            .mime_type = wire.value.mime_type,
            .seq = wire.value.seq,
            .timestamp = wire.value.timestamp,
            .text = wire.value.text,
            .@"error" = wire.value.@"error",
        },
    };
}

fn parsePeerStreamEventType(comptime grt: type, raw: []const u8) !PeerStreamEventType {
    if (grt.std.mem.eql(u8, raw, "bos")) return .bos;
    if (grt.std.mem.eql(u8, raw, "eos")) return .eos;
    if (grt.std.mem.eql(u8, raw, "text.delta")) return .text_delta;
    if (grt.std.mem.eql(u8, raw, "text.done")) return .text_done;
    return error.InvalidEnumTag;
}

fn parsePeerStreamKind(comptime grt: type, raw: []const u8) !PeerStreamKind {
    if (grt.std.mem.eql(u8, raw, "audio")) return .audio;
    if (grt.std.mem.eql(u8, raw, "mixed")) return .mixed;
    if (grt.std.mem.eql(u8, raw, "text")) return .text;
    if (grt.std.mem.eql(u8, raw, "video")) return .video;
    return error.InvalidEnumTag;
}

pub fn writePeerStreamEvent(comptime grt: type, allocator: grt.std.mem.Allocator, stream: giznet.Stream, event: PeerStreamEvent) !void {
    const RpcRuntime = Rpc.make(grt);
    const value = if (event.v == 0) blk: {
        var copy = event;
        copy.v = peer_stream_event_version;
        break :blk copy;
    } else event;
    var out = grt.std.Io.Writer.Allocating.init(allocator);
    defer out.deinit();
    try grt.std.json.Stringify.value(value, .{}, &out.writer);
    try RpcRuntime.writeJsonFrame(allocator, stream, out.written());
}

pub fn writePeerAudioBegin(comptime grt: type, allocator: grt.std.mem.Allocator, stream: giznet.Stream, options: PeerAudioTurnOptions) !void {
    try writePeerStreamEvent(grt, allocator, stream, .{
        .type = .bos,
        .kind = .audio,
        .stream_id = options.stream_id,
        .label = options.label,
        .timestamp = options.timestamp,
    });
}

pub fn writePeerAudioEnd(comptime grt: type, allocator: grt.std.mem.Allocator, stream: giznet.Stream, options: PeerAudioTurnOptions) !void {
    try writePeerStreamEvent(grt, allocator, stream, .{
        .type = .eos,
        .kind = .audio,
        .stream_id = options.stream_id,
        .label = options.label,
        .timestamp = options.timestamp,
        .@"error" = options.@"error",
    });
}

pub fn packStampedOpus(allocator: anytype, frame: StampedOpusFrame) ![]u8 {
    const out = try allocator.alloc(u8, stamped_opus_header_size + frame.frame.len);
    out[0] = stamped_opus_version;
    const timestamp = frame.timestamp & stamped_opus_timestamp_mask;
    inline for (0..7) |i| {
        const shift = 48 - i * 8;
        out[1 + i] = @intCast((timestamp >> shift) & 0xff);
    }
    @memcpy(out[stamped_opus_header_size..], frame.frame);
    return out;
}

pub fn unpackStampedOpus(payload: []const u8) !StampedOpusFrame {
    if (payload.len < stamped_opus_header_size) return error.InvalidStampedOpusFrame;
    if (payload[0] != stamped_opus_version) return error.InvalidStampedOpusFrame;
    const frame = payload[stamped_opus_header_size..];
    if (frame.len == 0) return error.InvalidStampedOpusFrame;
    var timestamp: u64 = 0;
    for (payload[1..stamped_opus_header_size]) |byte| {
        timestamp = (timestamp << 8) | byte;
    }
    return .{
        .timestamp = timestamp,
        .frame = frame,
    };
}

pub fn readStampedOpus(comptime grt: type, conn: giznet.Conn, buf: []u8, read_timeout: ?glib.time.duration.Duration) !StampedOpusFrame {
    _ = grt;
    while (true) {
        const result = if (read_timeout) |timeout|
            try conn.readTimeout(buf, timeout)
        else
            try conn.read(buf);
        if (result.protocol != service.protocol_stamped_opus) continue;
        return try unpackStampedOpus(buf[0..result.n]);
    }
}

pub fn writeStampedOpus(comptime grt: type, allocator: grt.std.mem.Allocator, conn: giznet.Conn, frame: StampedOpusFrame) !void {
    const payload = try packStampedOpus(allocator, frame);
    defer allocator.free(payload);
    const written = try conn.write(service.protocol_stamped_opus, payload);
    if (written != payload.len) return error.ShortWrite;
}
