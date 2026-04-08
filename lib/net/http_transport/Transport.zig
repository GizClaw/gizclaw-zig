const dep = @import("dep");
const StreamConnFile = @import("StreamConn.zig");

const ascii = dep.embed.ascii;
const fmt = dep.embed.fmt;
const mem = dep.embed.mem;
const net = dep.net;
const Thread = dep.embed_std.std.Thread;

const Header = net.http.Header;
const ReadCloser = net.http.ReadCloser;
const Request = net.http.Request;
const Response = net.http.Response;

const peer_public_key_header = "X-Peer-Public-Key";
const default_body_io_buf_len = 1024;
const default_max_header_bytes = 32 * 1024;
const max_informational_responses = 8;
const cancel_poll_interval_ns: i64 = 50 * dep.embed.time.ns_per_ms;

pub fn make(comptime Peer: type) type {
    const StreamConn = StreamConnFile.make(Peer);

    return struct {
        allocator: mem.Allocator = undefined,
        conn: ?*Peer.Conn = null,
        service_id: u64 = 0,

        const Self = @This();

        const ParsedHead = struct {
            status: []const u8,
            status_code: u16,
            proto: []const u8,
            proto_major: u8 = 1,
            proto_minor: u8 = 1,
            headers: []Header,
            content_length: ?usize = null,
            chunked: bool = false,
        };

        const BodyMode = enum {
            none,
            fixed,
            eof,
            chunked,
        };

        const CancelWatcher = struct {
            allocator: mem.Allocator,
            ctx: dep.context.Context,
            conn: net.Conn,
            thread: ?Thread = null,
            stop: u8 = 0,

            fn start(allocator: mem.Allocator, ctx: dep.context.Context, conn: net.Conn) !*CancelWatcher {
                const self = try allocator.create(CancelWatcher);
                errdefer allocator.destroy(self);

                self.* = .{
                    .allocator = allocator,
                    .ctx = ctx,
                    .conn = conn,
                };
                self.thread = try Thread.spawn(.{}, run, .{self});
                return self;
            }

            fn stopAndDestroy(self: *CancelWatcher) void {
                @atomicStore(u8, &self.stop, 1, .release);

                if (self.thread) |thread| thread.join();
                self.allocator.destroy(self);
            }

            fn shouldStop(self: *CancelWatcher) bool {
                return @atomicLoad(u8, &self.stop, .acquire) != 0;
            }

            fn run(self: *CancelWatcher) void {
                while (true) {
                    if (self.shouldStop()) return;
                    if (self.ctx.wait(cancel_poll_interval_ns) != null) {
                        self.conn.close();
                        return;
                    }
                }
            }
        };

        const BodyState = struct {
            allocator: mem.Allocator,
            conn: ?net.Conn = null,
            watcher: ?*CancelWatcher = null,
            mode: BodyMode = .none,
            fixed_remaining: usize = 0,
            chunk_remaining: usize = 0,
            chunk_final: bool = false,
            trailer_bytes: usize = 0,
            closed: bool = false,

            pub fn read(self: *BodyState, buf: []u8) anyerror!usize {
                if (self.closed or buf.len == 0) return 0;

                return switch (self.mode) {
                    .none => 0,
                    .fixed => self.readFixed(buf),
                    .eof => self.readEof(buf),
                    .chunked => self.readChunked(buf),
                };
            }

            pub fn close(self: *BodyState) void {
                self.finish();
            }

            fn deinit(self: *BodyState) void {
                self.finish();
            }

            fn finish(self: *BodyState) void {
                if (self.closed) return;
                self.closed = true;
                Self.stopAndDestroyWatcher(&self.watcher);
                Self.closeOwnedConn(&self.conn);
            }

            fn failRead(self: *BodyState, err: anyerror) anyerror!usize {
                self.finish();
                return err;
            }

            fn readFixed(self: *BodyState, buf: []u8) anyerror!usize {
                if (self.fixed_remaining == 0) {
                    self.finish();
                    return 0;
                }

                const read_len = @min(buf.len, self.fixed_remaining);
                const n = self.conn.?.read(buf[0..read_len]) catch |err| return self.failRead(switch (err) {
                    error.EndOfStream => error.InvalidResponse,
                    else => err,
                });
                if (n == 0) return self.failRead(error.InvalidResponse);

                self.fixed_remaining -= n;
                if (self.fixed_remaining == 0) self.finish();
                return n;
            }

            fn readEof(self: *BodyState, buf: []u8) anyerror!usize {
                const n = self.conn.?.read(buf) catch |err| switch (err) {
                    error.EndOfStream => {
                        self.finish();
                        return 0;
                    },
                    else => return self.failRead(err),
                };
                if (n == 0) {
                    self.finish();
                    return 0;
                }
                return n;
            }

            fn readChunked(self: *BodyState, buf: []u8) anyerror!usize {
                while (true) {
                    if (self.chunk_remaining == 0) {
                        if (self.chunk_final) {
                            self.finish();
                            return 0;
                        }

                        try self.beginNextChunk();
                        if (self.chunk_final) {
                            try self.consumeTrailers();
                            self.finish();
                            return 0;
                        }
                    }

                    const read_len = @min(buf.len, self.chunk_remaining);
                    const n = self.conn.?.read(buf[0..read_len]) catch |err| return self.failRead(switch (err) {
                        error.EndOfStream => error.InvalidResponse,
                        else => err,
                    });
                    if (n == 0) return self.failRead(error.InvalidResponse);

                    self.chunk_remaining -= n;
                    if (self.chunk_remaining == 0) {
                        self.expectCrlf() catch |err| return self.failRead(err);
                    }
                    return n;
                }
            }

            fn beginNextChunk(self: *BodyState) anyerror!void {
                const line = try self.readLine(default_max_header_bytes);
                defer self.allocator.free(line);

                const size_text = if (mem.indexOfScalar(u8, line, ';')) |sep| line[0..sep] else line;
                if (size_text.len == 0) return error.InvalidResponse;

                const size = fmt.parseInt(usize, size_text, 16) catch return error.InvalidResponse;
                self.chunk_remaining = size;
                self.chunk_final = size == 0;
            }

            fn consumeTrailers(self: *BodyState) anyerror!void {
                self.trailer_bytes = 0;
                while (true) {
                    const line = try self.readLine(default_max_header_bytes);
                    defer self.allocator.free(line);

                    self.trailer_bytes += line.len + 2;
                    if (self.trailer_bytes > default_max_header_bytes) return error.BufferTooSmall;
                    if (line.len == 0) return;
                }
            }

            fn readLine(self: *BodyState, limit: usize) ![]u8 {
                var storage = try self.allocator.alloc(u8, 64);
                errdefer self.allocator.free(storage);

                var len: usize = 0;
                while (true) {
                    if (len == storage.len) {
                        storage = try self.allocator.realloc(storage, storage.len * 2);
                    }

                    storage[len] = try readByte(self.conn.?);
                    len += 1;
                    if (len > limit + 2) return error.BufferTooSmall;

                    if (len >= 2 and storage[len - 2] == '\r' and storage[len - 1] == '\n') {
                        storage = try self.allocator.realloc(storage, len - 2);
                        return storage;
                    }
                }
            }

            fn expectCrlf(self: *BodyState) anyerror!void {
                if (try readByte(self.conn.?) != '\r') return error.InvalidResponse;
                if (try readByte(self.conn.?) != '\n') return error.InvalidResponse;
            }
        };

        const ResponseState = struct {
            allocator: mem.Allocator,
            head_storage: []u8,
            headers: []Header = &.{},
            body_state: ?*BodyState = null,
            conn: ?net.Conn = null,
            watcher: ?*CancelWatcher = null,
        };

        fn initOwned(allocator: mem.Allocator, conn: *Peer.Conn, service_id: u64) !*Self {
            const self = try allocator.create(Self);
            self.* = .{
                .allocator = allocator,
                .conn = conn,
                .service_id = service_id,
            };
            return self;
        }

        pub fn init(allocator: mem.Allocator, conn: *Peer.Conn, service_id: u64) !net.http.RoundTripper {
            const self = try Self.initOwned(allocator, conn, service_id);
            return net.http.RoundTripper.init(self);
        }

        pub fn deinit(self: *Self) void {
            self.allocator.destroy(self);
        }

        pub fn roundTrip(self: *Self, req: *const Request) anyerror!Response {
            try self.validateRequest(req);
            if (req.context()) |ctx| {
                if (contextErr(ctx)) |cause| return cause;
            }

            const peer_conn = try self.peerConn();
            const stream = try peer_conn.openService(self.service_id);

            var conn: ?net.Conn = try StreamConn.init(self.allocator, stream);
            errdefer Self.closeOwnedConn(&conn);

            var watcher: ?*CancelWatcher = null;
            if (req.context()) |ctx| {
                watcher = try CancelWatcher.start(self.allocator, ctx, conn.?);
            }
            errdefer Self.stopAndDestroyWatcher(&watcher);

            try self.writeRequest(conn.?, req);
            return try self.readResponse(&conn, &watcher, req);
        }

        pub fn service(self: *const Self) u64 {
            return self.service_id;
        }

        pub fn peerConn(self: *Self) error{InvalidHandle}!*Peer.Conn {
            if (self.conn) |conn| return conn;
            return error.InvalidHandle;
        }

        fn writeRequest(self: *Self, conn: net.Conn, req: *const Request) anyerror!void {
            try self.writeRequestHead(conn, req);

            if (req.body()) |body| {
                defer body.close();

                const send_chunked = self.shouldSendChunkedRequest(req);
                const content_length: usize = if (!send_chunked and req.content_length > 0)
                    @intCast(req.content_length)
                else
                    0;
                const io_buf = try self.allocator.alloc(u8, self.bodyIoBufLen(send_chunked, content_length));
                defer self.allocator.free(io_buf);

                if (send_chunked) {
                    try self.writeChunkedBody(conn, body, io_buf);
                } else {
                    try self.writeFixedBody(conn, body, content_length, io_buf);
                }
            }
        }

        fn writeRequestHead(self: *Self, conn: net.Conn, req: *const Request) anyerror!void {
            const allocator = req.allocator;
            const target = try requestTarget(allocator, req);
            defer allocator.free(target);

            const host_value = try hostHeaderValue(allocator, req);
            defer allocator.free(host_value);
            var peer_key_buf: [64]u8 = undefined;
            const peer_key_value = formatKeyHexLower(&peer_key_buf, (try self.peerConn()).publicKey());

            const body = req.body();
            const send_chunked = body != null and self.shouldSendChunkedRequest(req);
            const content_length: usize = if (req.content_length > 0)
                @intCast(req.content_length)
            else
                0;

            try writeAll(conn, req.effectiveMethod());
            try writeAll(conn, " ");
            try writeAll(conn, target);
            try writeAll(conn, " ");
            try writeAll(conn, req.proto);
            try writeAll(conn, "\r\n");

            var user_agent_value: ?[]const u8 = null;
            var has_peer_public_key = false;

            for (req.header) |hdr| {
                if (hdr.is(Header.host) or
                    hdr.is(Header.content_length) or
                    hdr.is(Header.transfer_encoding))
                {
                    continue;
                }

                if (hdr.is(Header.user_agent)) {
                    if (user_agent_value == null) user_agent_value = hdr.value;
                    continue;
                }
                if (hdr.is(peer_public_key_header)) has_peer_public_key = true;

                try writeHeaderLine(conn, hdr.name, hdr.value);
            }

            try writeHeaderLine(conn, Header.host, host_value);
            if (!has_peer_public_key) try writeHeaderLine(conn, peer_public_key_header, peer_key_value);
            if (user_agent_value) |value| {
                if (value.len != 0) try writeHeaderLine(conn, Header.user_agent, value);
            }
            if (send_chunked) {
                try writeHeaderLine(conn, Header.transfer_encoding, "chunked");
            } else if (body != null or req.content_length > 0) {
                const len_buf = try fmt.allocPrint(allocator, "{d}", .{content_length});
                defer allocator.free(len_buf);
                try writeHeaderLine(conn, Header.content_length, len_buf);
            }

            try writeAll(conn, "\r\n");
        }

        fn writeFixedBody(self: *Self, conn: net.Conn, body: ReadCloser, content_length: usize, buf: []u8) anyerror!void {
            _ = self;

            if (content_length == 0) return;
            if (buf.len == 0) return error.Unexpected;

            var remaining = content_length;
            var reader = body;
            while (remaining != 0) {
                const n = try reader.read(buf[0..@min(buf.len, remaining)]);
                if (n == 0) return error.InvalidResponse;
                try writeAll(conn, buf[0..n]);
                remaining -= n;
            }
        }

        fn writeChunkedBody(self: *Self, conn: net.Conn, body: ReadCloser, buf: []u8) anyerror!void {
            _ = self;

            if (buf.len == 0) return error.Unexpected;

            var reader = body;
            var size_buf: [32]u8 = undefined;

            while (true) {
                const n = try reader.read(buf);
                if (n == 0) break;

                const size_line = fmt.bufPrint(&size_buf, "{x}\r\n", .{n}) catch return error.Unexpected;
                try writeAll(conn, size_line);
                try writeAll(conn, buf[0..n]);
                try writeAll(conn, "\r\n");
            }

            try writeAll(conn, "0\r\n\r\n");
        }

        fn bodyIoBufLen(_: *Self, send_chunked: bool, content_length: usize) usize {
            if (send_chunked) return default_body_io_buf_len;
            return @max(@as(usize, 1), @min(default_body_io_buf_len, content_length));
        }

        fn shouldSendChunkedRequest(_: *Self, req: *const Request) bool {
            if (req.transfer_encoding.len != 0) {
                for (req.transfer_encoding) |encoding| {
                    if (ascii.eqlIgnoreCase(encoding, "chunked")) return true;
                }
            }
            return req.content_length <= 0;
        }

        fn readResponse(self: *Self, conn: *?net.Conn, watcher: *?*CancelWatcher, req: *const Request) anyerror!Response {
            _ = self;

            const allocator = req.allocator;
            var informational_responses: usize = 0;

            while (true) {
                const head_storage = readResponseHead(conn.* orelse unreachable, allocator) catch |err| return switch (err) {
                    error.EndOfStream => error.InvalidResponse,
                    else => err,
                };

                var state_parts = ResponseState{
                    .allocator = allocator,
                    .head_storage = head_storage,
                };
                var transferred = false;
                defer if (!transferred) Self.freeResponseStateParts(&state_parts);

                const parsed = try Self.parseHead(&state_parts);
                if (isInformationalResponse(parsed.status_code)) {
                    informational_responses += 1;
                    if (informational_responses > max_informational_responses) return error.InvalidResponse;
                    continue;
                }

                const state = try allocator.create(ResponseState);
                errdefer allocator.destroy(state);
                state.* = .{
                    .allocator = allocator,
                    .head_storage = state_parts.head_storage,
                    .headers = state_parts.headers,
                };
                transferred = true;

                const has_body = !responseMustBeBodyless(req, parsed.status_code) and
                    (parsed.chunked or parsed.content_length == null or parsed.content_length.? != 0);

                if (has_body) {
                    const body_state = try allocator.create(BodyState);
                    errdefer allocator.destroy(body_state);

                    body_state.* = .{
                        .allocator = allocator,
                        .conn = conn.*,
                        .watcher = watcher.*,
                        .mode = Self.responseBodyMode(req, parsed),
                        .fixed_remaining = parsed.content_length orelse 0,
                    };
                    conn.* = null;
                    watcher.* = null;
                    state.body_state = body_state;
                } else {
                    state.conn = conn.*;
                    state.watcher = watcher.*;
                    conn.* = null;
                    watcher.* = null;
                }

                return .{
                    .deinit_ptr = @ptrCast(state),
                    .deinit_fn = responseStateDeinit,
                    .status = parsed.status,
                    .status_code = parsed.status_code,
                    .proto = parsed.proto,
                    .proto_major = parsed.proto_major,
                    .proto_minor = parsed.proto_minor,
                    .header = parsed.headers,
                    .body_reader = if (state.body_state) |body_state| ReadCloser.init(body_state) else null,
                    .content_length = if (parsed.content_length) |n| @intCast(n) else @as(i64, -1),
                    .close = true,
                    .request = req.*,
                };
            }
        }

        fn responseStateDeinit(ptr: *anyopaque) void {
            const state: *ResponseState = @ptrCast(@alignCast(ptr));
            if (state.body_state) |body| {
                body.deinit();
                state.allocator.destroy(body);
            } else {
                Self.stopAndDestroyWatcher(&state.watcher);
                Self.closeOwnedConn(&state.conn);
            }
            if (state.headers.len != 0) state.allocator.free(state.headers);
            if (state.head_storage.len != 0) state.allocator.free(state.head_storage);
            state.allocator.destroy(state);
        }

        fn freeResponseStateParts(state: *ResponseState) void {
            if (state.headers.len != 0) state.allocator.free(state.headers);
            if (state.head_storage.len != 0) state.allocator.free(state.head_storage);
        }

        fn parseHead(state: *ResponseState) anyerror!ParsedHead {
            const status_line_end = mem.indexOf(u8, state.head_storage, "\r\n") orelse return error.InvalidResponse;
            const status_line = state.head_storage[0..status_line_end];

            const first_space = mem.indexOfScalar(u8, status_line, ' ') orelse return error.InvalidResponse;
            const proto = status_line[0..first_space];
            const rest = status_line[first_space + 1 ..];
            const second_space = mem.indexOfScalar(u8, rest, ' ') orelse return error.InvalidResponse;
            const code_slice = rest[0..second_space];
            const status_slice = rest;
            const status_code = fmt.parseInt(u16, code_slice, 10) catch return error.InvalidResponse;

            var proto_major: u8 = 1;
            var proto_minor: u8 = 1;
            if (mem.startsWith(u8, proto, "HTTP/")) {
                const version = proto["HTTP/".len..];
                if (mem.indexOfScalar(u8, version, '.')) |dot| {
                    proto_major = fmt.parseInt(u8, version[0..dot], 10) catch return error.InvalidResponse;
                    proto_minor = fmt.parseInt(u8, version[dot + 1 ..], 10) catch return error.InvalidResponse;
                }
            }

            const header_block = state.head_storage[status_line_end + 2 ..];
            const header_count = countHeaderLines(header_block);
            state.headers = if (header_count == 0) &.{} else try state.allocator.alloc(Header, header_count);

            var parsed = ParsedHead{
                .status = status_slice,
                .status_code = status_code,
                .proto = proto,
                .proto_major = proto_major,
                .proto_minor = proto_minor,
                .headers = state.headers,
            };

            var saw_transfer_encoding = false;
            var line_start: usize = 0;
            var header_index: usize = 0;
            while (line_start < header_block.len) {
                const rel_end = mem.indexOf(u8, header_block[line_start..], "\r\n") orelse return error.InvalidResponse;
                if (rel_end == 0) break;

                const line = header_block[line_start .. line_start + rel_end];
                const colon = mem.indexOfScalar(u8, line, ':') orelse return error.InvalidResponse;
                const name = mem.trim(u8, line[0..colon], " ");
                const value = mem.trim(u8, line[colon + 1 ..], " ");
                parsed.headers[header_index] = .{ .name = name, .value = value };
                header_index += 1;

                if (ascii.eqlIgnoreCase(name, Header.content_length)) {
                    const content_length = fmt.parseInt(usize, value, 10) catch return error.InvalidResponse;
                    if (parsed.chunked) return error.InvalidResponse;
                    if (parsed.content_length) |existing| {
                        if (existing != content_length) return error.InvalidResponse;
                    } else {
                        parsed.content_length = content_length;
                    }
                } else if (ascii.eqlIgnoreCase(name, Header.transfer_encoding)) {
                    if (saw_transfer_encoding or parsed.content_length != null) return error.InvalidResponse;
                    if (!isSupportedChunkedTransferEncoding(value)) return error.InvalidResponse;
                    parsed.chunked = true;
                    saw_transfer_encoding = true;
                }

                line_start += rel_end + 2;
            }

            parsed.headers = parsed.headers[0..header_index];
            return parsed;
        }

        fn responseBodyMode(req: *const Request, parsed: ParsedHead) BodyMode {
            if (responseMustBeBodyless(req, parsed.status_code)) return .none;
            if (parsed.chunked) return .chunked;
            if (parsed.content_length) |_| return .fixed;
            return .eof;
        }

        fn validateRequest(self: *Self, req: *const Request) anyerror!void {
            if (!isValidToken(req.effectiveMethod())) return error.InvalidMethod;
            if (req.effectiveHost().len == 0) return error.MissingHost;
            if (req.trailer.len != 0) return error.UnsupportedTrailers;
            if (req.content_length > 0 and req.body() == null) return error.InvalidRequest;

            try validateHeaderList(req.header, false);
            try self.validateRequestFramingHeaders(req);
        }

        fn validateRequestFramingHeaders(self: *Self, req: *const Request) anyerror!void {
            const body = req.body();
            const send_chunked = body != null and self.shouldSendChunkedRequest(req);
            const expected_content_length: i64 = if (req.content_length > 0) req.content_length else 0;

            var header_content_length: ?i64 = null;
            var saw_transfer_encoding = false;

            for (req.header) |hdr| {
                if (hdr.is(Header.content_length)) {
                    const parsed = fmt.parseInt(i64, hdr.value, 10) catch return error.InvalidHeader;
                    if (parsed < 0) return error.InvalidHeader;
                    if (header_content_length) |existing| {
                        if (existing != parsed) return error.InvalidHeader;
                    } else {
                        header_content_length = parsed;
                    }
                } else if (hdr.is(Header.transfer_encoding)) {
                    if (saw_transfer_encoding) return error.InvalidHeader;
                    if (!isSupportedChunkedTransferEncoding(hdr.value)) return error.InvalidHeader;
                    saw_transfer_encoding = true;
                }
            }

            if (saw_transfer_encoding) {
                if (!send_chunked) return error.InvalidHeader;
                if (header_content_length != null) return error.InvalidHeader;
            }

            if (header_content_length) |parsed| {
                if (send_chunked) return error.InvalidHeader;
                if (parsed != expected_content_length) return error.InvalidHeader;
            }
        }

        fn closeOwnedConn(conn: *?net.Conn) void {
            if (conn.*) |owned_conn| {
                owned_conn.deinit();
                conn.* = null;
            }
        }

        fn stopAndDestroyWatcher(watcher: *?*CancelWatcher) void {
            if (watcher.*) |owned_watcher| {
                owned_watcher.stopAndDestroy();
                watcher.* = null;
            }
        }
    };
}

fn readResponseHead(conn: net.Conn, allocator: mem.Allocator) anyerror![]u8 {
    var storage = try allocator.alloc(u8, 256);
    errdefer allocator.free(storage);

    var len: usize = 0;
    while (true) {
        if (len == storage.len) {
            storage = try allocator.realloc(storage, storage.len * 2);
        }

        storage[len] = try readByte(conn);
        len += 1;
        if (len > default_max_header_bytes + 2) return error.BufferTooSmall;

        if (len >= 4 and
            storage[len - 4] == '\r' and
            storage[len - 3] == '\n' and
            storage[len - 2] == '\r' and
            storage[len - 1] == '\n')
        {
            storage = try allocator.realloc(storage, len - 2);
            return storage;
        }
    }
}

fn formatKeyHexLower(buf: *[64]u8, key: anytype) []const u8 {
    const chars = "0123456789abcdef";
    for (key.asBytes().*, 0..) |byte, i| {
        buf[i * 2] = chars[byte >> 4];
        buf[i * 2 + 1] = chars[byte & 0x0f];
    }
    return buf;
}

fn writeAll(conn: net.Conn, buf: []const u8) anyerror!void {
    var written: usize = 0;
    while (written < buf.len) {
        const n = try conn.write(buf[written..]);
        if (n == 0) return error.Unexpected;
        written += n;
    }
}

fn writeHeaderLine(conn: net.Conn, name: []const u8, value: []const u8) anyerror!void {
    try writeAll(conn, name);
    try writeAll(conn, ": ");
    try writeAll(conn, value);
    try writeAll(conn, "\r\n");
}

fn requestTarget(allocator: mem.Allocator, req: *const Request) mem.Allocator.Error![]u8 {
    if (req.request_uri.len != 0) return allocator.dupe(u8, req.request_uri);

    const path = if (req.url.path.len != 0) req.url.path else "/";
    if (req.url.raw_query.len == 0) return allocator.dupe(u8, path);
    return fmt.allocPrint(allocator, "{s}?{s}", .{ path, req.url.raw_query });
}

fn hostHeaderValue(allocator: mem.Allocator, req: *const Request) mem.Allocator.Error![]u8 {
    if (req.host.len != 0) return allocator.dupe(u8, req.host);

    const host = req.url.host;
    const needs_brackets = mem.indexOfScalar(u8, host, ':') != null;
    if (req.url.port.len == 0) {
        if (needs_brackets) return fmt.allocPrint(allocator, "[{s}]", .{host});
        return allocator.dupe(u8, host);
    }

    if (needs_brackets) return fmt.allocPrint(allocator, "[{s}]:{s}", .{ host, req.url.port });
    return fmt.allocPrint(allocator, "{s}:{s}", .{ host, req.url.port });
}

fn readByte(conn: net.Conn) anyerror!u8 {
    var one: [1]u8 = undefined;
    const n = try conn.read(&one);
    if (n == 0) return error.EndOfStream;
    return one[0];
}

fn countHeaderLines(block: []const u8) usize {
    var count: usize = 0;
    var start: usize = 0;
    while (start < block.len) {
        const line_end = mem.indexOfPos(u8, block, start, "\r\n") orelse break;
        if (line_end == start) break;
        count += 1;
        start = line_end + 2;
    }
    return count;
}

fn responseMustBeBodyless(req: *const Request, status_code: u16) bool {
    if (ascii.eqlIgnoreCase(req.effectiveMethod(), "HEAD")) return true;
    return (status_code >= 100 and status_code < 200 and status_code != 101) or
        status_code == 204 or
        status_code == 304;
}

fn isInformationalResponse(status_code: u16) bool {
    return status_code >= 100 and status_code < 200 and status_code != 101;
}

fn contextErr(ctx: dep.context.Context) ?anyerror {
    if (ctx.err()) |cause| return cause;
    if (ctx.deadline()) |deadline_ns| {
        if (deadline_ns <= dep.embed_std.std.time.nanoTimestamp()) return dep.context.Context.DeadlineExceeded;
    }
    return null;
}

fn isSupportedChunkedTransferEncoding(value: []const u8) bool {
    var start: usize = 0;
    var saw_chunked = false;
    while (start <= value.len) {
        const comma = mem.indexOfScalarPos(u8, value, start, ',') orelse value.len;
        const part = mem.trim(u8, value[start..comma], " ");
        if (part.len == 0) return false;
        if (!ascii.eqlIgnoreCase(part, "chunked")) return false;
        if (saw_chunked) return false;
        saw_chunked = true;
        if (comma == value.len) break;
        start = comma + 1;
    }
    return saw_chunked;
}

fn validateHeaderList(headers: []const Header, is_trailer: bool) anyerror!void {
    for (headers) |hdr| {
        if (!isValidToken(hdr.name)) {
            return if (is_trailer) error.InvalidTrailer else error.InvalidHeader;
        }
        if (!isValidHeaderValue(hdr.value)) {
            return if (is_trailer) error.InvalidTrailer else error.InvalidHeader;
        }
    }
}

fn isValidToken(value: []const u8) bool {
    if (value.len == 0) return false;
    for (value) |c| {
        if (c <= 0x20 or c >= 0x7f) return false;
        switch (c) {
            '(', ')', '<', '>', '@', ',', ';', ':', '\\', '"', '/', '[', ']', '?', '=', '{', '}' => return false,
            else => {},
        }
    }
    return true;
}

fn isValidHeaderValue(value: []const u8) bool {
    for (value) |c| {
        if (c == '\r' or c == '\n') return false;
        if (c < 0x20 and c != '\t') return false;
        if (c == 0x7f) return false;
    }
    return true;
}
