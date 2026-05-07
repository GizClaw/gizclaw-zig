//! HttpTransport sends HTTP/1.1 requests over giznet KCP streams.

const glib = @import("glib");
const io = glib.io;
const stdz = glib.std;

const Conn = @import("Conn.zig");
const StreamConn = @import("StreamConn.zig");
const framing = @import("httptransport/framing.zig");

pub fn make(comptime grt: type) type {
    const Allocator = grt.std.mem.Allocator;
    const NetConn = grt.net.Conn;
    const Http = grt.net.http;
    const Header = Http.Header;
    const ReadCloser = Http.ReadCloser;
    const Request = Http.Request;
    const Response = Http.Response;
    const RoundTripper = Http.RoundTripper;
    const BufferedConnReader = io.BufferedReader(NetConn);
    const BufferedConnWriter = io.BufferedWriter(NetConn);
    const TextprotoReader = grt.net.textproto.Reader(BufferedConnReader);
    const TextprotoWriter = grt.net.textproto.Writer(BufferedConnWriter);
    const StreamConnImpl = StreamConn.make(grt);

    return struct {
        allocator: Allocator,
        conn: Conn,
        service_id: u64,
        options: Options,
        idle_mu: grt.std.Thread.Mutex = .{},
        idle_conns: grt.std.ArrayList(NetConn) = .{},

        const Self = @This();

        pub const Options = struct {
            user_agent: []const u8 = "giznet-httptransport/1.0",
            body_io_buf_len: usize = 1024,
            max_header_bytes: usize = 32 * 1024,
            max_body_bytes: usize = stdz.math.maxInt(usize),
        };

        const ParsedHead = struct {
            status: []const u8,
            status_code: u16,
            proto: []const u8,
            proto_major: u8 = 1,
            proto_minor: u8 = 1,
            headers: []Header,
            content_length: ?usize = null,
            chunked: bool = false,
            close: bool = false,
        };

        const ResponseState = struct {
            allocator: Allocator,
            head_storage: []u8,
            headers: []Header,
            body_state: ?*BodyState = null,
        };

        const BodyState = struct {
            allocator: Allocator,
            transport: *Self,
            conn: NetConn,
            buffered: BufferedConnReader,
            mode: BodyMode,
            request_body: ?*RequestBodyState,
            reusable: bool,
            closed: bool = false,
            complete: bool = false,
            owns_conn: bool = true,
            buffered_active: bool = true,

            const BodyMode = union(enum) {
                none,
                fixed: usize,
                eof,
                chunked: ChunkedState,
            };

            const ChunkedState = struct {
                remaining_in_chunk: usize = 0,
                finished: bool = false,
            };

            pub fn read(self: *BodyState, buf: []u8) anyerror!usize {
                if (self.closed or buf.len == 0) return 0;
                return switch (self.mode) {
                    .none => self.finishAndReturnEof(),
                    .fixed => |*remaining| self.readFixed(buf, remaining),
                    .eof => self.readFromStream(buf),
                    .chunked => |*chunked| self.readChunked(buf, chunked),
                };
            }

            pub fn close(self: *BodyState) void {
                if (self.closed) return;
                self.closed = true;
                if (self.owns_conn) self.conn.close();
                if (self.request_body) |writer| _ = writer.joinAndDestroy();
                self.request_body = null;
            }

            fn deinit(self: *BodyState) void {
                self.close();
                if (self.buffered_active) {
                    self.buffered.deinit();
                    self.buffered_active = false;
                }
                if (self.owns_conn) {
                    self.conn.deinit();
                    self.owns_conn = false;
                }
            }

            fn readFixed(self: *BodyState, buf: []u8, remaining: *usize) anyerror!usize {
                if (remaining.* == 0) return self.finishAndReturnEof();
                const n = try self.readFromBuffered(buf[0..@min(buf.len, remaining.*)]);
                if (n == 0) return error.EndOfStream;
                remaining.* -= n;
                if (remaining.* == 0) self.finishResponse();
                return n;
            }

            fn readChunked(self: *BodyState, buf: []u8, chunked: *ChunkedState) anyerror!usize {
                if (chunked.finished) return self.finishAndReturnEof();
                if (chunked.remaining_in_chunk == 0) {
                    var line_buf: [128]u8 = undefined;
                    const raw_line = try self.readBufferedLine(&line_buf);
                    const semi = stdz.mem.indexOfScalar(u8, raw_line, ';') orelse raw_line.len;
                    const size_text = stdz.mem.trim(u8, raw_line[0..semi], " ");
                    const chunk_size = try stdz.fmt.parseInt(usize, size_text, 16);
                    if (chunk_size == 0) {
                        while (true) {
                            const trailer = try self.readBufferedLine(&line_buf);
                            if (trailer.len == 0) break;
                        }
                        chunked.finished = true;
                        return self.finishAndReturnEof();
                    }
                    chunked.remaining_in_chunk = chunk_size;
                }

                const n = try self.readFromBuffered(buf[0..@min(buf.len, chunked.remaining_in_chunk)]);
                if (n == 0) return error.EndOfStream;
                chunked.remaining_in_chunk -= n;
                if (chunked.remaining_in_chunk == 0) try self.expectBufferedCrlf();
                return n;
            }

            fn readFromStream(self: *BodyState, buf: []u8) anyerror!usize {
                const n = try self.readFromBuffered(buf);
                if (n == 0) self.close();
                return n;
            }

            fn finishAndReturnEof(self: *BodyState) anyerror!usize {
                self.finishResponse();
                return 0;
            }

            fn finishResponse(self: *BodyState) void {
                if (self.complete) return;
                self.complete = true;

                const can_reuse = self.reusable and
                    self.buffered.ioReader().buffered().len == 0 and
                    self.finishRequestBody();

                if (self.buffered_active) {
                    self.buffered.deinit();
                    self.buffered_active = false;
                }
                if (can_reuse) {
                    self.transport.releaseConn(self.conn);
                    self.owns_conn = false;
                    self.closed = true;
                } else {
                    self.close();
                }
            }

            fn finishRequestBody(self: *BodyState) bool {
                const writer = self.request_body orelse return true;
                const result = writer.joinAndDestroy();
                self.request_body = null;
                return result == null;
            }

            fn readFromBuffered(self: *BodyState, buf: []u8) anyerror!usize {
                return self.buffered.ioReader().readSliceShort(buf) catch |err| switch (err) {
                    error.ReadFailed => return self.buffered.err() orelse error.Unexpected,
                    else => return err,
                };
            }

            fn readBufferedLine(self: *BodyState, out: []u8) anyerror![]const u8 {
                const raw = self.buffered.ioReader().takeDelimiterInclusive('\n') catch |err| switch (err) {
                    error.ReadFailed => return self.buffered.err() orelse error.Unexpected,
                    else => return err,
                };
                if (raw.len < 2 or raw[raw.len - 2] != '\r') return error.InvalidResponse;
                const line = raw[0 .. raw.len - 2];
                if (line.len > out.len) return error.BufferTooSmall;
                @memcpy(out[0..line.len], line);
                return out[0..line.len];
            }

            fn readBufferedByte(self: *BodyState) anyerror!u8 {
                var one: [1]u8 = undefined;
                const n = try self.readFromBuffered(&one);
                if (n == 0) return error.EndOfStream;
                return one[0];
            }

            fn expectBufferedCrlf(self: *BodyState) anyerror!void {
                if (try self.readBufferedByte() != '\r') return error.InvalidResponse;
                if (try self.readBufferedByte() != '\n') return error.InvalidResponse;
            }
        };

        const RequestBodyState = struct {
            allocator: Allocator,
            conn: NetConn,
            buffered: BufferedConnWriter,
            body: ReadCloser,
            io_buf: []u8,
            send_chunked: bool,
            content_length: usize,
            thread: ?grt.std.Thread = null,
            result: ?anyerror = null,

            fn spawn(
                allocator: Allocator,
                conn: NetConn,
                body: ReadCloser,
                send_chunked: bool,
                content_length: usize,
                io_buf_len: usize,
            ) !*RequestBodyState {
                const self = try allocator.create(RequestBodyState);
                errdefer allocator.destroy(self);
                const io_buf = try allocator.alloc(u8, @max(@as(usize, 1), io_buf_len));
                errdefer allocator.free(io_buf);
                self.* = .{
                    .allocator = allocator,
                    .conn = conn,
                    .buffered = try BufferedConnWriter.initAlloc(&self.conn, allocator, io_buf_len),
                    .body = body,
                    .io_buf = io_buf,
                    .send_chunked = send_chunked,
                    .content_length = content_length,
                };
                errdefer self.buffered.deinit();
                self.thread = try grt.std.Thread.spawn(.{}, RequestBodyState.run, .{self});
                return self;
            }

            fn run(self: *RequestBodyState) void {
                self.writeBody() catch |err| {
                    self.result = err;
                    self.body.close();
                    return;
                };
                self.result = null;
                self.body.close();
            }

            fn joinAndDestroy(self: *RequestBodyState) ?anyerror {
                if (self.thread) |thread| {
                    thread.join();
                    self.thread = null;
                }
                const result = self.result;
                self.buffered.deinit();
                self.allocator.free(self.io_buf);
                self.allocator.destroy(self);
                return result;
            }

            fn writeBody(self: *RequestBodyState) anyerror!void {
                if (self.send_chunked) {
                    try self.writeChunkedBody();
                } else {
                    try self.writeFixedBody();
                }
                try self.buffered.flush();
            }

            fn writeFixedBody(self: *RequestBodyState) anyerror!void {
                var remaining = self.content_length;
                while (remaining != 0) {
                    const n = try self.body.read(self.io_buf[0..@min(self.io_buf.len, remaining)]);
                    if (n == 0) return error.InvalidRequestBody;
                    try self.buffered.ioWriter().writeAll(self.io_buf[0..n]);
                    try self.buffered.flush();
                    remaining -= n;
                }
            }

            fn writeChunkedBody(self: *RequestBodyState) anyerror!void {
                var size_buf: [32]u8 = undefined;
                while (true) {
                    const n = try self.body.read(self.io_buf);
                    if (n == 0) break;
                    const size_line = stdz.fmt.bufPrint(&size_buf, "{x}\r\n", .{n}) catch return error.Unexpected;
                    try self.buffered.ioWriter().writeAll(size_line);
                    try self.buffered.ioWriter().writeAll(self.io_buf[0..n]);
                    try self.buffered.ioWriter().writeAll("\r\n");
                    try self.buffered.flush();
                }
                try self.buffered.ioWriter().writeAll("0\r\n\r\n");
            }
        };

        pub fn init(allocator: Allocator, conn: Conn, service_id: u64) Self {
            return initOptions(allocator, conn, service_id, .{});
        }

        pub fn initOptions(allocator: Allocator, conn: Conn, service_id: u64, options: Options) Self {
            return .{
                .allocator = allocator,
                .conn = conn,
                .service_id = service_id,
                .options = options,
            };
        }

        pub fn deinit(self: *Self) void {
            self.closeIdleConnections();
            self.idle_conns.deinit(self.allocator);
            self.* = undefined;
        }

        pub fn roundTripper(self: *Self) RoundTripper {
            return RoundTripper.init(self);
        }

        pub fn closeIdleConnections(self: *Self) void {
            self.idle_mu.lock();
            defer self.idle_mu.unlock();

            while (self.idle_conns.items.len != 0) {
                const index = self.idle_conns.items.len - 1;
                var conn = self.idle_conns.items[index];
                self.idle_conns.items.len = index;
                conn.deinit();
            }
        }

        pub fn roundTrip(self: *Self, req: *const Request) RoundTripper.RoundTripError!Response {
            try self.validateRequest(req);

            var net_conn = try self.acquireConn();
            errdefer net_conn.deinit();

            try self.applyDeadline(net_conn, req);
            try self.writeRequestHead(net_conn, req);

            var request_body: ?*RequestBodyState = null;
            errdefer if (request_body) |writer| {
                net_conn.close();
                _ = writer.joinAndDestroy();
            };

            if (req.body()) |body| {
                const send_chunked = self.shouldSendChunkedRequest(req);
                const content_length = if (!send_chunked and req.content_length > 0) @as(usize, @intCast(req.content_length)) else 0;
                request_body = try RequestBodyState.spawn(
                    self.allocator,
                    net_conn,
                    body,
                    send_chunked,
                    content_length,
                    self.options.body_io_buf_len,
                );
            }

            return self.readResponse(net_conn, req, &request_body);
        }

        fn validateRequest(self: *Self, req: *const Request) RoundTripper.RoundTripError!void {
            _ = self;
            if (!stdz.mem.eql(u8, req.url.scheme, "http")) return error.UnsupportedScheme;
            if (req.effectiveHost().len == 0) return error.MissingHost;
            if (req.trailer.len != 0) return error.UnsupportedTrailers;
            if (req.content_length > 0 and req.body() == null) return error.InvalidRequestBody;
        }

        fn applyDeadline(self: *Self, conn: NetConn, req: *const Request) RoundTripper.RoundTripError!void {
            _ = self;
            const ctx = req.context() orelse {
                conn.setReadDeadline(null);
                conn.setWriteDeadline(null);
                return;
            };
            const deadline = ctx.deadline() orelse {
                conn.setReadDeadline(null);
                conn.setWriteDeadline(null);
                return;
            };
            if (glib.time.instant.sub(deadline, grt.time.instant.now()) <= 0) return error.DeadlineExceeded;
            conn.setReadDeadline(deadline);
            conn.setWriteDeadline(deadline);
        }

        fn writeRequestHead(self: *Self, conn: NetConn, req: *const Request) RoundTripper.RoundTripError!void {
            var conn_writer = conn;
            var buffered = try BufferedConnWriter.initAlloc(&conn_writer, self.allocator, self.options.body_io_buf_len);
            defer buffered.deinit();

            const target = try self.requestTarget(req);
            defer self.allocator.free(target);
            const host = try self.hostHeaderValue(req);
            defer self.allocator.free(host);

            var writer = TextprotoWriter.fromBuffered(&buffered);
            try self.writeTextprotoLine(&writer, &buffered, &.{ req.effectiveMethod(), " ", target, " ", req.proto });

            var has_host = false;
            var has_connection_close = false;
            var has_user_agent = false;
            var has_content_length = false;
            var has_transfer_encoding = false;
            for (req.header) |hdr| {
                if (hdr.is(Header.host)) has_host = true;
                if (hdr.is(Header.connection) and framing.containsToken(hdr.value, "close")) has_connection_close = true;
                if (hdr.is(Header.user_agent)) has_user_agent = true;
                if (hdr.is(Header.content_length)) has_content_length = true;
                if (hdr.is(Header.transfer_encoding)) has_transfer_encoding = true;
                try self.writeTextprotoLine(&writer, &buffered, &.{ hdr.name, ": ", hdr.value });
            }
            if (!has_host) try self.writeTextprotoLine(&writer, &buffered, &.{ Header.host, ": ", host });
            if (req.close and !has_connection_close) try self.writeTextprotoLine(&writer, &buffered, &.{ Header.connection, ": close" });
            if (!has_user_agent and self.options.user_agent.len != 0) {
                try self.writeTextprotoLine(&writer, &buffered, &.{ Header.user_agent, ": ", self.options.user_agent });
            }

            if (req.body() != null) {
                if (self.shouldSendChunkedRequest(req)) {
                    if (!has_transfer_encoding) try self.writeTextprotoLine(&writer, &buffered, &.{ Header.transfer_encoding, ": chunked" });
                } else if (!has_content_length) {
                    const len = try stdz.fmt.allocPrint(self.allocator, "{d}", .{req.content_length});
                    defer self.allocator.free(len);
                    try self.writeTextprotoLine(&writer, &buffered, &.{ Header.content_length, ": ", len });
                }
            }

            try self.writeTextprotoLine(&writer, &buffered, &.{});
            try buffered.flush();
        }

        fn writeTextprotoLine(
            self: *Self,
            writer: *TextprotoWriter,
            buffered: *BufferedConnWriter,
            parts: []const []const u8,
        ) RoundTripper.RoundTripError!void {
            _ = self;
            writer.writeLineParts(parts) catch |err| switch (err) {
                error.InvalidLine => return error.InvalidHeader,
                error.WriteFailed => return buffered.err() orelse error.Unexpected,
            };
        }

        fn readResponse(
            self: *Self,
            conn: NetConn,
            req: *const Request,
            request_body: *?*RequestBodyState,
        ) RoundTripper.RoundTripError!Response {
            var conn_reader = conn;
            var buffered = try BufferedConnReader.initAlloc(&conn_reader, self.allocator, self.options.max_header_bytes);
            var buffered_transferred = false;
            defer if (!buffered_transferred) buffered.deinit();
            var informational_responses: usize = 0;

            while (true) {
                const head_storage = try self.readResponseHead(&buffered);
                var state = try self.allocator.create(ResponseState);
                errdefer self.allocator.destroy(state);
                state.* = .{
                    .allocator = self.allocator,
                    .head_storage = head_storage,
                    .headers = &.{},
                    .body_state = null,
                };
                var state_transferred = false;
                defer if (!state_transferred) responseStateDeinit(@ptrCast(state));

                const parsed = try self.parseHead(state);
                if (framing.isInformationalResponse(parsed.status_code)) {
                    informational_responses += 1;
                    if (informational_responses > 8) return error.InvalidResponse;
                    continue;
                }

                const body_mode = self.responseBodyMode(req, parsed);
                const has_body = switch (body_mode) {
                    .none => false,
                    .fixed => |remaining| remaining != 0,
                    .eof, .chunked => true,
                };

                const reusable = self.responseCanReuseConnection(req, parsed, body_mode);

                if (has_body) {
                    const body_state = try self.allocator.create(BodyState);
                    errdefer self.allocator.destroy(body_state);
                    body_state.* = .{
                        .allocator = self.allocator,
                        .transport = self,
                        .conn = conn,
                        .buffered = buffered,
                        .mode = body_mode,
                        .request_body = request_body.*,
                        .reusable = reusable,
                    };
                    body_state.buffered.rd = &body_state.conn;
                    request_body.* = null;
                    buffered_transferred = true;
                    state.body_state = body_state;
                } else {
                    buffered.deinit();
                    buffered_transferred = true;
                    const can_reuse = reusable and self.finishRequestBody(request_body);
                    if (can_reuse) {
                        self.releaseConn(conn);
                    } else {
                        var doomed = conn;
                        doomed.deinit();
                    }
                }

                state_transferred = true;
                return .{
                    .deinit_ptr = @ptrCast(state),
                    .deinit_fn = responseStateDeinit,
                    .status = parsed.status,
                    .status_code = parsed.status_code,
                    .proto = parsed.proto,
                    .proto_major = parsed.proto_major,
                    .proto_minor = parsed.proto_minor,
                    .header = parsed.headers,
                    .body_reader = if (has_body) ReadCloser.init(state.body_state.?) else null,
                    .content_length = if (parsed.content_length) |n| @intCast(n) else @as(i64, -1),
                    .close = !reusable,
                    .request = req.*,
                };
            }
        }

        fn readResponseHead(self: *Self, buffered: *BufferedConnReader) RoundTripper.RoundTripError![]u8 {
            var reader = TextprotoReader.fromBuffered(buffered);
            const raw = reader.takeHeaderBlockMax(self.options.max_header_bytes, .{}) catch |err| switch (err) {
                error.InvalidLineEnding => return error.InvalidResponse,
                error.BufferTooSmall => return error.BufferTooSmall,
                error.ReadFailed => return buffered.err() orelse error.Unexpected,
                else => return err,
            };
            return self.allocator.dupe(u8, raw);
        }

        fn parseHead(self: *Self, state: *ResponseState) RoundTripper.RoundTripError!ParsedHead {
            const status_line_end = stdz.mem.indexOf(u8, state.head_storage, "\r\n") orelse return error.InvalidResponse;
            const status_line = state.head_storage[0..status_line_end];
            const first_space = stdz.mem.indexOfScalar(u8, status_line, ' ') orelse return error.InvalidResponse;
            const proto = status_line[0..first_space];
            const rest = status_line[first_space + 1 ..];
            const second_space = stdz.mem.indexOfScalar(u8, rest, ' ') orelse return error.InvalidResponse;
            const code_slice = rest[0..second_space];
            const status_code = stdz.fmt.parseInt(u16, code_slice, 10) catch return error.InvalidResponse;

            var proto_major: u8 = 1;
            var proto_minor: u8 = 1;
            if (stdz.mem.startsWith(u8, proto, "HTTP/")) {
                const version = proto["HTTP/".len..];
                if (stdz.mem.indexOfScalar(u8, version, '.')) |dot| {
                    proto_major = stdz.fmt.parseInt(u8, version[0..dot], 10) catch return error.InvalidResponse;
                    proto_minor = stdz.fmt.parseInt(u8, version[dot + 1 ..], 10) catch return error.InvalidResponse;
                }
            }

            const header_block = state.head_storage[status_line_end + 2 ..];
            const header_count = framing.countHeaderLines(header_block);
            state.headers = if (header_count == 0) &.{} else try self.allocator.alloc(Header, header_count);

            var parsed = ParsedHead{
                .status = rest,
                .status_code = status_code,
                .proto = proto,
                .proto_major = proto_major,
                .proto_minor = proto_minor,
                .headers = state.headers,
            };

            var line_start: usize = 0;
            var header_index: usize = 0;
            while (line_start < header_block.len) {
                const rel_end = stdz.mem.indexOf(u8, header_block[line_start..], "\r\n") orelse return error.InvalidResponse;
                if (rel_end == 0) break;
                const line = header_block[line_start .. line_start + rel_end];
                const colon = stdz.mem.indexOfScalar(u8, line, ':') orelse return error.InvalidResponse;
                const name = stdz.mem.trim(u8, line[0..colon], " ");
                const value = stdz.mem.trim(u8, line[colon + 1 ..], " ");
                parsed.headers[header_index] = Header.init(name, value);
                header_index += 1;

                if (stdz.ascii.eqlIgnoreCase(name, Header.content_length)) {
                    parsed.content_length = stdz.fmt.parseInt(usize, value, 10) catch return error.InvalidResponse;
                } else if (stdz.ascii.eqlIgnoreCase(name, Header.transfer_encoding)) {
                    parsed.chunked = framing.containsToken(value, "chunked");
                } else if (stdz.ascii.eqlIgnoreCase(name, Header.connection)) {
                    parsed.close = framing.containsToken(value, "close");
                }

                line_start += rel_end + 2;
            }
            return parsed;
        }

        fn responseBodyMode(self: *Self, req: *const Request, parsed: ParsedHead) BodyState.BodyMode {
            _ = self;
            if (framing.responseMustBeBodyless(req.effectiveMethod(), parsed.status_code)) return .none;
            if (parsed.chunked) return .{ .chunked = .{} };
            if (parsed.content_length) |len| return .{ .fixed = len };
            return .eof;
        }

        fn requestTarget(self: *Self, req: *const Request) Allocator.Error![]u8 {
            if (req.request_uri.len != 0) return self.allocator.dupe(u8, req.request_uri);
            const path = if (req.url.path.len != 0) req.url.path else "/";
            if (req.url.raw_query.len == 0) return self.allocator.dupe(u8, path);
            return stdz.fmt.allocPrint(self.allocator, "{s}?{s}", .{ path, req.url.raw_query });
        }

        fn hostHeaderValue(self: *Self, req: *const Request) Allocator.Error![]u8 {
            if (req.host.len != 0) return self.allocator.dupe(u8, req.host);
            if (req.url.port.len == 0) return self.allocator.dupe(u8, req.url.host);
            return stdz.fmt.allocPrint(self.allocator, "{s}:{s}", .{ req.url.host, req.url.port });
        }

        fn shouldSendChunkedRequest(_: *Self, req: *const Request) bool {
            if (req.transfer_encoding.len != 0) {
                for (req.transfer_encoding) |encoding| {
                    if (stdz.ascii.eqlIgnoreCase(encoding, "chunked")) return true;
                }
            }
            return req.content_length <= 0;
        }

        fn acquireConn(self: *Self) RoundTripper.RoundTripError!NetConn {
            self.idle_mu.lock();
            if (self.idle_conns.items.len != 0) {
                const index = self.idle_conns.items.len - 1;
                const conn = self.idle_conns.items[index];
                self.idle_conns.items.len = index;
                self.idle_mu.unlock();
                return conn;
            }
            self.idle_mu.unlock();

            const stream = self.conn.openStream(self.service_id) catch |err| return self.mapOpenStreamError(err);
            errdefer stream.deinit();
            return StreamConnImpl.init(self.allocator, stream);
        }

        fn releaseConn(self: *Self, conn: NetConn) void {
            var idle_conn = conn;
            idle_conn.setReadDeadline(null);
            idle_conn.setWriteDeadline(null);

            self.idle_mu.lock();
            self.idle_conns.append(self.allocator, idle_conn) catch {
                self.idle_mu.unlock();
                idle_conn.deinit();
                return;
            };
            self.idle_mu.unlock();
        }

        fn finishRequestBody(_: *Self, request_body: *?*RequestBodyState) bool {
            const writer = request_body.* orelse return true;
            const result = writer.joinAndDestroy();
            request_body.* = null;
            return result == null;
        }

        fn responseCanReuseConnection(self: *Self, req: *const Request, parsed: ParsedHead, body_mode: BodyState.BodyMode) bool {
            if (req.close or self.requestHasConnectionClose(req)) return false;
            if (parsed.close) return false;
            return switch (body_mode) {
                .none, .fixed, .chunked => true,
                .eof => false,
            };
        }

        fn requestHasConnectionClose(_: *Self, req: *const Request) bool {
            for (req.header) |hdr| {
                if (hdr.is(Header.connection) and framing.containsToken(hdr.value, "close")) return true;
            }
            return false;
        }

        fn mapOpenStreamError(self: *Self, err: anyerror) RoundTripper.RoundTripError {
            _ = self;
            return switch (err) {
                error.OutOfMemory => error.OutOfMemory,
                error.Timeout => error.TimedOut,
                error.ConnClosed,
                error.StreamClosed,
                error.RuntimeChannelClosed,
                error.KcpStreamClosed,
                => error.ConnectionReset,
                else => error.Unexpected,
            };
        }

        fn responseStateDeinit(ptr: *anyopaque) void {
            const state: *ResponseState = @ptrCast(@alignCast(ptr));
            if (state.body_state) |body| {
                body.deinit();
                state.allocator.destroy(body);
            }
            if (state.headers.len != 0) state.allocator.free(state.headers);
            state.allocator.free(state.head_storage);
            state.allocator.destroy(state);
        }
    };
}
