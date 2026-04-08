const dep = @import("dep");
const testing_api = dep.testing;

const HttpRealUdpFixtureFile = @import("http_real_udp_fixture.zig");

const peer_public_key_header = "X-Peer-Public-Key";

pub fn make(comptime lib: type) testing_api.TestRunner {
    const testing = lib.testing;
    const Fixture = HttpRealUdpFixtureFile.make(lib);
    const HttpServer = dep.net.http.Server(lib);
    const HttpClient = dep.net.http.Client(lib);
    const HttpHandler = dep.net.http.Handler(lib);
    const Header = dep.net.http.Header;
    const Request = dep.net.http.Request;
    const ReadCloser = dep.net.http.ReadCloser;
    const ResponseWriter = dep.net.http.ResponseWriter(lib);

    const SliceBody = struct {
        bytes: []const u8,
        offset: usize = 0,

        pub fn read(self: *@This(), buf: []u8) anyerror!usize {
            const remaining = self.bytes[self.offset..];
            const n = @min(buf.len, remaining.len);
            @memcpy(buf[0..n], remaining[0..n]);
            self.offset += n;
            return n;
        }

        pub fn close(_: *@This()) void {}
    };

    const HandlerState = struct {
        allocator: dep.embed.mem.Allocator,
        mutex: lib.Thread.Mutex = .{},
        request_count: usize = 0,
        header_value: ?[]u8 = null,
        body_value: ?[]u8 = null,
        err: ?anyerror = null,

        fn deinit(self: *@This()) void {
            if (self.header_value) |value| self.allocator.free(value);
            if (self.body_value) |value| self.allocator.free(value);
            self.* = undefined;
        }

        pub fn serveHTTP(self: *@This(), rw: *ResponseWriter, req: *Request) void {
            const header_value = headerValue(req.header, peer_public_key_header) orelse {
                self.recordError(error.MissingHeader);
                rw.writeHeader(400) catch {};
                return;
            };

            const body_value = readRequestBody(self.allocator, req) catch |err| {
                self.recordError(err);
                rw.writeHeader(500) catch {};
                return;
            };
            defer self.allocator.free(body_value);

            self.recordRequest(header_value, body_value) catch |err| {
                self.recordError(err);
                rw.writeHeader(500) catch {};
                return;
            };

            var len_buf: [32]u8 = undefined;
            const content_length = lib.fmt.bufPrint(&len_buf, "{d}", .{body_value.len}) catch {
                self.recordError(error.Unexpected);
                rw.writeHeader(500) catch {};
                return;
            };
            rw.setHeader(Header.content_length, content_length) catch {
                self.recordError(error.OutOfMemory);
                rw.writeHeader(500) catch {};
                return;
            };
            _ = rw.write(body_value) catch |err| {
                self.recordError(err);
            };
        }

        fn recordRequest(self: *@This(), header: []const u8, body: []const u8) !void {
            self.mutex.lock();
            defer self.mutex.unlock();

            if (self.header_value) |value| self.allocator.free(value);
            if (self.body_value) |value| self.allocator.free(value);
            self.header_value = try self.allocator.dupe(u8, header);
            self.body_value = try self.allocator.dupe(u8, body);
            self.request_count += 1;
        }

        fn recordError(self: *@This(), err: anyerror) void {
            self.mutex.lock();
            defer self.mutex.unlock();

            if (self.err == null) self.err = err;
        }

        fn assertObserved(self: *@This(), expected_header: []const u8, expected_body: []const u8, testing_ns: anytype) !void {
            self.mutex.lock();
            defer self.mutex.unlock();

            if (self.err) |err| return err;
            try testing_ns.expectEqual(@as(usize, 1), self.request_count);
            try testing_ns.expect(self.header_value != null);
            try testing_ns.expect(self.body_value != null);
            try testing_ns.expectEqualStrings(expected_header, self.header_value.?);
            try testing_ns.expectEqualStrings(expected_body, self.body_value.?);
        }
    };

    const ServeTask = struct {
        server: *HttpServer,
        listener: dep.net.Listener,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            defer self.listener.deinit();
            self.server.serve(self.listener) catch |err| {
                if (err != error.ServerClosed) self.err = err;
            };
        }
    };

    const Local = struct {
        fn runCase(fixture: *Fixture, allocator: dep.embed.mem.Allocator) !void {
            const request_body = "hello from http_transport over udp";
            const expected_header = try fixture.expectedPeerPublicKeyHeader();
            defer allocator.free(expected_header);

            var handler = HandlerState{
                .allocator = allocator,
            };
            defer handler.deinit();

            var server = try HttpServer.init(allocator, .{});
            defer server.deinit();
            try server.handle("/", HttpHandler.init(&handler));

            var serve_task = ServeTask{
                .server = &server,
                .listener = try fixture.serverListener(),
            };
            var serve_thread = try lib.Thread.spawn(.{}, ServeTask.run, .{&serve_task});
            errdefer {
                server.close();
                serve_thread.join();
            }

            var transport = try fixture.clientTransport();
            var client = try HttpClient.init(allocator, .{
                .round_tripper = dep.net.http.RoundTripper.init(&transport),
            });
            defer client.deinit();

            {
                var body = SliceBody{
                    .bytes = request_body,
                };
                var req = try Request.init(allocator, "POST", "http://peer-http/echo");
                defer req.deinit();
                req = req.withBody(ReadCloser.init(&body));
                req.content_length = @intCast(request_body.len);

                var resp = try client.do(&req);
                defer resp.deinit();

                try testing.expectEqual(@as(u16, 200), resp.status_code);
                const response_body = if (resp.body()) |response_body|
                    try readAllReadCloser(allocator, response_body)
                else
                    try allocator.dupe(u8, "");
                defer allocator.free(response_body);

                try testing.expectEqualStrings(request_body, response_body);
            }

            server.close();
            serve_thread.join();
            if (serve_task.err) |err| return err;

            fixture.stopDriver();
            try fixture.closeService();
            try fixture.driveIgnoringServiceRejected(64);

            try fixture.ensureDriverHealthy();
            try handler.assertObserved(expected_header, request_body, testing);
        }
    };

    const Runner = struct {
        pub fn init(self: *@This(), allocator: dep.embed.mem.Allocator) !void {
            _ = self;
            _ = allocator;
        }

        pub fn run(self: *@This(), t: *testing_api.T, allocator: dep.embed.mem.Allocator) bool {
            _ = self;

            var fixture = Fixture.init(allocator, .{}) catch |err| {
                t.logErrorf("integration/net/http_transport client_server_real_udp setup failed: {}", .{err});
                return false;
            };
            defer fixture.deinit();

            fixture.startDriver() catch |err| {
                t.logErrorf("integration/net/http_transport client_server_real_udp driver failed to start: {}", .{err});
                return false;
            };

            Local.runCase(&fixture, allocator) catch |err| {
                t.logErrorf("integration/net/http_transport client_server_real_udp failed: {}", .{err});
                return false;
            };
            return true;
        }

        pub fn deinit(self: *@This(), allocator: dep.embed.mem.Allocator) void {
            _ = allocator;
            lib.testing.allocator.destroy(self);
        }
    };

    const value = lib.testing.allocator.create(Runner) catch @panic("OOM");
    value.* = .{};
    return testing_api.TestRunner.make(Runner).new(value);
}

fn headerValue(headers: []const dep.net.http.Header, name: []const u8) ?[]const u8 {
    for (headers) |hdr| {
        if (hdr.is(name)) return hdr.value;
    }
    return null;
}

fn readAllReadCloser(allocator: dep.embed.mem.Allocator, body: dep.net.http.ReadCloser) ![]u8 {
    var storage = try allocator.alloc(u8, 64);
    errdefer allocator.free(storage);

    var len: usize = 0;
    while (true) {
        if (len == storage.len) {
            storage = try allocator.realloc(storage, storage.len * 2);
        }

        const n = body.read(storage[len..]) catch |err| switch (err) {
            error.EndOfStream => break,
            else => return err,
        };
        if (n == 0) break;
        len += n;
    }

    return allocator.realloc(storage, len);
}

fn readRequestBody(allocator: dep.embed.mem.Allocator, req: *dep.net.http.Request) ![]u8 {
    if (req.body()) |body| return readAllReadCloser(allocator, body);
    return allocator.dupe(u8, "");
}
