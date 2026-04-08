const dep = @import("dep");
const testing_api = dep.testing;

const bench = @import("../common.zig");
const HttpRealUdpFixtureFile = @import("../../integration/http_transport/http_real_udp_fixture.zig");

const peer_public_key_header = "X-Peer-Public-Key";
const payload_len: usize = 64 * 1024;
const upload_payload: [payload_len]u8 = [_]u8{0x55} ** payload_len;
const download_payload: [payload_len]u8 = [_]u8{0x66} ** payload_len;
const echo_payload: [payload_len]u8 = [_]u8{0x77} ** payload_len;

pub fn make(comptime lib: type) testing_api.TestRunner {
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

    const BenchHandler = struct {
        expected_header: []const u8,
        mutex: lib.Thread.Mutex = .{},
        err: ?anyerror = null,

        pub fn serveHTTP(self: *@This(), rw: *ResponseWriter, req: *Request) void {
            const observed = headerValue(req.header, peer_public_key_header) orelse {
                self.recordError(error.MissingHeader);
                rw.writeHeader(400) catch {};
                return;
            };
            if (!dep.embed.mem.eql(u8, observed, self.expected_header)) {
                self.recordError(error.TestUnexpectedResult);
                rw.writeHeader(400) catch {};
                return;
            }

            const path = if (req.url.path.len != 0) req.url.path else "/";
            if (dep.embed.mem.eql(u8, path, "/download")) {
                self.handleDownload(rw);
                return;
            }
            if (dep.embed.mem.eql(u8, path, "/upload")) {
                self.handleUpload(rw, req);
                return;
            }
            if (dep.embed.mem.eql(u8, path, "/echo")) {
                self.handleEcho(rw, req);
                return;
            }

            self.recordError(error.TestUnexpectedResult);
            rw.writeHeader(404) catch {};
        }

        fn handleDownload(self: *@This(), rw: *ResponseWriter) void {
            var len_buf: [32]u8 = undefined;
            const content_length = lib.fmt.bufPrint(&len_buf, "{d}", .{download_payload.len}) catch {
                self.recordError(error.Unexpected);
                rw.writeHeader(500) catch {};
                return;
            };
            rw.setHeader(Header.content_length, content_length) catch {
                self.recordError(error.OutOfMemory);
                rw.writeHeader(500) catch {};
                return;
            };
            _ = rw.write(&download_payload) catch |err| self.recordError(err);
        }

        fn handleUpload(self: *@This(), rw: *ResponseWriter, req: *Request) void {
            const body = req.body() orelse {
                self.recordError(error.TestUnexpectedResult);
                rw.writeHeader(400) catch {};
                return;
            };
            const total = drainBody(body) catch |err| {
                self.recordError(err);
                rw.writeHeader(500) catch {};
                return;
            };
            if (total != upload_payload.len) {
                self.recordError(error.TestUnexpectedResult);
                rw.writeHeader(400) catch {};
                return;
            }
            rw.writeHeader(204) catch |err| self.recordError(err);
        }

        fn handleEcho(self: *@This(), rw: *ResponseWriter, req: *Request) void {
            const body = req.body() orelse {
                self.recordError(error.TestUnexpectedResult);
                rw.writeHeader(400) catch {};
                return;
            };

            var received: [payload_len]u8 = undefined;
            var total: usize = 0;
            while (total < received.len) {
                const n = body.read(received[total..]) catch |err| {
                    self.recordError(err);
                    rw.writeHeader(500) catch {};
                    return;
                };
                if (n == 0) break;
                total += n;
            }
            if (total != echo_payload.len) {
                self.recordError(error.TestUnexpectedResult);
                rw.writeHeader(400) catch {};
                return;
            }
            if (!dep.embed.mem.eql(u8, &echo_payload, received[0..total])) {
                self.recordError(error.TestUnexpectedResult);
                rw.writeHeader(400) catch {};
                return;
            }

            var len_buf: [32]u8 = undefined;
            const content_length = lib.fmt.bufPrint(&len_buf, "{d}", .{total}) catch {
                self.recordError(error.Unexpected);
                rw.writeHeader(500) catch {};
                return;
            };
            rw.setHeader(Header.content_length, content_length) catch {
                self.recordError(error.OutOfMemory);
                rw.writeHeader(500) catch {};
                return;
            };
            _ = rw.write(received[0..total]) catch |err| self.recordError(err);
        }

        fn recordError(self: *@This(), err: anyerror) void {
            self.mutex.lock();
            defer self.mutex.unlock();
            if (self.err == null) self.err = err;
        }

        fn ensureHealthy(self: *@This()) !void {
            self.mutex.lock();
            defer self.mutex.unlock();
            if (self.err) |err| return err;
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
        fn withClient(allocator: dep.embed.mem.Allocator, comptime run_fn: *const fn (*HttpClient) anyerror!u64) !u64 {
            var fixture = try Fixture.init(allocator, .{});
            defer fixture.deinit();
            try fixture.startDriver();

            const expected_header = try fixture.expectedPeerPublicKeyHeader();
            defer allocator.free(expected_header);

            var handler = BenchHandler{
                .expected_header = expected_header,
            };

            var server = try HttpServer.init(allocator, .{});
            defer server.deinit();
            try server.handle("/", HttpHandler.init(&handler));

            var serve_task = ServeTask{
                .server = &server,
                .listener = try fixture.serverListener(),
            };
            var serve_thread = try lib.Thread.spawn(.{}, ServeTask.run, .{&serve_task});
            var serve_thread_active = true;
            defer if (serve_thread_active) {
                server.close();
                serve_thread.join();
            };

            var transport = try fixture.clientTransport();
            var client = try HttpClient.init(allocator, .{
                .round_tripper = dep.net.http.RoundTripper.init(&transport),
            });
            var client_active = true;
            defer if (client_active) client.deinit();

            const elapsed_ns = try run_fn(&client);
            lib.Thread.sleep(25 * lib.time.ns_per_ms);

            client.deinit();
            client_active = false;

            server.close();
            serve_thread.join();
            serve_thread_active = false;

            fixture.stopDriver();
            try fixture.closeService();
            try fixture.driveIgnoringServiceRejected(64);

            try handler.ensureHealthy();
            try fixture.ensureDriverHealthy();
            if (serve_task.err) |err| return err;
            return elapsed_ns;
        }

        fn runDownloadCase(allocator: dep.embed.mem.Allocator) !u64 {
            const config: bench.Config = .{
                .warmup = 0,
                .iterations = 1,
            };

            const elapsed_ns = try withClient(allocator, struct {
                fn run(client: *HttpClient) !u64 {
                    const State = struct {
                        client: *HttpClient,
                        sink: usize = 0,
                    };
                    var state = State{ .client = client };

                    const elapsed_ns = try bench.runLoop(lib, config, &state, struct {
                        fn runOne(value: *State) !void {
                            var req = try Request.init(lib.testing.allocator, "GET", "http://peer-http/download");
                            defer req.deinit();

                            var resp = try value.client.do(&req);
                            defer resp.deinit();
                            if (resp.status_code != 200) return error.TestUnexpectedResult;

                            const response_body = resp.body() orelse return error.TestUnexpectedResult;
                            try readExactBody(response_body, &download_payload);
                            value.sink +%= download_payload.len;
                        }
                    }.runOne);
                    lib.mem.doNotOptimizeAway(state.sink);
                    return elapsed_ns;
                }
            }.run);

            bench.print(lib, "http_transport.real_udp.download", config, elapsed_ns, .{
                .tier = .smoke,
                .impairment = bench.no_impairment,
                .payload_bytes_per_op = download_payload.len,
                .copy_bytes_per_op = download_payload.len,
            });

            return elapsed_ns;
        }

        fn runUploadCase(allocator: dep.embed.mem.Allocator) !u64 {
            const config: bench.Config = .{
                .warmup = 0,
                .iterations = 1,
            };

            const elapsed_ns = try withClient(allocator, struct {
                fn run(client: *HttpClient) !u64 {
                    const State = struct {
                        client: *HttpClient,
                        sink: usize = 0,
                    };
                    var state = State{ .client = client };

                    const elapsed_ns = try bench.runLoop(lib, config, &state, struct {
                        fn runOne(value: *State) !void {
                            var request_body = SliceBody{ .bytes = &upload_payload };
                            var req = try Request.init(lib.testing.allocator, "POST", "http://peer-http/upload");
                            defer req.deinit();
                            req = req.withBody(ReadCloser.init(&request_body));
                            req.content_length = upload_payload.len;

                            var resp = try value.client.do(&req);
                            defer resp.deinit();
                            if (resp.status_code != 204) return error.TestUnexpectedResult;
                            value.sink +%= upload_payload.len;
                        }
                    }.runOne);
                    lib.mem.doNotOptimizeAway(state.sink);
                    return elapsed_ns;
                }
            }.run);

            bench.print(lib, "http_transport.real_udp.upload", config, elapsed_ns, .{
                .tier = .smoke,
                .impairment = bench.no_impairment,
                .payload_bytes_per_op = upload_payload.len,
                .copy_bytes_per_op = upload_payload.len,
            });

            return elapsed_ns;
        }

        fn runEchoCase(allocator: dep.embed.mem.Allocator) !u64 {
            const config: bench.Config = .{
                .warmup = 0,
                .iterations = 1,
            };

            const elapsed_ns = try withClient(allocator, struct {
                fn run(client: *HttpClient) !u64 {
                    const State = struct {
                        client: *HttpClient,
                        sink: usize = 0,
                    };
                    var state = State{ .client = client };

                    const elapsed_ns = try bench.runLoop(lib, config, &state, struct {
                        fn runOne(value: *State) !void {
                            var request_body = SliceBody{ .bytes = &echo_payload };
                            var req = try Request.init(lib.testing.allocator, "POST", "http://peer-http/echo");
                            defer req.deinit();
                            req = req.withBody(ReadCloser.init(&request_body));
                            req.content_length = echo_payload.len;

                            var resp = try value.client.do(&req);
                            defer resp.deinit();
                            if (resp.status_code != 200) return error.TestUnexpectedResult;

                            const response_body = resp.body() orelse return error.TestUnexpectedResult;
                            try readExactBody(response_body, &echo_payload);
                            value.sink +%= echo_payload.len * 2;
                        }
                    }.runOne);
                    lib.mem.doNotOptimizeAway(state.sink);
                    return elapsed_ns;
                }
            }.run);

            bench.print(lib, "http_transport.real_udp.echo", config, elapsed_ns, .{
                .tier = .smoke,
                .impairment = bench.no_impairment,
                .payload_bytes_per_op = echo_payload.len * 2,
                .copy_bytes_per_op = echo_payload.len * 2,
            });

            return elapsed_ns;
        }
    };

    const Runner = struct {
        pub fn init(self: *@This(), allocator: dep.embed.mem.Allocator) !void {
            _ = self;
            _ = allocator;
        }

        pub fn run(self: *@This(), t: *testing_api.T, allocator: dep.embed.mem.Allocator) bool {
            _ = self;

            _ = Local.runDownloadCase(allocator) catch |err| {
                t.logErrorf("benchmark/http_transport/real_udp download failed: {}", .{err});
                return false;
            };

            _ = Local.runUploadCase(allocator) catch |err| {
                t.logErrorf("benchmark/http_transport/real_udp upload failed: {}", .{err});
                return false;
            };

            _ = Local.runEchoCase(allocator) catch |err| {
                t.logErrorf("benchmark/http_transport/real_udp echo failed: {}", .{err});
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

fn readExactBody(body: dep.net.http.ReadCloser, expected: []const u8) !void {
    var received: [payload_len]u8 = undefined;
    var total: usize = 0;
    while (total < expected.len) {
        const n = body.read(received[total..expected.len]) catch |err| switch (err) {
            error.EndOfStream => break,
            else => return err,
        };
        if (n == 0) break;
        total += n;
    }
    if (total != expected.len) return error.TestUnexpectedResult;
    if (!dep.embed.mem.eql(u8, expected, received[0..total])) return error.TestUnexpectedResult;
}

fn drainBody(body: dep.net.http.ReadCloser) !usize {
    var total: usize = 0;
    var buf: [4096]u8 = undefined;
    while (true) {
        const n = body.read(&buf) catch |err| switch (err) {
            error.EndOfStream => break,
            else => return err,
        };
        if (n == 0) break;
        total += n;
    }
    return total;
}
