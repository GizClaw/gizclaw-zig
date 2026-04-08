const dep = @import("dep");
const net_pkg = @import("../../../../net.zig");

const ListenerFile = @import("../../../http_transport/Listener.zig");
const TransportFile = @import("../../../http_transport/Transport.zig");
const PeerRealUdpFixtureFile = @import("../peer/peer_real_udp_fixture.zig");

pub fn make(comptime lib: type) type {
    const Net = net_pkg.make(lib);
    const Peer = Net.peer;
    const HttpListener = ListenerFile.make(Peer);
    const HttpTransport = TransportFile.make(Peer);
    const PeerFixture = PeerRealUdpFixtureFile.make(lib);

    return struct {
        allocator: dep.embed.mem.Allocator,
        peer_fixture: PeerFixture,
        service_id: u64,
        driver_mu: lib.Thread.Mutex = .{},
        driver_thread: ?lib.Thread = null,
        driver_stop: bool = false,
        driver_err: ?anyerror = null,

        const Self = @This();
        pub const default_service_id: u64 = 71;

        pub const Options = struct {
            service_id: u64 = default_service_id,
        };

        pub fn init(allocator: dep.embed.mem.Allocator, options: Options) !Self {
            var peer_fixture = try PeerFixture.init(allocator, .{
                .enable_kcp = true,
                .allow_all_services = true,
            });
            errdefer peer_fixture.deinit();

            try peer_fixture.dialAndAccept();

            return .{
                .allocator = allocator,
                .peer_fixture = peer_fixture,
                .service_id = options.service_id,
            };
        }

        pub fn deinit(self: *Self) void {
            self.stopDriver();
            self.peer_fixture.deinit();
            self.* = undefined;
        }

        pub fn startDriver(self: *Self) !void {
            self.driver_mu.lock();
            defer self.driver_mu.unlock();

            if (self.driver_thread != null) return;
            self.driver_stop = false;
            self.driver_err = null;
            self.driver_thread = try lib.Thread.spawn(.{}, driveLoop, .{self});
        }

        pub fn stopDriver(self: *Self) void {
            self.driverMuSetStop();
            if (self.driver_thread) |thread| {
                thread.join();
                self.driver_thread = null;
            }
        }

        pub fn ensureDriverHealthy(self: *Self) !void {
            self.driver_mu.lock();
            defer self.driver_mu.unlock();

            if (self.driver_err) |err| return err;
        }

        pub fn serverListener(self: *Self) !dep.net.Listener {
            return HttpListener.init(self.allocator, try self.peer_fixture.serverConn(), self.service_id);
        }

        pub fn clientTransport(self: *Self) !HttpTransport {
            return .{
                .allocator = self.allocator,
                .conn = try self.peer_fixture.clientConn(),
                .service_id = self.service_id,
            };
        }

        pub fn expectedPeerPublicKeyHeader(self: *Self) ![]u8 {
            var buf: [64]u8 = undefined;
            return self.allocator.dupe(u8, formatKeyHexLower(&buf, self.peer_fixture.base.server_static.public));
        }

        pub fn drive(self: *Self, rounds: usize) !void {
            try self.peer_fixture.drive(rounds);
        }

        pub fn closeService(self: *Self) !void {
            if (self.peer_fixture.client_conn) |conn| {
                conn.closeService(self.service_id) catch |err| switch (err) {
                    error.StreamNotFound, error.ServiceRejected => {},
                    else => return err,
                };
            }
            if (self.peer_fixture.server_conn) |conn| {
                conn.closeService(self.service_id) catch |err| switch (err) {
                    error.StreamNotFound, error.ServiceRejected => {},
                    else => return err,
                };
            }
        }

        pub fn driveIgnoringServiceRejected(self: *Self, rounds: usize) !void {
            var round: usize = 0;
            while (round < rounds) : (round += 1) {
                self.drive(1) catch |err| switch (err) {
                    error.ServiceRejected => continue,
                    else => return err,
                };
            }
        }

        fn driveLoop(self: *Self) void {
            while (true) {
                self.driver_mu.lock();
                const should_stop = self.driver_stop;
                self.driver_mu.unlock();
                if (should_stop) return;

                self.peer_fixture.drive(1) catch |err| {
                    self.driver_mu.lock();
                    if (!self.driver_stop and self.driver_err == null) self.driver_err = err;
                    self.driver_stop = true;
                    self.driver_mu.unlock();
                    return;
                };
            }
        }

        fn driverMuSetStop(self: *Self) void {
            self.driver_mu.lock();
            self.driver_stop = true;
            self.driver_mu.unlock();
        }
    };
}

fn formatKeyHexLower(buf: *[64]u8, key: anytype) []const u8 {
    const chars = "0123456789abcdef";
    for (key.asBytes().*, 0..) |byte, i| {
        buf[i * 2] = chars[byte >> 4];
        buf[i * 2 + 1] = chars[byte & 0x0f];
    }
    return buf;
}
