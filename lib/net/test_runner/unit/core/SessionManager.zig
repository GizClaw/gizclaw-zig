const dep = @import("dep");
const testing_api = @import("dep").testing;
const noise = @import("../../../noise.zig");
const errors = @import("../../../core/errors.zig");
const SessionManagerFile = @import("../../../core/SessionManager.zig");

pub fn make(comptime lib: type) testing_api.TestRunner {
    const Runner = struct {
        pub fn init(self: *@This(), allocator: dep.embed.mem.Allocator) !void {
            _ = self;
            _ = allocator;
        }

        pub fn run(self: *@This(), t: *testing_api.T, allocator: dep.embed.mem.Allocator) bool {
            _ = self;
            runCases(lib, lib.testing, allocator) catch |err| {
                t.logErrorf("core/SessionManager failed: {}", .{err});
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

fn runCases(comptime lib: type, testing: anytype, allocator: dep.embed.mem.Allocator) !void {
    const Noise = noise.make(lib);
    const Manager = SessionManagerFile.make(lib, Noise);
    const Thread = lib.Thread;
    const Mutex = Thread.Mutex;
    const Condition = Thread.Condition;

    const StartGate = struct {
        mutex: Mutex = .{},
        cond: Condition = .{},
        ready: usize = 0,
        target: usize,

        fn init(target: usize) @This() {
            return .{ .target = target };
        }

        fn wait(self: *@This()) void {
            self.mutex.lock();
            defer self.mutex.unlock();

            self.ready += 1;
            if (self.ready == self.target) {
                self.cond.broadcast();
                return;
            }
            while (self.ready < self.target) self.cond.wait(&self.mutex);
        }
    };

    var manager = try Manager.init(allocator);
    defer manager.deinit();

    const send_a = noise.Key.fromBytes([_]u8{1} ** noise.Key.key_size);
    const recv_a = noise.Key.fromBytes([_]u8{2} ** noise.Key.key_size);
    const pk_a = noise.Key.fromBytes([_]u8{3} ** noise.Key.key_size);
    const pk_b = noise.Key.fromBytes([_]u8{4} ** noise.Key.key_size);

    try testing.expectError(errors.Error.InvalidReceiverIndex, manager.createSession(pk_a, send_a, recv_a, 0));

    const first = try manager.createSession(pk_a, send_a, recv_a, 41);
    try testing.expect(first.localIndex() != 0);
    try testing.expectEqual(@as(usize, 1), manager.count());
    try testing.expect(manager.getByIndex(first.localIndex()) == first);
    try testing.expect(manager.getByPublicKey(pk_a) == first);
    try testing.expectEqual(@as(u32, 41), first.remoteIndex());

    const replaced = try manager.createSession(pk_a, recv_a, send_a, 42);
    try testing.expectEqual(@as(usize, 1), manager.count());
    try testing.expect(manager.getByPublicKey(pk_a) == replaced);
    try testing.expect(manager.getByIndex(first.localIndex()) == null);

    const second = try manager.createSession(pk_b, send_a, recv_a, 43);
    try testing.expectEqual(@as(usize, 2), manager.count());
    try testing.expect(manager.getByPublicKey(pk_b) == second);

    try testing.expect(manager.getByIndex(first.localIndex()) == null);

    const external = try allocator.create(Noise.Session);
    defer allocator.destroy(external);
    external.* = Noise.Session.init(.{
        .local_index = 99,
        .remote_index = 44,
        .send_key = send_a,
        .recv_key = recv_a,
        .remote_pk = noise.Key.fromBytes([_]u8{5} ** noise.Key.key_size),
    });
    try testing.expect((try manager.registerSession(external)) == external);
    try testing.expect(manager.getByIndex(99) == external);

    const conflicting = try allocator.create(Noise.Session);
    defer allocator.destroy(conflicting);
    conflicting.* = Noise.Session.init(.{
        .local_index = second.localIndex(),
        .remote_index = 45,
        .send_key = send_a,
        .recv_key = recv_a,
        .remote_pk = noise.Key.fromBytes([_]u8{6} ** noise.Key.key_size),
    });
    try testing.expectError(errors.Error.IndexInUse, manager.registerSession(conflicting));

    const same_peer_conflict = try allocator.create(Noise.Session);
    defer allocator.destroy(same_peer_conflict);
    same_peer_conflict.* = Noise.Session.init(.{
        .local_index = second.localIndex(),
        .remote_index = 46,
        .send_key = send_a,
        .recv_key = recv_a,
        .remote_pk = pk_b,
    });
    try testing.expectError(errors.Error.IndexInUse, manager.registerSession(same_peer_conflict));

    var callback_remote_index: u32 = 0;
    try testing.expect(manager.withSessionByPublicKeyLocked(pk_b, &callback_remote_index, struct {
        fn call(out: *u32, session: *Noise.Session) void {
            out.* = session.remoteIndex();
        }
    }.call));
    try testing.expectEqual(@as(u32, 43), callback_remote_index);

    const index_snapshot = try manager.localIndexSnapshot();
    defer allocator.free(index_snapshot);
    try testing.expectEqual(@as(usize, 3), index_snapshot.len);
    const key_snapshot = try manager.publicKeySnapshot();
    defer allocator.free(key_snapshot);
    try testing.expectEqual(@as(usize, 3), key_snapshot.len);

    second.expire();
    try testing.expectEqual(@as(usize, 1), manager.expire());
    try testing.expectEqual(@as(usize, 2), manager.count());

    var worker_manager = try Manager.init(allocator);
    defer worker_manager.deinit();
    const worker_session = try worker_manager.createSession(pk_a, send_a, recv_a, 77);
    worker_session.expire();
    try worker_manager.startExpiryWorker(1);
    defer worker_manager.stopExpiryWorker();
    while (worker_manager.count() != 0) {
        lib.Thread.sleep(lib.time.ns_per_ms);
    }
    try testing.expectEqual(@as(usize, 0), worker_manager.count());
    try testing.expectError(errors.Error.ExpiryWorkerAlreadyRunning, worker_manager.startExpiryWorker(1));

    var concurrent_manager = try Manager.init(allocator);
    defer concurrent_manager.deinit();
    _ = try concurrent_manager.createSession(pk_a, send_a, recv_a, 88);
    var gate = StartGate.init(3);
    var callback_hits = lib.atomic.Value(u32).init(0);
    var null_reads = lib.atomic.Value(u32).init(0);
    var create_errors = lib.atomic.Value(u32).init(0);
    var threads: [3]Thread = undefined;
    threads[0] = try Thread.spawn(.{}, struct {
        fn run(mgr: *Manager, remote_pk: noise.Key, shared_gate: *StartGate, hits: *lib.atomic.Value(u32)) void {
            shared_gate.wait();
            var round: usize = 0;
            while (round < 200) : (round += 1) {
                _ = mgr.withSessionByPublicKeyLocked(remote_pk, hits, struct {
                    fn call(counter: *lib.atomic.Value(u32), _: *Noise.Session) void {
                        _ = counter.fetchAdd(1, .seq_cst);
                    }
                }.call);
            }
        }
    }.run, .{ &concurrent_manager, pk_a, &gate, &callback_hits });
    threads[1] = try Thread.spawn(.{}, struct {
        fn run(mgr: *Manager, remote_pk: noise.Key, shared_gate: *StartGate, missing: *lib.atomic.Value(u32)) void {
            shared_gate.wait();
            var round: usize = 0;
            while (round < 200) : (round += 1) {
                if (mgr.getByPublicKey(remote_pk) == null) {
                    _ = missing.fetchAdd(1, .seq_cst);
                }
            }
        }
    }.run, .{ &concurrent_manager, pk_a, &gate, &null_reads });
    threads[2] = try Thread.spawn(.{}, struct {
        fn run(
            mgr: *Manager,
            remote_pk: noise.Key,
            shared_gate: *StartGate,
            send_key_: noise.Key,
            recv_key_: noise.Key,
            err_count: *lib.atomic.Value(u32),
        ) void {
            shared_gate.wait();
            var round: usize = 0;
            while (round < 50) : (round += 1) {
                const session = mgr.getByPublicKey(remote_pk) orelse continue;
                _ = mgr.removeByIndex(session.localIndex());
                _ = mgr.createSession(remote_pk, send_key_, recv_key_, @as(u32, @intCast(100 + round))) catch {
                    _ = err_count.fetchAdd(1, .seq_cst);
                };
            }
        }
    }.run, .{ &concurrent_manager, pk_a, &gate, send_a, recv_a, &create_errors });
    for (threads) |thread| thread.join();
    try testing.expect(callback_hits.load(.seq_cst) > 0);
    try testing.expect(concurrent_manager.count() <= 1);
    try testing.expect(null_reads.load(.seq_cst) <= 200);
    try testing.expectEqual(@as(u32, 0), create_errors.load(.seq_cst));

    try testing.expect(manager.removeByPublicKey(pk_a));
    try testing.expectEqual(@as(usize, 1), manager.count());
    try testing.expect(manager.removeByIndex(99));
    try testing.expectEqual(@as(usize, 0), manager.count());
}
