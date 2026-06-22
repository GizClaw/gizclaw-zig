const giznet = @import("giznet");
const glib = @import("glib");
const models = @import("models.zig");

pub const max_frame_size: usize = 65535;
pub const speed_test_frame_size: usize = 32 * 1024;
pub const speed_test_log_interval: i64 = 256 * 1024;
pub const speed_test_trace_enabled = false;
pub const speed_test_trace_interval: glib.time.duration.Duration = glib.time.duration.Second;
pub const speed_test_trace_stack_size: usize = 8 * 1024;
pub const speed_test_upload_stack_size: usize = 64 * 1024;
pub const max_speed_test_content_length: i64 = 1 << 30;
pub const method_ping = models.RpcMethods.all_ping;
pub const method_speed_test_run = models.RpcMethods.all_speed_test_run;
pub const method_client_info_get = models.RpcMethods.client_info_get;
pub const method_client_identifiers_get = models.RpcMethods.client_identifiers_get;
pub const method_device_info_get = models.RpcMethods.device_info_get;
pub const method_device_identifiers_get = models.RpcMethods.device_identifiers_get;
pub const method_peer_info_get = models.RpcMethods.peer_info_get;
pub const method_peer_info_put = models.RpcMethods.peer_info_put;
pub const method_peer_runtime_get = models.RpcMethods.peer_runtime_get;
pub const method_server_info_get = models.RpcMethods.server_info_get;
pub const method_server_info_put = models.RpcMethods.server_info_put;
pub const method_server_runtime_get = models.RpcMethods.server_runtime_get;
pub const method_server_status_get = models.RpcMethods.server_status_get;
pub const method_server_status_put = models.RpcMethods.server_status_put;
pub const method_server_run_agent_get = models.RpcMethods.server_run_agent_get;
pub const method_server_run_agent_set = models.RpcMethods.server_run_agent_set;
pub const method_server_run_workspace_get = models.RpcMethods.server_run_workspace_get;
pub const method_server_run_workspace_set = models.RpcMethods.server_run_workspace_set;
pub const method_server_run_workspace_reload = models.RpcMethods.server_run_workspace_reload;
pub const method_server_run_workspace_history = models.RpcMethods.server_run_workspace_history;
pub const method_server_run_workspace_history_play = models.RpcMethods.server_run_workspace_history_play;
pub const method_server_run_workspace_memory_stats = models.RpcMethods.server_run_workspace_memory_stats;
pub const method_server_run_workspace_recall = models.RpcMethods.server_run_workspace_recall;
pub const method_server_run_reload = models.RpcMethods.server_run_reload;
pub const method_server_run_status = models.RpcMethods.server_run_status;
pub const method_server_run_stop = models.RpcMethods.server_run_stop;
pub const method_server_run_say = models.RpcMethods.server_run_say;
pub const method_server_firmware_list = models.RpcMethods.server_firmware_list;
pub const method_server_firmware_get = models.RpcMethods.server_firmware_get;
pub const method_server_firmware_download = models.RpcMethods.server_firmware_download;
pub const method_server_workspace_list = models.RpcMethods.server_workspace_list;
pub const method_server_workspace_get = models.RpcMethods.server_workspace_get;
pub const method_server_workspace_create = models.RpcMethods.server_workspace_create;
pub const method_server_workspace_put = models.RpcMethods.server_workspace_put;
pub const method_server_workspace_delete = models.RpcMethods.server_workspace_delete;
pub const method_server_workspace_history_list = models.RpcMethods.server_workspace_history_list;
pub const method_server_workspace_history_get = models.RpcMethods.server_workspace_history_get;
pub const method_server_workspace_history_audio_get = models.RpcMethods.server_workspace_history_audio_get;
pub const method_server_workflow_list = models.RpcMethods.server_workflow_list;
pub const method_server_workflow_get = models.RpcMethods.server_workflow_get;
pub const method_server_workflow_create = models.RpcMethods.server_workflow_create;
pub const method_server_workflow_put = models.RpcMethods.server_workflow_put;
pub const method_server_workflow_delete = models.RpcMethods.server_workflow_delete;
pub const method_server_model_list = models.RpcMethods.server_model_list;
pub const method_server_model_get = models.RpcMethods.server_model_get;
pub const method_server_credential_list = models.RpcMethods.server_credential_list;
pub const method_server_credential_get = models.RpcMethods.server_credential_get;
pub const method_server_contact_list = models.RpcMethods.server_contact_list;
pub const method_server_contact_get = models.RpcMethods.server_contact_get;
pub const method_server_contact_create = models.RpcMethods.server_contact_create;
pub const method_server_contact_put = models.RpcMethods.server_contact_put;
pub const method_server_contact_delete = models.RpcMethods.server_contact_delete;
pub const method_server_friend_requests_list = models.RpcMethods.server_friend_requests_list;
pub const method_server_friend_requests_create = models.RpcMethods.server_friend_requests_create;
pub const method_server_friend_requests_accept = models.RpcMethods.server_friend_requests_accept;
pub const method_server_friend_requests_reject = models.RpcMethods.server_friend_requests_reject;
pub const method_server_friend_list = models.RpcMethods.server_friend_list;
pub const method_server_friend_delete = models.RpcMethods.server_friend_delete;
pub const method_server_friend_group_list = models.RpcMethods.server_friend_group_list;
pub const method_server_friend_group_get = models.RpcMethods.server_friend_group_get;
pub const method_server_friend_group_create = models.RpcMethods.server_friend_group_create;
pub const method_server_friend_group_put = models.RpcMethods.server_friend_group_put;
pub const method_server_friend_group_delete = models.RpcMethods.server_friend_group_delete;
pub const method_server_friend_group_members_list = models.RpcMethods.server_friend_group_members_list;
pub const method_server_friend_group_members_add = models.RpcMethods.server_friend_group_members_add;
pub const method_server_friend_group_members_put = models.RpcMethods.server_friend_group_members_put;
pub const method_server_friend_group_members_delete = models.RpcMethods.server_friend_group_members_delete;
pub const method_server_friend_group_messages_list = models.RpcMethods.server_friend_group_messages_list;
pub const method_server_friend_group_messages_get = models.RpcMethods.server_friend_group_messages_get;
pub const method_server_friend_group_messages_send = models.RpcMethods.server_friend_group_messages_send;

pub const FrameType = enum(u16) {
    eos = 0,
    json = 1,
    binary = 2,
    text = 3,
};

pub fn make(comptime grt: type) type {
    const Allocator = grt.std.mem.Allocator;
    const log = grt.std.log.scoped(.gizclaw_rpc);

    return struct {
        const Package = @This();

        pub const Frame = struct {
            type: FrameType,
            payload: []u8,

            pub fn deinit(self: *Frame, allocator: Allocator) void {
                allocator.free(self.payload);
                self.* = undefined;
            }
        };

        pub const Rpc = struct {
            allocator: Allocator,
            stream: giznet.Stream,
            closed: bool = false,

            pub fn init(allocator: Allocator, stream: giznet.Stream) Rpc {
                return .{
                    .allocator = allocator,
                    .stream = stream,
                };
            }

            pub fn close(self: *Rpc) !void {
                if (self.closed) return;
                self.closed = true;
                try self.stream.close();
            }

            pub fn deinit(self: *Rpc) void {
                self.close() catch {};
                self.stream.deinit();
                self.* = undefined;
            }

            pub fn ping(self: *Rpc, id: []const u8) !models.PingResponse {
                const params = try grt.std.fmt.allocPrint(
                    self.allocator,
                    "{{\"client_send_time\":{d}}}",
                    .{grt.time.now().unixMilli()},
                );
                defer self.allocator.free(params);
                const response_data = try self.call(id, method_ping, params);
                defer self.allocator.free(response_data);

                const Response = struct {
                    v: i64,
                    id: []const u8,
                    result: ?models.PingResponse = null,
                    @"error": ?models.RPCError = null,
                };
                const parsed = try grt.std.json.parseFromSlice(Response, self.allocator, response_data, .{ .ignore_unknown_fields = true });
                defer parsed.deinit();
                _ = parsed.value.v;
                _ = parsed.value.id;
                if (parsed.value.@"error") |_| return error.RpcError;
                return parsed.value.result orelse error.MissingRpcResult;
            }

            pub fn speedTest(
                self: *Rpc,
                id: []const u8,
                request: models.SpeedTestRequest,
            ) !SpeedTestResult {
                try validateSpeedTestRequest(request);
                log.info("speed test request build id={s} up_bytes={d} down_bytes={d}", .{
                    id,
                    request.up_content_length,
                    request.down_content_length,
                });
                const params = try grt.std.fmt.allocPrint(
                    self.allocator,
                    "{{\"up_content_length\":{d},\"down_content_length\":{d}}}",
                    .{ request.up_content_length, request.down_content_length },
                );
                defer self.allocator.free(params);
                const rpc_request = try buildRequest(self.allocator, id, method_speed_test_run, params);
                defer self.allocator.free(rpc_request);

                log.info("speed test request write start bytes={d}", .{rpc_request.len});
                try self.writeJsonFrame(rpc_request);
                log.info("speed test request write done bytes={d}", .{rpc_request.len});

                log.info("speed test ack read start", .{});
                const response_data = try self.readJsonFrame();
                defer self.allocator.free(response_data);
                log.info("speed test ack read done bytes={d}", .{response_data.len});
                try self.readSpeedTestAck(response_data, request);
                log.info("speed test ack ok", .{});

                var trace = SpeedTestTrace{};
                const trace_ptr: ?*SpeedTestTrace = if (speed_test_trace_enabled) &trace else null;
                const trace_thread = if (speed_test_trace_enabled)
                    try grt.task.go("gizclaw/rpc/speed_trace", .{
                        .min_stack_size = speed_test_trace_stack_size,
                    }, glib.task.Routine.init(&trace, SpeedTestTrace.run))
                else
                    null;
                var trace_joined = false;
                defer {
                    if (trace_thread) |thread| {
                        trace.done.store(true, .release);
                        if (!trace_joined) thread.join();
                    }
                }

                const start = grt.time.instant.now();
                var upload = SpeedTestUpload{
                    .rpc = self,
                    .total = request.up_content_length,
                    .trace = trace_ptr,
                };
                log.info("speed test upload spawn start total={d} stack_size={d}", .{
                    request.up_content_length,
                    speed_test_upload_stack_size,
                });
                const upload_thread = try grt.task.go("gizclaw/rpc/speed_up", .{
                    .min_stack_size = speed_test_upload_stack_size,
                }, glib.task.Routine.init(&upload, SpeedTestUpload.run));
                log.info("speed test upload spawn done total={d}", .{request.up_content_length});
                var upload_joined = false;
                defer if (!upload_joined) upload_thread.join();

                log.info("speed test download read start expected={d}", .{request.down_content_length});
                const down_start = grt.time.instant.now();
                const down_bytes = try Package.readBinaryFramesTraced(self.allocator, self.stream, trace_ptr);
                const down_duration_ns = grt.time.instant.sub(grt.time.instant.now(), down_start);
                log.info("speed test download read done bytes={d} duration_ms={d} duration_ns={d}", .{
                    down_bytes,
                    @divTrunc(down_duration_ns, glib.time.duration.MilliSecond),
                    down_duration_ns,
                });
                if (down_bytes != request.down_content_length) return error.RpcSpeedTestLengthMismatch;
                log.info("speed test upload join start", .{});
                const upload_join_start = grt.time.instant.now();
                upload_thread.join();
                upload_joined = true;
                const upload_join_duration_ns = grt.time.instant.sub(grt.time.instant.now(), upload_join_start);
                log.info("speed test upload join done duration_ms={d} duration_ns={d}", .{
                    @divTrunc(upload_join_duration_ns, glib.time.duration.MilliSecond),
                    upload_join_duration_ns,
                });
                const up_bytes = try upload.result;
                log.info("speed test upload result bytes={d}", .{up_bytes});
                if (up_bytes != request.up_content_length) return error.RpcSpeedTestLengthMismatch;
                if (trace_thread) |thread| {
                    trace.done.store(true, .release);
                    thread.join();
                    trace_joined = true;
                }
                const duration_ns = grt.time.instant.sub(grt.time.instant.now(), start);

                return .{
                    .up_content_length = request.up_content_length,
                    .down_content_length = request.down_content_length,
                    .up_bytes = up_bytes,
                    .down_bytes = down_bytes,
                    .duration_ns = duration_ns,
                };
            }

            pub fn call(self: *Rpc, id: []const u8, method: []const u8, params_json: []const u8) ![]u8 {
                const request = try buildRequest(self.allocator, id, method, params_json);
                defer self.allocator.free(request);

                try self.writeJsonFrame(request);
                try self.writeEOS();

                const response_data = try self.readJsonFrame();
                errdefer self.allocator.free(response_data);
                try self.readEOS();
                return response_data;
            }

            pub fn writeFrame(self: *Rpc, frame_type: FrameType, payload: []const u8) !void {
                try Package.writeFrame(self.allocator, self.stream, frame_type, payload);
            }

            pub fn readFrame(self: *Rpc) !Frame {
                return try Package.readFrame(self.allocator, self.stream);
            }

            pub fn writeEOS(self: *Rpc) !void {
                try Package.writeEOS(self.allocator, self.stream);
            }

            pub fn readEOS(self: *Rpc) !void {
                try Package.readEOS(self.allocator, self.stream);
            }

            pub fn writeJsonFrame(self: *Rpc, data: []const u8) !void {
                try Package.writeJsonFrame(self.allocator, self.stream, data);
            }

            pub fn readJsonFrame(self: *Rpc) ![]u8 {
                return try Package.readJsonFrame(self.allocator, self.stream);
            }

            pub fn writeBinaryFrames(self: *Rpc, total: i64) !i64 {
                return try Package.writeBinaryFrames(self.allocator, self.stream, total);
            }

            pub fn readBinaryFrames(self: *Rpc) !i64 {
                return try Package.readBinaryFrames(self.allocator, self.stream);
            }

            pub fn readBinaryFramesExpected(self: *Rpc, total: i64) !i64 {
                return try Package.readBinaryFramesExpected(self.allocator, self.stream, total);
            }

            fn readSpeedTestAck(self: *Rpc, data: []const u8, request: models.SpeedTestRequest) !void {
                const Response = struct {
                    v: i64,
                    id: []const u8,
                    result: ?models.SpeedTestResponse = null,
                    @"error": ?models.RPCError = null,
                };
                const parsed = try grt.std.json.parseFromSlice(Response, self.allocator, data, .{ .ignore_unknown_fields = true });
                defer parsed.deinit();
                _ = parsed.value.v;
                _ = parsed.value.id;
                if (parsed.value.@"error") |_| return error.RpcError;
                const ack = parsed.value.result orelse return error.MissingRpcResult;
                log.info("speed test ack parsed up_bytes={d} down_bytes={d}", .{
                    ack.up_content_length,
                    ack.down_content_length,
                });
                if (ack.up_content_length != request.up_content_length or
                    ack.down_content_length != request.down_content_length)
                {
                    return error.RpcSpeedTestAckMismatch;
                }
            }
        };

        const SpeedTestUpload = struct {
            rpc: *Rpc,
            total: i64,
            trace: ?*SpeedTestTrace,
            result: anyerror!i64 = 0,

            fn run(self: *@This()) void {
                log.info("speed test upload thread start total={d}", .{self.total});
                const start = grt.time.instant.now();
                self.result = Package.writeBinaryFramesTraced(self.rpc.allocator, self.rpc.stream, self.total, self.trace);
                const written = self.result catch |err| {
                    const duration_ns = grt.time.instant.sub(grt.time.instant.now(), start);
                    log.warn("speed test upload thread failed err={s} duration_ms={d} duration_ns={d}", .{
                        @errorName(err),
                        @divTrunc(duration_ns, glib.time.duration.MilliSecond),
                        duration_ns,
                    });
                    return;
                };
                const duration_ns = grt.time.instant.sub(grt.time.instant.now(), start);
                log.info("speed test upload thread done bytes={d} duration_ms={d} duration_ns={d}", .{
                    written,
                    @divTrunc(duration_ns, glib.time.duration.MilliSecond),
                    duration_ns,
                });
            }
        };

        const SpeedTestTrace = struct {
            done: grt.std.atomic.Value(bool) = grt.std.atomic.Value(bool).init(false),
            upload_before_frame: grt.std.atomic.Value(u64) = grt.std.atomic.Value(u64).init(0),
            upload_after_frame: grt.std.atomic.Value(u64) = grt.std.atomic.Value(u64).init(0),
            upload_bytes: grt.std.atomic.Value(u64) = grt.std.atomic.Value(u64).init(0),
            download_before_frame: grt.std.atomic.Value(u64) = grt.std.atomic.Value(u64).init(0),
            download_after_frame: grt.std.atomic.Value(u64) = grt.std.atomic.Value(u64).init(0),
            download_bytes: grt.std.atomic.Value(u64) = grt.std.atomic.Value(u64).init(0),
            download_read_phase: grt.std.atomic.Value(u64) = grt.std.atomic.Value(u64).init(0),
            download_read_offset: grt.std.atomic.Value(u64) = grt.std.atomic.Value(u64).init(0),
            download_read_target: grt.std.atomic.Value(u64) = grt.std.atomic.Value(u64).init(0),

            fn run(self: *@This()) void {
                while (!self.done.load(.acquire)) {
                    grt.time.sleep(speed_test_trace_interval);
                    if (self.done.load(.acquire)) break;
                    self.logSnapshot();
                }
            }

            fn logSnapshot(self: *@This()) void {
                log.info(
                    "speed test heartbeat up_frames={d}/{d} up_bytes={d} down_frames={d}/{d} down_bytes={d} read_phase={s} read_offset={d}/{d}",
                    .{
                        self.upload_after_frame.load(.monotonic),
                        self.upload_before_frame.load(.monotonic),
                        self.upload_bytes.load(.monotonic),
                        self.download_after_frame.load(.monotonic),
                        self.download_before_frame.load(.monotonic),
                        self.download_bytes.load(.monotonic),
                        readPhaseName(self.download_read_phase.load(.monotonic)),
                        self.download_read_offset.load(.monotonic),
                        self.download_read_target.load(.monotonic),
                    },
                );
            }

            fn readPhaseName(phase: u64) []const u8 {
                return switch (phase) {
                    1 => "header",
                    2 => "payload",
                    else => "idle",
                };
            }
        };

        pub const SpeedTestResult = struct {
            up_content_length: i64,
            down_content_length: i64,
            up_bytes: i64,
            down_bytes: i64,
            duration_ns: i128,

            pub fn upMbps(self: SpeedTestResult) f64 {
                return mbps(self.up_bytes, self.duration_ns);
            }

            pub fn downMbps(self: SpeedTestResult) f64 {
                return mbps(self.down_bytes, self.duration_ns);
            }
        };

        pub fn buildRequest(allocator: Allocator, id: []const u8, method: []const u8, params_json: []const u8) ![]u8 {
            var out = grt.std.Io.Writer.Allocating.init(allocator);
            errdefer out.deinit();

            try out.writer.writeAll("{\"v\":1,\"id\":");
            try grt.std.json.Stringify.value(id, .{}, &out.writer);
            try out.writer.writeAll(",\"method\":");
            try grt.std.json.Stringify.value(method, .{}, &out.writer);
            try out.writer.writeAll(",\"params\":");
            try out.writer.writeAll(params_json);
            try out.writer.writeAll("}");
            return try out.toOwnedSlice();
        }

        pub fn writeFrame(allocator: Allocator, stream: giznet.Stream, frame_type: FrameType, payload: []const u8) !void {
            if (payload.len > max_frame_size) return error.RpcFrameTooLarge;
            if (frame_type == .eos and payload.len != 0) return error.RpcEOSFrameMustBeEmpty;

            const frame = try allocator.alloc(u8, 4 + payload.len);
            defer allocator.free(frame);
            grt.std.mem.writeInt(u16, frame[0..2], @intCast(payload.len), .little);
            grt.std.mem.writeInt(u16, frame[2..4], @intFromEnum(frame_type), .little);
            @memcpy(frame[4..], payload);
            try writeAll(stream, frame);
        }

        pub fn readFrame(allocator: Allocator, stream: giznet.Stream) !Frame {
            return try readFrameTraced(allocator, stream, null);
        }

        fn readFrameTraced(allocator: Allocator, stream: giznet.Stream, trace: ?*SpeedTestTrace) !Frame {
            var header: [4]u8 = undefined;
            if (trace) |t| {
                t.download_read_phase.store(1, .monotonic);
                t.download_read_offset.store(0, .monotonic);
                t.download_read_target.store(header.len, .monotonic);
            }
            try readExactTraced(stream, &header, trace);
            const length = grt.std.mem.readInt(u16, header[0..2], .little);
            const raw_type = grt.std.mem.readInt(u16, header[2..4], .little);
            const frame_type: FrameType = switch (raw_type) {
                0 => .eos,
                1 => .json,
                2 => .binary,
                3 => .text,
                else => return error.UnknownRpcFrameType,
            };
            if (frame_type == .eos and length != 0) return error.RpcEOSFrameMustBeEmpty;
            if (trace) |t| {
                t.download_read_phase.store(2, .monotonic);
                t.download_read_offset.store(0, .monotonic);
                t.download_read_target.store(length, .monotonic);
            }

            const payload = try allocator.alloc(u8, length);
            errdefer allocator.free(payload);
            try readExactTraced(stream, payload, trace);
            if (trace) |t| {
                t.download_read_phase.store(0, .monotonic);
                t.download_read_offset.store(0, .monotonic);
                t.download_read_target.store(0, .monotonic);
            }
            return .{
                .type = frame_type,
                .payload = payload,
            };
        }

        pub fn writeEOS(allocator: Allocator, stream: giznet.Stream) !void {
            try writeFrame(allocator, stream, .eos, "");
        }

        pub fn readEOS(allocator: Allocator, stream: giznet.Stream) !void {
            var frame = try readFrame(allocator, stream);
            defer frame.deinit(allocator);
            if (frame.type != .eos) return error.ExpectedRpcEOSFrame;
        }

        pub fn writeJsonFrame(allocator: Allocator, stream: giznet.Stream, data: []const u8) !void {
            try writeFrame(allocator, stream, .json, data);
        }

        pub fn readJsonFrame(allocator: Allocator, stream: giznet.Stream) ![]u8 {
            var frame = try readFrame(allocator, stream);
            if (frame.type != .json) {
                frame.deinit(allocator);
                return error.ExpectedRpcJsonFrame;
            }
            return frame.payload;
        }

        pub fn writeBinaryFrames(allocator: Allocator, stream: giznet.Stream, total: i64) !i64 {
            return try writeBinaryFramesTraced(allocator, stream, total, null);
        }

        fn writeBinaryFramesTraced(allocator: Allocator, stream: giznet.Stream, total: i64, trace: ?*SpeedTestTrace) !i64 {
            if (total < 0) return error.RpcSpeedTestLengthOutOfRange;
            var chunk: [speed_test_frame_size]u8 = undefined;
            for (&chunk, 0..) |*byte, index| byte.* = @intCast(index % 256);

            var written: i64 = 0;
            var next_log: i64 = speed_test_log_interval;
            while (written < total) {
                var size: i64 = @intCast(chunk.len);
                const remaining = total - written;
                if (remaining < size) size = remaining;
                if (written == 0) log.info("speed test upload first frame write start size={d}", .{size});
                if (trace) |t| _ = t.upload_before_frame.fetchAdd(1, .monotonic);
                try writeFrame(allocator, stream, .binary, chunk[0..@intCast(size)]);
                if (trace) |t| {
                    _ = t.upload_after_frame.fetchAdd(1, .monotonic);
                    t.upload_bytes.store(@intCast(written + size), .monotonic);
                }
                if (written == 0) log.info("speed test upload first frame write done size={d}", .{size});
                written += size;
                if (written >= next_log or written == total) {
                    log.info("speed test upload progress written={d} total={d}", .{ written, total });
                    while (next_log <= written) next_log += speed_test_log_interval;
                }
            }
            log.info("speed test upload eos write start written={d}", .{written});
            if (trace) |t| _ = t.upload_before_frame.fetchAdd(1, .monotonic);
            try writeEOS(allocator, stream);
            if (trace) |t| _ = t.upload_after_frame.fetchAdd(1, .monotonic);
            log.info("speed test upload eos write done written={d}", .{written});
            return written;
        }

        pub fn readBinaryFrames(allocator: Allocator, stream: giznet.Stream) !i64 {
            return try readBinaryFramesTraced(allocator, stream, null);
        }

        fn readBinaryFramesTraced(allocator: Allocator, stream: giznet.Stream, trace: ?*SpeedTestTrace) !i64 {
            var read: i64 = 0;
            var next_log: i64 = speed_test_log_interval;
            while (true) {
                if (trace) |t| _ = t.download_before_frame.fetchAdd(1, .monotonic);
                var frame = try readFrameTraced(allocator, stream, trace);
                if (trace) |t| _ = t.download_after_frame.fetchAdd(1, .monotonic);
                defer frame.deinit(allocator);
                if (frame.type == .eos) {
                    log.info("speed test download eos read bytes={d}", .{read});
                    return read;
                }
                if (frame.type != .binary) return error.ExpectedRpcBinaryFrame;
                read += @intCast(frame.payload.len);
                if (trace) |t| t.download_bytes.store(@intCast(read), .monotonic);
                if (read >= next_log) {
                    log.info("speed test download progress read={d}", .{read});
                    while (next_log <= read) next_log += speed_test_log_interval;
                }
            }
        }

        pub fn readBinaryFramesExpected(allocator: Allocator, stream: giznet.Stream, total: i64) !i64 {
            if (total < 0) return error.RpcSpeedTestLengthOutOfRange;
            var read: i64 = 0;
            while (read < total) {
                var frame = try readFrame(allocator, stream);
                defer frame.deinit(allocator);
                if (frame.type == .eos) return error.RpcSpeedTestLengthMismatch;
                if (frame.type != .binary) return error.ExpectedRpcBinaryFrame;
                read += @intCast(frame.payload.len);
                if (read > total) return error.RpcSpeedTestLengthMismatch;
            }
            return read;
        }

        pub fn validateSpeedTestRequest(request: models.SpeedTestRequest) !void {
            if (request.up_content_length < 0) return error.RpcSpeedTestLengthOutOfRange;
            if (request.down_content_length < 0) return error.RpcSpeedTestLengthOutOfRange;
            if (request.up_content_length > max_speed_test_content_length) return error.RpcSpeedTestLengthOutOfRange;
            if (request.down_content_length > max_speed_test_content_length) return error.RpcSpeedTestLengthOutOfRange;
        }

        fn readExact(stream: giznet.Stream, buf: []u8) !void {
            try readExactTraced(stream, buf, null);
        }

        fn readExactTraced(stream: giznet.Stream, buf: []u8, trace: ?*SpeedTestTrace) !void {
            var offset: usize = 0;
            while (offset < buf.len) {
                const n = stream.read(buf[offset..]) catch |err| switch (err) {
                    error.EndOfStream => return error.TruncatedRpcStream,
                    error.StreamClosed => return error.TruncatedRpcStream,
                    error.ConnClosed => return error.TruncatedRpcStream,
                    else => return err,
                };
                if (n == 0) return error.TruncatedRpcStream;
                offset += n;
                if (trace) |t| t.download_read_offset.store(offset, .monotonic);
            }
        }

        fn writeAll(stream: giznet.Stream, data: []const u8) !void {
            var offset: usize = 0;
            while (offset < data.len) {
                const n = try stream.write(data[offset..]);
                if (n == 0) return error.WriteZero;
                offset += n;
            }
        }

        fn mbps(bytes: i64, duration_ns: i128) f64 {
            if (bytes <= 0 or duration_ns <= 0) return 0;
            const bits: f64 = @floatFromInt(bytes * 8);
            const seconds: f64 = @as(f64, @floatFromInt(duration_ns)) / @as(f64, grt.time.duration.Second);
            return bits / seconds / 1_000_000;
        }
    };
}
