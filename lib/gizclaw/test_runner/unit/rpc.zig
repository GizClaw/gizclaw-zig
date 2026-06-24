const glib = @import("glib");
const giznet = @import("giznet");
const gizclaw = @import("../../../gizclaw.zig");
const models = @import("../../models.zig");

pub fn make(comptime grt: type) glib.testing.TestRunner {
    return glib.testing.TestRunner.fromFn(grt.std, 1024 * 1024, struct {
        fn run(_: *glib.testing.T, allocator: grt.std.mem.Allocator) !void {
            try rpcTypes(grt);
            try rpcGeneratedResourceTypes(grt, allocator);
            try rpcRequestEscapesStrings(grt, allocator);
            try rpcFrameProtocol(grt, allocator);
            try peerStreamProtocols(grt, allocator);
        }

        fn rpcTypes(comptime any_grt: type) !void {
            const testing = any_grt.std.testing;
            const req: models.PingRequest = .{ .client_send_time = 123 };
            const resp: models.PingResponse = .{ .server_time = 456 };
            const speed_req: models.SpeedTestRequest = .{ .up_content_length = 1024, .down_content_length = 2048 };
            const speed_resp: models.SpeedTestResponse = .{ .up_content_length = 1024, .down_content_length = 2048 };
            const rpc_error: models.RPCError = .{ .code = 1, .message = "boom" };

            try testing.expectEqual(@as(i64, 123), req.client_send_time);
            try testing.expectEqual(@as(i64, 456), resp.server_time);
            try testing.expectEqual(@as(i64, 1024), speed_req.up_content_length);
            try testing.expectEqual(@as(i64, 2048), speed_req.down_content_length);
            try testing.expectEqual(@as(i64, 1024), speed_resp.up_content_length);
            try testing.expectEqual(@as(i64, 2048), speed_resp.down_content_length);
            try testing.expectEqual(@as(i64, 1), rpc_error.code);
            try testing.expectEqualStrings("boom", rpc_error.message);
            try testing.expectEqualStrings("all.ping", models.RpcMethods.all_ping);
            try testing.expectEqualStrings("all.speed_test.run", models.RpcMethods.all_speed_test_run);
            try testing.expectEqualStrings("client.info.get", models.RpcMethods.client_info_get);
            try testing.expectEqualStrings("client.identifiers.get", models.RpcMethods.client_identifiers_get);
            try testing.expectEqualStrings("client.info.get", gizclaw.Rpc.method_client_info_get);
            try testing.expectEqualStrings("client.identifiers.get", gizclaw.Rpc.method_client_identifiers_get);
            try testing.expectEqualStrings("device.info.get", models.RpcMethods.device_info_get);
            try testing.expectEqualStrings("device.identifiers.get", models.RpcMethods.device_identifiers_get);
            try testing.expectEqualStrings("peer.info.get", models.RpcMethods.peer_info_get);
            try testing.expectEqualStrings("peer.info.put", models.RpcMethods.peer_info_put);
            try testing.expectEqualStrings("peer.runtime.get", models.RpcMethods.peer_runtime_get);
            try testing.expectEqualStrings("server.info.get", models.RpcMethods.server_info_get);
            try testing.expectEqualStrings("server.info.put", models.RpcMethods.server_info_put);
            try testing.expectEqualStrings("server.runtime.get", models.RpcMethods.server_runtime_get);
            try testing.expectEqualStrings("server.status.get", models.RpcMethods.server_status_get);
            try testing.expectEqualStrings("server.status.put", models.RpcMethods.server_status_put);
            try testing.expectEqualStrings("server.run.agent.get", models.RpcMethods.server_run_agent_get);
            try testing.expectEqualStrings("server.run.agent.set", models.RpcMethods.server_run_agent_set);
            try testing.expectEqualStrings("server.run.reload", models.RpcMethods.server_run_reload);
            try testing.expectEqualStrings("server.run.status", models.RpcMethods.server_run_status);
            try testing.expectEqualStrings("server.run.stop", models.RpcMethods.server_run_stop);
            try testing.expectEqualStrings("server.run.say", models.RpcMethods.server_run_say);
            try testing.expectEqualStrings("server.workspace.list", models.RpcMethods.server_workspace_list);
            try testing.expectEqualStrings("server.workspace.get", models.RpcMethods.server_workspace_get);
            try testing.expectEqualStrings("server.workspace.create", models.RpcMethods.server_workspace_create);
            try testing.expectEqualStrings("server.workspace.put", models.RpcMethods.server_workspace_put);
            try testing.expectEqualStrings("server.workflow.list", models.RpcMethods.server_workflow_list);
            try testing.expectEqualStrings("server.workflow.get", models.RpcMethods.server_workflow_get);
            try testing.expectEqualStrings("server.workflow.create", models.RpcMethods.server_workflow_create);
            try testing.expectEqualStrings("server.workflow.put", models.RpcMethods.server_workflow_put);
            try testing.expectEqualStrings("server.model.list", models.RpcMethods.server_model_list);
            try testing.expectEqualStrings("server.model.get", models.RpcMethods.server_model_get);
            try testing.expectEqualStrings("server.model.create", models.RpcMethods.server_model_create);
            try testing.expectEqualStrings("server.model.put", models.RpcMethods.server_model_put);
            try testing.expectEqualStrings("server.model.delete", models.RpcMethods.server_model_delete);
            try testing.expectEqualStrings("server.credential.list", models.RpcMethods.server_credential_list);
            try testing.expectEqualStrings("server.credential.get", models.RpcMethods.server_credential_get);
            try testing.expectEqualStrings("server.credential.create", models.RpcMethods.server_credential_create);
            try testing.expectEqualStrings("server.credential.put", models.RpcMethods.server_credential_put);
            try testing.expectEqualStrings("server.credential.delete", models.RpcMethods.server_credential_delete);
            try testing.expectEqualStrings("server.firmware.list", models.RpcMethods.server_firmware_list);
            try testing.expectEqualStrings("server.firmware.get", models.RpcMethods.server_firmware_get);
            try testing.expectEqualStrings("server.firmware.download", models.RpcMethods.server_firmware_download);
            try testing.expectEqualStrings("server.friend.invite_token.get", models.RpcMethods.server_friend_invite_token_get);
            try testing.expectEqualStrings("server.friend.invite_token.create", models.RpcMethods.server_friend_invite_token_create);
            try testing.expectEqualStrings("server.friend.invite_token.clear", models.RpcMethods.server_friend_invite_token_clear);
            try testing.expectEqualStrings("server.friend.add", models.RpcMethods.server_friend_add);
            try testing.expectEqualStrings("server.friend_group.invite_token.get", models.RpcMethods.server_friend_group_invite_token_get);
            try testing.expectEqualStrings("server.friend_group.invite_token.create", models.RpcMethods.server_friend_group_invite_token_create);
            try testing.expectEqualStrings("server.friend_group.invite_token.clear", models.RpcMethods.server_friend_group_invite_token_clear);
            try testing.expectEqualStrings("server.friend_group.join", models.RpcMethods.server_friend_group_join);
            try testing.expectEqualStrings("server.friend_group.messages.send", models.RpcMethods.server_friend_group_messages_send);
            try testing.expectEqualStrings("server.model.create", gizclaw.Rpc.method_server_model_create);
            try testing.expectEqualStrings("server.model.put", gizclaw.Rpc.method_server_model_put);
            try testing.expectEqualStrings("server.model.delete", gizclaw.Rpc.method_server_model_delete);
            try testing.expectEqualStrings("server.credential.create", gizclaw.Rpc.method_server_credential_create);
            try testing.expectEqualStrings("server.credential.put", gizclaw.Rpc.method_server_credential_put);
            try testing.expectEqualStrings("server.credential.delete", gizclaw.Rpc.method_server_credential_delete);
            try testing.expectEqualStrings("server.friend.invite_token.create", gizclaw.Rpc.method_server_friend_invite_token_create);
            try testing.expectEqualStrings("server.friend.add", gizclaw.Rpc.method_server_friend_add);
            try testing.expectEqualStrings("server.friend_group.join", gizclaw.Rpc.method_server_friend_group_join);
            _ = models.RPCRequest;
            _ = models.RPCResponse;
        }

        fn rpcGeneratedResourceTypes(comptime any_grt: type, allocator: any_grt.std.mem.Allocator) !void {
            const testing = any_grt.std.testing;

            const list_request = try models.toJson(allocator, models.ModelListRequest{ .limit = 1 });
            defer allocator.free(list_request);
            try testing.expectEqualStrings("{\"limit\":1}", list_request);

            var page = try models.fromJson(
                models.ModelListResponse,
                allocator,
                "{\"items\":[],\"has_next\":false}",
            );
            defer page.deinit();
            try testing.expectEqual(@as(usize, 0), page.value.items.len);
            try testing.expect(!page.value.has_next);

            const model_create = try models.toJson(allocator, models.ModelCreateRequest{
                .id = "zig-e2e-model",
                .kind = "e2e",
                .source = "zig",
                .name = "Zig E2E Model",
            });
            defer allocator.free(model_create);
            try testing.expectEqualStrings("{\"id\":\"zig-e2e-model\",\"kind\":\"e2e\",\"source\":\"zig\",\"name\":\"Zig E2E Model\"}", model_create);

            var model_put = try models.fromJson(
                models.ModelPutRequest,
                allocator,
                "{\"id\":\"zig-e2e-model\",\"body\":{\"id\":\"zig-e2e-model\",\"kind\":\"e2e\",\"source\":\"zig\"}}",
            );
            defer model_put.deinit();
            try testing.expectEqualStrings("zig-e2e-model", model_put.value.id);
            try testing.expectEqualStrings("zig-e2e-model", model_put.value.body.id);

            var credential_create = try models.fromJson(
                models.CredentialCreateRequest,
                allocator,
                "{\"name\":\"zig-e2e-credential\",\"provider\":\"e2e\",\"body\":{}}",
            );
            defer credential_create.deinit();
            try testing.expectEqualStrings("zig-e2e-credential", credential_create.value.name);
            try testing.expectEqualStrings("e2e", credential_create.value.provider);

            const friend_add = try models.toJson(allocator, models.FriendAddRequest{ .invite_token = "friend-token" });
            defer allocator.free(friend_add);
            try testing.expectEqualStrings("{\"invite_token\":\"friend-token\"}", friend_add);

            var friend_token = try models.fromJson(
                models.FriendInviteTokenCreateResponse,
                allocator,
                "{\"invite_token\":\"friend-token\",\"expires_at\":\"2026-06-24T12:00:00Z\"}",
            );
            defer friend_token.deinit();
            try testing.expectEqualStrings("friend-token", friend_token.value.invite_token);

            const group_token_request = try models.toJson(
                allocator,
                models.FriendGroupInviteTokenCreateRequest{ .friend_group_id = "group-1" },
            );
            defer allocator.free(group_token_request);
            try testing.expectEqualStrings("{\"friend_group_id\":\"group-1\"}", group_token_request);

            const group_join = try models.toJson(allocator, models.FriendGroupJoinRequest{ .invite_token = "group-token" });
            defer allocator.free(group_join);
            try testing.expectEqualStrings("{\"invite_token\":\"group-token\"}", group_join);

            const say = try models.toJson(allocator, models.ServerRunSayRequest{ .text = "hello" });
            defer allocator.free(say);
            try testing.expectEqualStrings("{\"text\":\"hello\"}", say);

            const client_info = try models.toJson(allocator, models.ClientGetInfoResponse{
                .name = "zig-client",
                .manufacturer = "GizClaw",
                .model = "devkit",
                .hardware_revision = "r1",
            });
            defer allocator.free(client_info);
            try testing.expectEqualStrings(
                "{\"name\":\"zig-client\",\"manufacturer\":\"GizClaw\",\"model\":\"devkit\",\"hardware_revision\":\"r1\"}",
                client_info,
            );

            var client_identifiers = try models.fromJson(
                models.ClientGetIdentifiersResponse,
                allocator,
                "{\"sn\":\"sn-1\",\"imeis\":[{\"tac\":\"12345678\",\"serial\":\"123456\"}],\"labels\":[{\"key\":\"slot\",\"value\":\"main\"}]}",
            );
            defer client_identifiers.deinit();
            try testing.expectEqualStrings("sn-1", client_identifiers.value.sn.?);
            try testing.expectEqualStrings("12345678", client_identifiers.value.imeis.?[0].tac);
            try testing.expectEqualStrings("main", client_identifiers.value.labels.?[0].value);

            const audio_message = try models.toJson(allocator, models.FriendGroupMessageSendRequest{
                .friend_group_id = "fg_1",
                .audio_base64 = "T2dnUw==",
                .audio_content_type = "audio/opus",
            });
            defer allocator.free(audio_message);
            try testing.expectEqualStrings(
                "{\"friend_group_id\":\"fg_1\",\"audio_base64\":\"T2dnUw==\",\"audio_content_type\":\"audio/opus\"}",
                audio_message,
            );

            var audio_response = try models.fromJson(
                models.FriendGroupMessageSendResponse,
                allocator,
                "{\"id\":\"msg_1\",\"friend_group_id\":\"fg_1\",\"sender_peer_id\":\"peer_1\",\"audio_path\":\"friend-groups/fg_1/msg_1.ogg\",\"audio_content_type\":\"audio/opus\",\"audio_size_bytes\":16,\"ttl_seconds\":60,\"expires_at\":\"2026-06-17T00:01:00Z\",\"created_at\":\"2026-06-17T00:00:00Z\"}",
            );
            defer audio_response.deinit();
            try testing.expectEqualStrings("msg_1", audio_response.value.id.?);
            try testing.expectEqualStrings("fg_1", audio_response.value.friend_group_id.?);
            try testing.expectEqualStrings("friend-groups/fg_1/msg_1.ogg", audio_response.value.audio_path.?);
            try testing.expectEqualStrings("audio/opus", audio_response.value.audio_content_type.?);
            try testing.expectEqual(@as(i64, 16), audio_response.value.audio_size_bytes.?);
            try testing.expectEqual(@as(i64, 60), audio_response.value.ttl_seconds.?);
        }

        fn rpcRequestEscapesStrings(comptime any_grt: type, allocator: any_grt.std.mem.Allocator) !void {
            const testing = any_grt.std.testing;
            const rpc = gizclaw.Rpc.make(any_grt);

            const request = try rpc.buildRequest(allocator, "quote\"id", gizclaw.Rpc.method_ping, "{}");
            defer allocator.free(request);

            try testing.expectEqualStrings(
                "{\"v\":1,\"id\":\"quote\\\"id\",\"method\":\"all.ping\",\"params\":{}}",
                request,
            );
        }

        fn rpcFrameProtocol(comptime any_grt: type, allocator: any_grt.std.mem.Allocator) !void {
            const testing = any_grt.std.testing;
            const rpc = gizclaw.Rpc.make(any_grt);

            const MemoryStream = struct {
                input: []const u8,
                read_offset: usize = 0,
                output: []u8,
                output_len: usize = 0,
                closed: bool = false,
                deinited: bool = false,

                fn written(self: *@This()) []const u8 {
                    return self.output[0..self.output_len];
                }

                pub fn read(self: *@This(), buf: []u8) !usize {
                    if (self.read_offset >= self.input.len) return 0;
                    const n = @min(buf.len, self.input.len - self.read_offset);
                    @memcpy(buf[0..n], self.input[self.read_offset..][0..n]);
                    self.read_offset += n;
                    return n;
                }

                pub fn setReadDeadline(_: *@This(), _: glib.time.instant.Time) !void {}

                pub fn write(self: *@This(), payload: []const u8) !usize {
                    if (self.output_len + payload.len > self.output.len) return error.NoSpaceLeft;
                    @memcpy(self.output[self.output_len..][0..payload.len], payload);
                    self.output_len += payload.len;
                    return payload.len;
                }

                pub fn setWriteDeadline(_: *@This(), _: glib.time.instant.Time) !void {}

                pub fn close(self: *@This()) !void {
                    self.closed = true;
                }

                pub fn deinit(self: *@This()) void {
                    self.deinited = true;
                }
            };

            const Helper = struct {
                fn stream(impl: *MemoryStream) giznet.Stream {
                    return giznet.Stream.init(impl, 0, 0);
                }

                fn appendFrame(
                    buf: []u8,
                    len: *usize,
                    frame_type: gizclaw.Rpc.FrameType,
                    payload: []const u8,
                ) void {
                    any_grt.std.mem.writeInt(u16, buf[len.*..][0..2], @intCast(payload.len), .little);
                    any_grt.std.mem.writeInt(u16, buf[len.* + 2 ..][0..2], @intFromEnum(frame_type), .little);
                    len.* += 4;
                    @memcpy(buf[len.*..][0..payload.len], payload);
                    len.* += payload.len;
                }
            };

            {
                var out_buf: [16]u8 = undefined;
                var impl = MemoryStream{ .input = "", .output = &out_buf };
                try rpc.writeJsonFrame(allocator, Helper.stream(&impl), "{}");
                try testing.expectEqualSlices(u8, &[_]u8{ 2, 0, 1, 0, '{', '}' }, impl.written());
            }

            {
                var out_buf: [16]u8 = undefined;
                var impl = MemoryStream{ .input = "", .output = &out_buf };
                try rpc.writeEOS(allocator, Helper.stream(&impl));
                try testing.expectEqualSlices(u8, &[_]u8{ 0, 0, 0, 0 }, impl.written());
            }

            {
                const input = [_]u8{ 2, 0, 1, 0, '{', '}' };
                var out_buf: [1]u8 = undefined;
                var impl = MemoryStream{ .input = &input, .output = &out_buf };
                var frame = try rpc.readFrame(allocator, Helper.stream(&impl));
                defer frame.deinit(allocator);
                try testing.expectEqual(gizclaw.Rpc.FrameType.json, frame.type);
                try testing.expectEqualStrings("{}", frame.payload);
            }

            {
                const input = [_]u8{ 0, 0, 0, 0 };
                var out_buf: [1]u8 = undefined;
                var impl = MemoryStream{ .input = &input, .output = &out_buf };
                try rpc.readEOS(allocator, Helper.stream(&impl));
            }

            {
                const input = [_]u8{ 0, 0, 99, 0 };
                var out_buf: [1]u8 = undefined;
                var impl = MemoryStream{ .input = &input, .output = &out_buf };
                try testing.expectError(error.UnknownRpcFrameType, rpc.readFrame(allocator, Helper.stream(&impl)));
            }

            {
                const input = [_]u8{ 1, 0, 0, 0, 'x' };
                var out_buf: [1]u8 = undefined;
                var impl = MemoryStream{ .input = &input, .output = &out_buf };
                try testing.expectError(error.RpcEOSFrameMustBeEmpty, rpc.readFrame(allocator, Helper.stream(&impl)));
            }

            {
                const payload = try allocator.alloc(u8, gizclaw.Rpc.max_frame_size + 1);
                defer allocator.free(payload);
                var out_buf: [16]u8 = undefined;
                var impl = MemoryStream{ .input = "", .output = &out_buf };
                try testing.expectError(error.RpcFrameTooLarge, rpc.writeFrame(allocator, Helper.stream(&impl), .binary, payload));
            }

            {
                const input = [_]u8{ 2, 0, 2, 0, '{', '}' };
                var out_buf: [1]u8 = undefined;
                var impl = MemoryStream{ .input = &input, .output = &out_buf };
                try testing.expectError(error.ExpectedRpcJsonFrame, rpc.readJsonFrame(allocator, Helper.stream(&impl)));
            }

            {
                const input = [_]u8{ 2, 0, 1, 0, '{', '}' };
                var out_buf: [1]u8 = undefined;
                var impl = MemoryStream{ .input = &input, .output = &out_buf };
                try testing.expectError(error.ExpectedRpcBinaryFrame, rpc.readBinaryFrames(allocator, Helper.stream(&impl)));
            }

            {
                const input = [_]u8{ 2, 0, 1, 0, '{', '}' };
                var out_buf: [1]u8 = undefined;
                var impl = MemoryStream{ .input = &input, .output = &out_buf };
                try testing.expectError(error.ExpectedRpcEOSFrame, rpc.readEOS(allocator, Helper.stream(&impl)));
            }

            {
                const input = [_]u8{ 2, 0, 1 };
                var out_buf: [1]u8 = undefined;
                var impl = MemoryStream{ .input = &input, .output = &out_buf };
                try testing.expectError(error.TruncatedRpcStream, rpc.readFrame(allocator, Helper.stream(&impl)));
            }

            {
                const input = [_]u8{ 2, 0, 1, 0, '{' };
                var out_buf: [1]u8 = undefined;
                var impl = MemoryStream{ .input = &input, .output = &out_buf };
                try testing.expectError(error.TruncatedRpcStream, rpc.readFrame(allocator, Helper.stream(&impl)));
            }

            {
                const response_json = "{\"v\":1,\"id\":\"req\",\"result\":{\"server_time\":456}}";
                var input_buf: [128]u8 = undefined;
                var input_len: usize = 0;
                Helper.appendFrame(&input_buf, &input_len, .json, response_json);
                Helper.appendFrame(&input_buf, &input_len, .eos, "");

                var out_buf: [256]u8 = undefined;
                var impl = MemoryStream{ .input = input_buf[0..input_len], .output = &out_buf };
                var client = rpc.Rpc.init(allocator, Helper.stream(&impl));
                const response = try client.call("req", gizclaw.Rpc.method_ping, "{\"client_send_time\":1}");
                defer allocator.free(response);
                try testing.expectEqualStrings(response_json, response);

                const request = try rpc.buildRequest(allocator, "req", gizclaw.Rpc.method_ping, "{\"client_send_time\":1}");
                defer allocator.free(request);
                var expected: [256]u8 = undefined;
                var expected_len: usize = 0;
                Helper.appendFrame(&expected, &expected_len, .json, request);
                Helper.appendFrame(&expected, &expected_len, .eos, "");
                try testing.expectEqualSlices(u8, expected[0..expected_len], impl.written());

                try client.close();
                client.deinit();
                try testing.expect(impl.closed);
                try testing.expect(impl.deinited);
            }

            {
                var out_buf: [128]u8 = undefined;
                var impl = MemoryStream{ .input = "", .output = &out_buf };
                try testing.expectEqual(@as(i64, 5), try rpc.writeBinaryFrames(allocator, Helper.stream(&impl), 5));
                try testing.expectEqualSlices(
                    u8,
                    &[_]u8{ 5, 0, 2, 0, 0, 1, 2, 3, 4, 0, 0, 0, 0 },
                    impl.written(),
                );
            }

            {
                var input_buf: [128]u8 = undefined;
                var input_len: usize = 0;
                Helper.appendFrame(&input_buf, &input_len, .binary, &[_]u8{ 0, 1, 2 });
                Helper.appendFrame(&input_buf, &input_len, .binary, &[_]u8{ 3, 4 });
                Helper.appendFrame(&input_buf, &input_len, .eos, "");

                var out_buf: [1]u8 = undefined;
                var impl = MemoryStream{ .input = input_buf[0..input_len], .output = &out_buf };
                try testing.expectEqual(@as(i64, 5), try rpc.readBinaryFrames(allocator, Helper.stream(&impl)));
            }
        }

        fn peerStreamProtocols(comptime any_grt: type, allocator: any_grt.std.mem.Allocator) !void {
            const testing = any_grt.std.testing;
            const peer_stream = gizclaw.peer_stream.make(any_grt);

            try testing.expectEqual(@as(u64, 0x20), gizclaw.service.event);
            try testing.expectEqual(@as(u8, 0x10), gizclaw.service.protocol_stamped_opus);

            const opus_packet = try peer_stream.packStampedOpus(allocator, .{
                .timestamp = 0x01020304050607,
                .frame = &.{ 0xf8, 0x01 },
            });
            defer allocator.free(opus_packet);
            try testing.expectEqualSlices(u8, &.{ 1, 1, 2, 3, 4, 5, 6, 7, 0xf8, 0x01 }, opus_packet);
            const unpacked = try peer_stream.unpackStampedOpus(opus_packet);
            try testing.expectEqual(@as(u64, 0x01020304050607), unpacked.timestamp);
            try testing.expectEqualSlices(u8, &.{ 0xf8, 0x01 }, unpacked.frame);

            const MemoryConn = struct {
                output: []u8,
                output_len: usize = 0,
                write_protocol: ?u8 = null,
                closed: bool = false,
                deinited: bool = false,

                fn written(self: *@This()) []const u8 {
                    return self.output[0..self.output_len];
                }

                pub fn read(_: *@This(), _: []u8) !giznet.Conn.ReadResult {
                    return error.Timeout;
                }

                pub fn readTimeout(_: *@This(), _: []u8, _: glib.time.duration.Duration) !giznet.Conn.ReadResult {
                    return error.Timeout;
                }

                pub fn write(self: *@This(), protocol: u8, payload: []const u8) !usize {
                    if (self.output_len + payload.len > self.output.len) return error.NoSpaceLeft;
                    self.write_protocol = protocol;
                    @memcpy(self.output[self.output_len..][0..payload.len], payload);
                    self.output_len += payload.len;
                    return payload.len;
                }

                pub fn openStream(_: *@This(), _: u64) !giznet.Stream {
                    return error.Unsupported;
                }

                pub fn accept(_: *@This(), _: ?glib.time.duration.Duration) !giznet.Stream {
                    return error.Unsupported;
                }

                pub fn close(self: *@This()) !void {
                    self.closed = true;
                }

                pub fn deinit(self: *@This()) void {
                    self.deinited = true;
                }

                pub fn localStatic(_: *@This()) giznet.Key {
                    return .{};
                }

                pub fn remoteStatic(_: *@This()) giznet.Key {
                    return .{};
                }
            };

            {
                var conn_out: [32]u8 = undefined;
                var conn_impl = MemoryConn{ .output = &conn_out };
                const conn = giznet.Conn.init(&conn_impl);
                try peer_stream.writeStampedOpus(allocator, conn, .{
                    .timestamp = 0x01020304050607,
                    .frame = &.{ 0xf8, 0x01 },
                });
                try testing.expectEqual(@as(?u8, gizclaw.service.protocol_stamped_opus), conn_impl.write_protocol);
                try testing.expectEqualSlices(u8, &.{ 1, 1, 2, 3, 4, 5, 6, 7, 0xf8, 0x01 }, conn_impl.written());
            }

            const MemoryStream = struct {
                input: []const u8 = "",
                read_offset: usize = 0,
                output: []u8,
                output_len: usize = 0,
                closed: bool = false,
                deinited: bool = false,

                fn written(self: *@This()) []const u8 {
                    return self.output[0..self.output_len];
                }

                pub fn read(self: *@This(), buf: []u8) !usize {
                    if (self.read_offset >= self.input.len) return 0;
                    const n = @min(buf.len, self.input.len - self.read_offset);
                    @memcpy(buf[0..n], self.input[self.read_offset..][0..n]);
                    self.read_offset += n;
                    return n;
                }

                pub fn setReadDeadline(_: *@This(), _: glib.time.instant.Time) !void {}

                pub fn write(self: *@This(), payload: []const u8) !usize {
                    if (self.output_len + payload.len > self.output.len) return error.NoSpaceLeft;
                    @memcpy(self.output[self.output_len..][0..payload.len], payload);
                    self.output_len += payload.len;
                    return payload.len;
                }

                pub fn setWriteDeadline(_: *@This(), _: glib.time.instant.Time) !void {}

                pub fn close(self: *@This()) !void {
                    self.closed = true;
                }

                pub fn deinit(self: *@This()) void {
                    self.deinited = true;
                }
            };

            var out_buf: [256]u8 = undefined;
            var writer_impl = MemoryStream{ .output = &out_buf };
            const writer_stream = giznet.Stream.init(&writer_impl, gizclaw.service.event, 1);
            try peer_stream.writePeerStreamEvent(allocator, writer_stream, .{
                .v = 0,
                .type = .text_delta,
                .kind = .text,
                .stream_id = "chat",
                .label = "user",
                .timestamp = 123,
                .text = "hello",
            });
            const want_payload = "{\"v\":1,\"type\":\"text.delta\",\"kind\":\"text\",\"stream_id\":\"chat\",\"label\":\"user\",\"timestamp\":123,\"text\":\"hello\"}";
            const generated_event = try models.toJson(allocator, models.PeerStreamEvent{
                .v = 1,
                .type = "text.delta",
                .kind = "text",
                .stream_id = "chat",
                .label = "user",
                .timestamp = 123,
                .text = "hello",
            });
            defer allocator.free(generated_event);

            var generated_parsed = try models.fromJson(models.PeerStreamEvent, allocator, want_payload);
            defer generated_parsed.deinit();
            try testing.expectEqual(@as(i64, 1), generated_parsed.value.v);
            try testing.expectEqualStrings("text.delta", generated_parsed.value.type);
            try testing.expectEqualStrings("text", generated_parsed.value.kind.?);
            try testing.expectEqualStrings("chat", generated_parsed.value.stream_id.?);
            try testing.expectEqualStrings("user", generated_parsed.value.label.?);
            try testing.expectEqual(@as(i64, 123), generated_parsed.value.timestamp.?);
            try testing.expectEqualStrings("hello", generated_parsed.value.text.?);

            var generated_roundtrip = try models.fromJson(models.PeerStreamEvent, allocator, generated_event);
            defer generated_roundtrip.deinit();
            try testing.expectEqual(@as(i64, 1), generated_roundtrip.value.v);
            try testing.expectEqualStrings("text.delta", generated_roundtrip.value.type);
            try testing.expectEqualStrings("text", generated_roundtrip.value.kind.?);
            try testing.expectEqualStrings("chat", generated_roundtrip.value.stream_id.?);
            try testing.expectEqualStrings("user", generated_roundtrip.value.label.?);
            try testing.expectEqual(@as(i64, 123), generated_roundtrip.value.timestamp.?);
            try testing.expectEqualStrings("hello", generated_roundtrip.value.text.?);

            var want_frame: [256]u8 = undefined;
            any_grt.std.mem.writeInt(u16, want_frame[0..2], @intCast(want_payload.len), .little);
            any_grt.std.mem.writeInt(u16, want_frame[2..4], @intFromEnum(gizclaw.Rpc.FrameType.json), .little);
            @memcpy(want_frame[4..][0..want_payload.len], want_payload);
            try testing.expectEqualSlices(u8, want_frame[0 .. 4 + want_payload.len], writer_impl.written());

            var in_buf: [256]u8 = undefined;
            any_grt.std.mem.writeInt(u16, in_buf[0..2], @intCast(want_payload.len), .little);
            any_grt.std.mem.writeInt(u16, in_buf[2..4], @intFromEnum(gizclaw.Rpc.FrameType.json), .little);
            @memcpy(in_buf[4..][0..want_payload.len], want_payload);
            var reader_impl = MemoryStream{
                .input = in_buf[0 .. 4 + want_payload.len],
                .output = &out_buf,
            };
            const reader_stream = giznet.Stream.init(&reader_impl, gizclaw.service.event, 2);
            var parsed = try peer_stream.readPeerStreamEvent(allocator, reader_stream);
            defer parsed.deinit();
            try testing.expectEqual(gizclaw.peer_stream.PeerStreamEventType.text_delta, parsed.value.type);
            try testing.expectEqual(gizclaw.peer_stream.PeerStreamKind.text, parsed.value.kind.?);
            try testing.expectEqualStrings("chat", parsed.value.stream_id.?);
            try testing.expectEqualStrings("hello", parsed.value.text.?);
            try testing.expectEqual(@as(i64, 123), parsed.value.timestamp.?);

            const history_payload = "{\"v\":1,\"type\":\"workspace.history.updated\",\"label\":\"workspace.history.updated\",\"timestamp\":456,\"last_updated_at\":\"2026-06-22T12:00:00Z\"}";
            var history_buf: [256]u8 = undefined;
            any_grt.std.mem.writeInt(u16, history_buf[0..2], @intCast(history_payload.len), .little);
            any_grt.std.mem.writeInt(u16, history_buf[2..4], @intFromEnum(gizclaw.Rpc.FrameType.json), .little);
            @memcpy(history_buf[4..][0..history_payload.len], history_payload);
            var history_impl = MemoryStream{
                .input = history_buf[0 .. 4 + history_payload.len],
                .output = &out_buf,
            };
            const history_stream = giznet.Stream.init(&history_impl, gizclaw.service.event, 6);
            var history = try peer_stream.readPeerStreamEvent(allocator, history_stream);
            defer history.deinit();
            try testing.expectEqual(gizclaw.peer_stream.PeerStreamEventType.workspace_history_updated, history.value.type);
            try testing.expectEqualStrings("workspace.history.updated", history.value.label.?);
            try testing.expectEqual(@as(i64, 456), history.value.timestamp.?);
            try testing.expectEqualStrings("2026-06-22T12:00:00Z", history.value.last_updated_at.?);

            {
                var chunk_impl = MemoryStream{
                    .input = in_buf[0 .. 4 + want_payload.len],
                    .output = &out_buf,
                };
                var combined = peer_stream.PeerStream{
                    .event_stream = .{
                        .allocator = allocator,
                        .stream = giznet.Stream.init(&chunk_impl, gizclaw.service.event, 5),
                    },
                    .subscriber = undefined,
                };
                defer combined.deinit();
                var chunk_result = try combined.readChunk(&out_buf);
                defer chunk_result.deinit();
                const chunk = chunk_result.chunk();
                switch (chunk) {
                    .event => |event| {
                        try testing.expectEqual(gizclaw.peer_stream.PeerStreamEventType.text_delta, event.type);
                        try testing.expectEqualStrings("hello", event.text.?);
                    },
                    .stamped_opus => return error.ExpectedPeerStreamEventChunk,
                }
            }

            {
                var close_out: [1]u8 = undefined;
                var close_impl = MemoryStream{ .output = &close_out };
                var event_stream = peer_stream.PeerEventStream{
                    .allocator = allocator,
                    .stream = giznet.Stream.init(&close_impl, gizclaw.service.event, 7),
                };
                event_stream.close();
                try testing.expect(close_impl.closed);
                event_stream.deinit();
                try testing.expect(close_impl.deinited);
            }

            {
                const eos_frame = [_]u8{ 0, 0, 0, 0 };
                var empty_event_out: [1]u8 = undefined;
                var empty_event_impl = MemoryStream{
                    .input = &eos_frame,
                    .output = &empty_event_out,
                };
                var audio_timeout_out: [1]u8 = undefined;
                var audio_timeout_impl = MemoryConn{ .output = &audio_timeout_out };
                var combined = peer_stream.PeerStream{
                    .event_stream = .{
                        .allocator = allocator,
                        .stream = giznet.Stream.init(&empty_event_impl, gizclaw.service.event, 8),
                    },
                    .subscriber = .{
                        .conn = giznet.Conn.init(&audio_timeout_impl),
                        .read_timeout = glib.time.duration.MilliSecond,
                    },
                };
                defer combined.deinit();
                try testing.expectError(error.Timeout, combined.readChunk(&out_buf));
            }

            {
                var audio_out: [256]u8 = undefined;
                var audio_impl = MemoryStream{ .output = &audio_out };
                const audio_stream = giznet.Stream.init(&audio_impl, gizclaw.service.event, 3);
                try peer_stream.writePeerAudioBegin(allocator, audio_stream, .{
                    .stream_id = "audio",
                    .label = "workspacetest",
                    .timestamp = 456,
                });
                const want_audio_begin = "{\"v\":1,\"type\":\"bos\",\"kind\":\"audio\",\"stream_id\":\"audio\",\"label\":\"workspacetest\",\"timestamp\":456}";
                var want_audio_frame: [256]u8 = undefined;
                any_grt.std.mem.writeInt(u16, want_audio_frame[0..2], @intCast(want_audio_begin.len), .little);
                any_grt.std.mem.writeInt(u16, want_audio_frame[2..4], @intFromEnum(gizclaw.Rpc.FrameType.json), .little);
                @memcpy(want_audio_frame[4..][0..want_audio_begin.len], want_audio_begin);
                try testing.expectEqualSlices(u8, want_audio_frame[0 .. 4 + want_audio_begin.len], audio_impl.written());
            }

            {
                var audio_out: [256]u8 = undefined;
                var audio_impl = MemoryStream{ .output = &audio_out };
                const audio_stream = giznet.Stream.init(&audio_impl, gizclaw.service.event, 4);
                try peer_stream.writePeerAudioEnd(allocator, audio_stream, .{
                    .stream_id = "audio",
                    .label = "workspacetest",
                    .timestamp = 789,
                    .@"error" = "done",
                });
                const want_audio_end = "{\"v\":1,\"type\":\"eos\",\"kind\":\"audio\",\"stream_id\":\"audio\",\"label\":\"workspacetest\",\"timestamp\":789,\"error\":\"done\"}";
                var want_audio_frame: [256]u8 = undefined;
                any_grt.std.mem.writeInt(u16, want_audio_frame[0..2], @intCast(want_audio_end.len), .little);
                any_grt.std.mem.writeInt(u16, want_audio_frame[2..4], @intFromEnum(gizclaw.Rpc.FrameType.json), .little);
                @memcpy(want_audio_frame[4..][0..want_audio_end.len], want_audio_end);
                try testing.expectEqualSlices(u8, want_audio_frame[0 .. 4 + want_audio_end.len], audio_impl.written());
            }
        }
    }.run);
}
