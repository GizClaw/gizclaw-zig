const embed = @import("embed");
const mem = embed.std.mem;

const Cipher = @import("Cipher.zig");
const Key = @import("Key.zig");
const KeyPair = @import("KeyPair.zig");
const Message = @import("Message.zig");

pub fn make(comptime std: type, comptime cipher_kind_value: Cipher.Kind) type {
    const X25519 = std.crypto.dh.X25519;
    const CipherSuite = Cipher.make(std, cipher_kind_value);
    const protocol_name = switch (cipher_kind_value) {
        .chacha_poly => "Noise_IK_25519_ChaChaPoly_BLAKE2s",
        .aes_256_gcm => "Noise_IK_25519_AESGCM_BLAKE2s",
        .plaintext => "Noise_IK_25519_Plaintext_BLAKE2s",
    };

    return struct {
        pub const Role = enum {
            initiator,
            responder,
        };

        pub const MessageType = enum(u8) {
            init = Message.MessageTypeHandshakeInit,
            response = Message.MessageTypeHandshakeResp,
        };

        pub const init_len: usize = Message.HandshakeInitSize;
        pub const response_tag_len: usize = CipherSuite.tag_size;
        pub const response_len: usize = Message.HandshakeRespSize;

        pub const SessionMaterial = struct {
            client_to_server: Key,
            server_to_client: Key,
            response_tag: [response_tag_len]u8,
        };

        pub const InitMessage = struct {
            session_index: u32,
            ephemeral_key: Key,
            static_encrypted: [48]u8,
        };

        pub const ResponseMessage = struct {
            initiator_session_index: u32,
            responder_session_index: u32,
            ephemeral_key: Key,
            tag: [response_tag_len]u8,
        };

        const SymmetricState = struct {
            chaining_key: Key,
            hash: [Cipher.hash_size]u8,

            fn init() SymmetricState {
                var ck: [Cipher.hash_size]u8 = [_]u8{0} ** Cipher.hash_size;
                if (protocol_name.len <= Cipher.hash_size) {
                    @memcpy(ck[0..protocol_name.len], protocol_name);
                } else {
                    ck = Cipher.hash(&.{protocol_name});
                }

                return .{
                    .chaining_key = .{ .bytes = ck },
                    .hash = ck,
                };
            }

            fn mixKey(self: *SymmetricState, input: []const u8) Key {
                const next_ck, const key = Cipher.kdf2(&self.chaining_key, input);
                self.chaining_key = next_ck;
                return key;
            }

            fn mixHash(self: *SymmetricState, data: []const u8) void {
                self.hash = Cipher.hash(&.{ &self.hash, data });
            }

            fn encryptAndHash(self: *SymmetricState, key: *const Key, plaintext: []const u8, out: []u8) !usize {
                const written = CipherSuite.encryptWithAd(key, &self.hash, plaintext, out);
                self.mixHash(out[0..written]);
                return written;
            }

            fn decryptAndHash(self: *SymmetricState, key: *const Key, ciphertext: []const u8, out: []u8) !usize {
                const written = try CipherSuite.decryptWithAd(key, &self.hash, ciphertext, out);
                self.mixHash(ciphertext);
                return written;
            }

            fn split(self: SymmetricState) struct { Key, Key } {
                const keys = Cipher.hkdf(&self.chaining_key, "", 2);
                return .{ keys[0], keys[1] };
            }
        };

        role: Role,
        local_keypair: KeyPair,
        remote_key: Key = .{},
        local_session_index: u32 = 0,
        remote_session_index: u32 = 0,
        local_ephemeral: ?KeyPair = null,
        remote_ephemeral: Key = .{},
        response_tag: [response_tag_len]u8 = [_]u8{0} ** response_tag_len,
        ss: SymmetricState,
        ready: bool = false,
        finished: bool = false,

        const Self = @This();

        pub fn initInitiator(local_keypair: KeyPair, remote_key: Key, local_session_index: u32) !Self {
            var ss = SymmetricState.init();
            ss.mixHash("");
            ss.mixHash(&remote_key.bytes);

            return .{
                .role = .initiator,
                .local_keypair = local_keypair,
                .remote_key = remote_key,
                .local_session_index = local_session_index,
                .local_ephemeral = try generateKeyPair(),
                .ss = ss,
                .ready = true,
            };
        }

        pub fn writeInit(self: *Self, out: []u8) !usize {
            if (self.role != .initiator) return error.InvalidRole;
            if (!self.ready or self.finished) return error.InvalidState;

            const local_ephemeral = self.local_ephemeral orelse return error.InvalidState;
            self.ss.mixHash(&local_ephemeral.public.bytes);

            const es = try dhShared(local_ephemeral.private, self.remote_key);
            _ = self.ss.mixKey(&es);

            var static_encrypted: [48]u8 = undefined;
            const static_key = self.ss.mixKey("");
            const static_len = try self.ss.encryptAndHash(&static_key, &self.local_keypair.public.bytes, &static_encrypted);
            if (static_len != static_encrypted.len) return error.InvalidState;

            const ss_shared = try dhShared(self.local_keypair.private, self.remote_key);
            _ = self.ss.mixKey(&ss_shared);

            return Message.buildHandshakeInit(self.local_session_index, local_ephemeral.public, &static_encrypted, out);
        }

        pub fn readInit(local_keypair: KeyPair, packet: []const u8) !Self {
            const parsed = try parseInit(packet);
            var ss = SymmetricState.init();
            ss.mixHash("");
            ss.mixHash(&local_keypair.public.bytes);
            ss.mixHash(&parsed.ephemeral_key.bytes);

            const es = try dhShared(local_keypair.private, parsed.ephemeral_key);
            _ = ss.mixKey(&es);

            const static_key = ss.mixKey("");
            var remote_static_bytes: [32]u8 = undefined;
            const written = ss.decryptAndHash(&static_key, &parsed.static_encrypted, &remote_static_bytes) catch {
                return error.InvalidHandshakeMessage;
            };
            if (written != remote_static_bytes.len) return error.InvalidHandshakeMessage;
            const remote_key: Key = .{ .bytes = remote_static_bytes };

            const ss_shared = try dhShared(local_keypair.private, remote_key);
            _ = ss.mixKey(&ss_shared);

            return .{
                .role = .responder,
                .local_keypair = local_keypair,
                .remote_key = remote_key,
                .remote_session_index = parsed.session_index,
                .remote_ephemeral = parsed.ephemeral_key,
                .ss = ss,
                .ready = true,
            };
        }

        pub fn writeResponse(self: *Self, responder_session_index: u32, out: []u8) !usize {
            if (self.role != .responder) return error.InvalidRole;
            if (!self.ready or self.finished) return error.InvalidState;
            if (self.remote_session_index == 0) return error.InvalidState;

            self.local_ephemeral = try generateKeyPair();
            const local_ephemeral = self.local_ephemeral.?;

            self.ss.mixHash(&local_ephemeral.public.bytes);

            const ee = try dhShared(local_ephemeral.private, self.remote_ephemeral);
            _ = self.ss.mixKey(&ee);

            const se = try dhShared(local_ephemeral.private, self.remote_key);
            _ = self.ss.mixKey(&se);

            var encrypted_empty: [response_tag_len]u8 = undefined;
            const payload_key = self.ss.mixKey("");
            const payload_len = try self.ss.encryptAndHash(&payload_key, "", &encrypted_empty);
            if (payload_len != encrypted_empty.len) return error.InvalidState;

            self.local_session_index = responder_session_index;
            self.response_tag = encrypted_empty;
            self.finished = true;
            return Message.buildHandshakeResp(
                responder_session_index,
                self.remote_session_index,
                local_ephemeral.public,
                &encrypted_empty,
                out,
            );
        }

        pub fn readResponse(self: *Self, packet: []const u8) !void {
            if (self.role != .initiator) return error.InvalidRole;
            if (!self.ready or self.finished) return error.InvalidState;

            const parsed = try parseResponse(packet);
            if (parsed.initiator_session_index != self.local_session_index) return error.SessionIndexMismatch;

            self.remote_ephemeral = parsed.ephemeral_key;
            self.ss.mixHash(&self.remote_ephemeral.bytes);

            const local_ephemeral = self.local_ephemeral orelse return error.InvalidState;
            const ee = try dhShared(local_ephemeral.private, self.remote_ephemeral);
            _ = self.ss.mixKey(&ee);

            const se = try dhShared(self.local_keypair.private, self.remote_ephemeral);
            _ = self.ss.mixKey(&se);

            const payload_key = self.ss.mixKey("");
            var decrypted: [0]u8 = .{};
            _ = self.ss.decryptAndHash(&payload_key, &parsed.tag, decrypted[0..]) catch {
                return error.InvalidResponseTag;
            };

            self.remote_session_index = parsed.responder_session_index;
            self.response_tag = parsed.tag;
            self.finished = true;
        }

        pub fn sessionMaterial(self: *const Self) !SessionMaterial {
            if (!self.finished) return error.NotReady;
            const split = self.ss.split();
            return .{
                .client_to_server = split[0],
                .server_to_client = split[1],
                .response_tag = self.response_tag,
            };
        }

        pub fn peerKey(self: Self) Key {
            return self.remote_key;
        }

        pub fn localSessionIndex(self: Self) u32 {
            return self.local_session_index;
        }

        pub fn remoteSessionIndex(self: Self) u32 {
            return self.remote_session_index;
        }

        pub fn parseMessageType(packet: []const u8) !MessageType {
            return switch (Message.getMessageType(packet) catch return error.InvalidPacket) {
                Message.MessageTypeHandshakeInit => .init,
                Message.MessageTypeHandshakeResp => .response,
                else => error.InvalidPacket,
            };
        }

        pub fn parseInit(packet: []const u8) !InitMessage {
            const parsed = Message.parseHandshakeInit(packet) catch return error.InvalidPacket;
            return .{
                .session_index = parsed.sender_index,
                .ephemeral_key = parsed.ephemeral,
                .static_encrypted = parsed.static_encrypted,
            };
        }

        pub fn parseResponse(packet: []const u8) !ResponseMessage {
            const parsed = Message.parseHandshakeResp(packet) catch return error.InvalidPacket;
            return .{
                .initiator_session_index = parsed.receiver_index,
                .responder_session_index = parsed.sender_index,
                .ephemeral_key = parsed.ephemeral,
                .tag = parsed.empty_encrypted,
            };
        }

        fn dhShared(local_private: Key, remote_public: Key) ![32]u8 {
            const shared = X25519.scalarmult(clampPrivate(local_private.bytes), remote_public.bytes) catch {
                return error.InvalidKeyMaterial;
            };
            if (isZero(&shared)) return error.InvalidKeyMaterial;
            return shared;
        }

        fn generateKeyPair() !KeyPair {
            const generated = X25519.KeyPair.generate();
            return .{
                .public = .{ .bytes = generated.public_key },
                .private = .{ .bytes = generated.secret_key },
            };
        }

        fn clampPrivate(private_key: [32]u8) [32]u8 {
            var out = private_key;
            out[0] &= 248;
            out[31] &= 127;
            out[31] |= 64;
            return out;
        }

        fn isZero(bytes: *const [32]u8) bool {
            return mem.eql(u8, bytes, &([_]u8{0} ** 32));
        }
    };
}

pub fn testRunner(comptime lib: type) embed.testing.TestRunner {
    const testing_api = embed.testing;
    const giznet = @import("../../giznet.zig");

    const Runner = struct {
        pub fn init(self: *@This(), allocator: mem.Allocator) !void {
            _ = self;
            _ = allocator;
        }

        pub fn run(self: *@This(), t: *testing_api.T, allocator: mem.Allocator) bool {
            _ = self;
            _ = allocator;

            tryCase(lib) catch |err| {
                t.logErrorf("giznet/noise Handshake unit failed: {}", .{err});
                return false;
            };
            return true;
        }

        pub fn deinit(self: *@This(), allocator: mem.Allocator) void {
            _ = allocator;
            lib.testing.allocator.destroy(self);
        }

        fn tryCase(comptime any_lib: type) !void {
            const Handshake = make(any_lib, Cipher.default_kind);

            const initiator_pair = giznet.noise.KeyPair.seed(any_lib, 3);
            const responder_pair = giznet.noise.KeyPair.seed(any_lib, 9);

            var initiator = try Handshake.initInitiator(initiator_pair, responder_pair.public, 11);
            var init_buffer: [Handshake.init_len]u8 = undefined;
            const init_len = try initiator.writeInit(init_buffer[0..]);

            var responder = try Handshake.readInit(responder_pair, init_buffer[0..init_len]);
            var response_buffer: [Handshake.response_len]u8 = undefined;
            const response_len = try responder.writeResponse(22, response_buffer[0..]);

            try initiator.readResponse(response_buffer[0..response_len]);

            const initiator_material = try initiator.sessionMaterial();
            const responder_material = try responder.sessionMaterial();
            try any_lib.testing.expect(initiator.peerKey().eql(responder_pair.public));
            try any_lib.testing.expect(responder.peerKey().eql(initiator_pair.public));
            try any_lib.testing.expect(initiator_material.client_to_server.eql(responder_material.client_to_server));
            try any_lib.testing.expect(initiator_material.server_to_client.eql(responder_material.server_to_client));
            try any_lib.testing.expectEqualSlices(u8, &initiator_material.response_tag, &responder_material.response_tag);

            response_buffer[9] ^= 0xff;
            var bad_initiator = try Handshake.initInitiator(initiator_pair, responder_pair.public, 11);
            _ = try bad_initiator.writeInit(init_buffer[0..]);
            try any_lib.testing.expectError(
                error.InvalidResponseTag,
                bad_initiator.readResponse(response_buffer[0..response_len]),
            );

            try any_lib.testing.expectError(error.InvalidPacket, Handshake.parseMessageType(&.{}));
            try any_lib.testing.expectError(error.InvalidPacket, Handshake.parseResponse(response_buffer[0..8]));

            var wrong_index_response = response_buffer;
            lib.mem.writeInt(u32, wrong_index_response[5..9], 99, .little);
            var wrong_index_initiator = try Handshake.initInitiator(initiator_pair, responder_pair.public, 11);
            _ = try wrong_index_initiator.writeInit(init_buffer[0..]);
            try any_lib.testing.expectError(
                error.SessionIndexMismatch,
                wrong_index_initiator.readResponse(wrong_index_response[0..response_len]),
            );

            var tampered_init = init_buffer;
            tampered_init[5] ^= 0xff;
            try any_lib.testing.expectError(
                error.InvalidHandshakeMessage,
                Handshake.readInit(responder_pair, tampered_init[0..init_len]),
            );
        }
    };

    const value = lib.testing.allocator.create(Runner) catch @panic("OOM");
    value.* = .{};
    return testing_api.TestRunner.make(Runner).new(value);
}
