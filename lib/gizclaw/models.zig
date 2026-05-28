const glib = @import("glib");
const openapi = @import("openapi");
const codegen = @import("codegen");
const options = @import("gizclaw_models_options");

fn files() openapi.Files {
    return .{
        .items = &.{
            .{ .name = "./rpc.json", .spec = openapi.json.parse(options.rpc_json) },
            .{ .name = "./rpc/peer.json", .spec = openapi.json.parse(options.rpc_peer_json) },
            .{ .name = "./rpc/public.json", .spec = openapi.json.parse(options.rpc_public_json) },
            .{ .name = "./rpc/gear.json", .spec = openapi.json.parse(options.rpc_gear_json) },
            .{ .name = "./type/configuration.json", .spec = openapi.json.parse(options.type_configuration_json) },
            .{ .name = "./type/server_info.json", .spec = openapi.json.parse(options.type_server_info_json) },
            .{ .name = "./type/device_info.json", .spec = openapi.json.parse(options.type_device_info_json) },
            .{ .name = "./type/refresh_info.json", .spec = openapi.json.parse(options.type_refresh_info_json) },
            .{ .name = "./type/refresh_identifiers.json", .spec = openapi.json.parse(options.type_refresh_identifiers_json) },
            .{ .name = "./type/registration.json", .spec = openapi.json.parse(options.type_registration_json) },
            .{ .name = "./type/gear.json", .spec = openapi.json.parse(options.type_gear_json) },
            .{ .name = "./type/runtime.json", .spec = openapi.json.parse(options.type_runtime_json) },
            .{ .name = "./type/hardware_info.json", .spec = openapi.json.parse(options.type_hardware_info_json) },
            .{ .name = "./type/gear_role.json", .spec = openapi.json.parse(options.type_gear_role_json) },
            .{ .name = "./type/gear_status.json", .spec = openapi.json.parse(options.type_gear_status_json) },
            .{ .name = "./type/gear_imei.json", .spec = openapi.json.parse(options.type_gear_imei_json) },
            .{ .name = "./type/gear_label.json", .spec = openapi.json.parse(options.type_gear_label_json) },
        },
    };
}

const Models = codegen.models.make(glib.std, files());

pub const toJson = Models.toJson;
pub const fromJson = Models.fromJson;

pub const Configuration = Models.Configuration;
pub const DeviceGetIdentifiersRequest = Models.DeviceGetIdentifiersRequest;
pub const DeviceGetIdentifiersResponse = Models.DeviceGetIdentifiersResponse;
pub const DeviceGetInfoRequest = Models.DeviceGetInfoRequest;
pub const DeviceGetInfoResponse = Models.DeviceGetInfoResponse;
pub const DeviceInfo = Models.DeviceInfo;
pub const Gear = Models.Gear;
pub const GearIMEI = Models.GearIMEI;
pub const GearLabel = Models.GearLabel;
pub const GearRole = Models.GearRole;
pub const GearStatus = Models.GearStatus;
pub const HardwareInfo = Models.HardwareInfo;
pub const PeerGetInfoRequest = Models.PeerGetInfoRequest;
pub const PeerGetInfoResponse = Models.PeerGetInfoResponse;
pub const PeerGetRuntimeRequest = Models.PeerGetRuntimeRequest;
pub const PeerGetRuntimeResponse = Models.PeerGetRuntimeResponse;
pub const PeerPutInfoRequest = Models.PeerPutInfoRequest;
pub const PeerPutInfoResponse = Models.PeerPutInfoResponse;
pub const PingRequest = Models.PingRequest;
pub const PingResponse = Models.PingResponse;
pub const RefreshIdentifiers = Models.RefreshIdentifiers;
pub const RefreshInfo = Models.RefreshInfo;
pub const Registration = Models.Registration;
pub const RPCError = Models.RPCError;
pub const RPCErrorCode = Models.RPCErrorCode;
pub const RPCMethod = Models.RPCMethod;
pub const RPCRequest = Models.RPCRequest;
pub const RPCResponse = Models.RPCResponse;
pub const RPCVersion = Models.RPCVersion;
pub const Runtime = Models.Runtime;
pub const ServerGetInfoRequest = Models.ServerGetInfoRequest;
pub const ServerGetInfoResponse = Models.ServerGetInfoResponse;
pub const ServerInfo = Models.ServerInfo;

pub const RpcMethods = struct {
    pub const peer_ping = rpcMethod("peer.ping");
    pub const device_info_get = rpcMethod("device.info.get");
    pub const device_identifiers_get = rpcMethod("device.identifiers.get");
    pub const peer_info_get = rpcMethod("peer.info.get");
    pub const peer_info_put = rpcMethod("peer.info.put");
    pub const peer_runtime_get = rpcMethod("peer.runtime.get");
    pub const server_info_get = rpcMethod("server.info.get");
};

fn rpcMethod(comptime value: []const u8) RPCMethod {
    const schema_or_ref = files().findSchema("./rpc.json", "RPCMethod") orelse
        @compileError("RPCMethod schema not found in ./rpc.json");
    const schema = switch (schema_or_ref) {
        .schema => |schema| schema,
        .reference => @compileError("RPCMethod schema must not be a reference"),
    };

    inline for (schema.enum_values) |enum_value| {
        switch (enum_value) {
            .string => |string| if (glib.std.mem.eql(u8, string, value)) return string,
            else => {},
        }
    }

    @compileError(glib.std.fmt.comptimePrint("RPC method '{s}' is not declared by api/rpc.json", .{value}));
}
