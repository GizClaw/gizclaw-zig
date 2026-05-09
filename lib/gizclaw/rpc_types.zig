const openapi = @import("openapi");
const codegen = @import("codegen");
const options = @import("gizclaw_rpc_types_options");

fn files() openapi.Files {
    return .{
        .items = &.{
            .{ .name = "./rpc/ping.json", .spec = openapi.json.parse(options.ping_json) },
            .{ .name = "./rpc/gear_config.json", .spec = openapi.json.parse(options.gear_config_json) },
            .{ .name = "./rpc/gear_info.json", .spec = openapi.json.parse(options.gear_info_json) },
            .{ .name = "./rpc/gear_ota.json", .spec = openapi.json.parse(options.gear_ota_json) },
            .{ .name = "./rpc/gear_registration.json", .spec = openapi.json.parse(options.gear_registration_json) },
            .{ .name = "./rpc/gear_runtime.json", .spec = openapi.json.parse(options.gear_runtime_json) },
            .{ .name = "../type/configuration.json", .spec = openapi.json.parse(options.type_configuration_json) },
            .{ .name = "../type/device_info.json", .spec = openapi.json.parse(options.type_device_info_json) },
            .{ .name = "../type/ota_summary.json", .spec = openapi.json.parse(options.type_ota_summary_json) },
            .{ .name = "../type/registration.json", .spec = openapi.json.parse(options.type_registration_json) },
            .{ .name = "../type/gear.json", .spec = openapi.json.parse(options.type_gear_json) },
            .{ .name = "../type/runtime.json", .spec = openapi.json.parse(options.type_runtime_json) },
            .{ .name = "../type/gear_certification.json", .spec = openapi.json.parse(options.type_gear_certification_json) },
            .{ .name = "../type/firmware_config.json", .spec = openapi.json.parse(options.type_firmware_config_json) },
            .{ .name = "../type/hardware_info.json", .spec = openapi.json.parse(options.type_hardware_info_json) },
            .{ .name = "../type/depot_file.json", .spec = openapi.json.parse(options.type_depot_file_json) },
            .{ .name = "../type/gear_role.json", .spec = openapi.json.parse(options.type_gear_role_json) },
            .{ .name = "../type/gear_status.json", .spec = openapi.json.parse(options.type_gear_status_json) },
            .{ .name = "../type/gear_certification_type.json", .spec = openapi.json.parse(options.type_gear_certification_type_json) },
            .{ .name = "../type/gear_certification_authority.json", .spec = openapi.json.parse(options.type_gear_certification_authority_json) },
            .{ .name = "../type/gear_firmware_channel.json", .spec = openapi.json.parse(options.type_gear_firmware_channel_json) },
            .{ .name = "../type/gear_imei.json", .spec = openapi.json.parse(options.type_gear_imei_json) },
            .{ .name = "../type/gear_label.json", .spec = openapi.json.parse(options.type_gear_label_json) },
        },
    };
}

const Models = codegen.models.make(files());

pub const Configuration = Models.Configuration;
pub const DepotFile = Models.DepotFile;
pub const DeviceInfo = Models.DeviceInfo;
pub const FirmwareConfig = Models.FirmwareConfig;
pub const Gear = Models.Gear;
pub const GearCertification = Models.GearCertification;
pub const GearCertificationAuthority = Models.GearCertificationAuthority;
pub const GearCertificationType = Models.GearCertificationType;
pub const GearFirmwareChannel = Models.GearFirmwareChannel;
pub const GearGetConfigRequest = Models.GearGetConfigRequest;
pub const GearGetConfigResponse = Models.GearGetConfigResponse;
pub const GearGetInfoRequest = Models.GearGetInfoRequest;
pub const GearGetInfoResponse = Models.GearGetInfoResponse;
pub const GearGetOTARequest = Models.GearGetOTARequest;
pub const GearGetOTAResponse = Models.GearGetOTAResponse;
pub const GearGetRegistrationRequest = Models.GearGetRegistrationRequest;
pub const GearGetRegistrationResponse = Models.GearGetRegistrationResponse;
pub const GearGetRuntimeRequest = Models.GearGetRuntimeRequest;
pub const GearGetRuntimeResponse = Models.GearGetRuntimeResponse;
pub const GearIMEI = Models.GearIMEI;
pub const GearLabel = Models.GearLabel;
pub const GearPutInfoRequest = Models.GearPutInfoRequest;
pub const GearPutInfoResponse = Models.GearPutInfoResponse;
pub const GearRegisterRequest = Models.GearRegisterRequest;
pub const GearRegisterResponse = Models.GearRegisterResponse;
pub const GearRole = Models.GearRole;
pub const GearStatus = Models.GearStatus;
pub const HardwareInfo = Models.HardwareInfo;
pub const OTASummary = Models.OTASummary;
pub const PingRequest = Models.PingRequest;
pub const PingResponse = Models.PingResponse;
pub const Registration = Models.Registration;
pub const Runtime = Models.Runtime;

pub const RPCVersion = i64;
pub const RPCMethod = []const u8;
pub const RPCErrorCode = i64;
pub const RPCError = struct {
    code: RPCErrorCode,
    message: []const u8,
};
pub const RPCRequest = struct {
    v: RPCVersion,
    id: []const u8,
    method: RPCMethod,
};
pub const RPCResponse = struct {
    v: RPCVersion,
    id: []const u8,
    @"error": ?RPCError = null,
};
