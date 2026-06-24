const consts = @import("consts.zig");

pub const Runtime = struct {
    workspace: []const u8 = "",
    workflow: []const u8 = "",
    mode: consts.Mode = .push_to_talk,
};

pub const InitConfig = struct {
    workspace: []const u8,
    workflow: []const u8,
    mode: consts.Mode,
};

pub fn init(config: InitConfig) Runtime {
    return .{
        .workspace = config.workspace,
        .workflow = config.workflow,
        .mode = config.mode,
    };
}
