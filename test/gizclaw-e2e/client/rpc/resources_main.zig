const Runner = @import("ResourcesRunner.zig");
const cli = @import("cli.zig");

pub fn main() !void {
    try cli.main(Runner);
}
