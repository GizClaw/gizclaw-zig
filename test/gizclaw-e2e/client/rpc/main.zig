const TestRunner = @import("TestRunner.zig");
const cli = @import("cli.zig");

pub fn main() !void {
    try cli.main(TestRunner);
}
