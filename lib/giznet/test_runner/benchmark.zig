const glib = @import("glib");
const testing_api = glib.testing;

pub fn make(comptime grt: type) testing_api.TestRunner {
    return @import("integration.zig").make(grt);
}
