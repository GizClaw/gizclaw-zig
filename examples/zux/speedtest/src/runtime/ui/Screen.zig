const glib = @import("glib");
const lvgl = @import("lvgl");

pub fn make(comptime grt: type, comptime ZuxAppType: type) type {
    _ = grt;
    const Stores = ZuxAppType.Store.Stores;
    const WifiStaState = @FieldType(Stores, "wifi").StateType;
    const SmokeStatus = @FieldType(Stores, "smoke_status").StateType;

    return struct {
        const Screen = @This();
        const selector_main = lvgl.binding.LV_PART_MAIN;

        line1: lvgl.Label,
        line2: lvgl.Label,
        line3: lvgl.Label,
        line4: lvgl.Label,
        line5: lvgl.Label,
        line6: lvgl.Label,
        line7: lvgl.Label,
        line8: lvgl.Label,
        line9: lvgl.Label,
        line1_text: [40:0]u8 = [_:0]u8{0} ** 40,
        line2_text: [40:0]u8 = [_:0]u8{0} ** 40,
        line3_text: [56:0]u8 = [_:0]u8{0} ** 56,
        line4_text: [64:0]u8 = [_:0]u8{0} ** 64,
        line5_text: [40:0]u8 = [_:0]u8{0} ** 40,
        line6_text: [64:0]u8 = [_:0]u8{0} ** 64,
        line7_text: [64:0]u8 = [_:0]u8{0} ** 64,
        line8_text: [64:0]u8 = [_:0]u8{0} ** 64,
        line9_text: [64:0]u8 = [_:0]u8{0} ** 64,

        pub fn init(display: lvgl.Display) !Screen {
            var screen = display.activeScreen();
            screen.clean();
            screen.removeStyleAll();
            screen.setStyleBgColor(lvgl.Color.fromHex(0x101820), selector_main);
            screen.setStyleBgOpa(lvgl.opa.cover, selector_main);

            return .{
                .line1 = try createLine(&screen, 8),
                .line2 = try createLine(&screen, 32),
                .line3 = try createLine(&screen, 56),
                .line4 = try createLine(&screen, 80),
                .line5 = try createLine(&screen, 104),
                .line6 = try createLine(&screen, 128),
                .line7 = try createLine(&screen, 152),
                .line8 = try createLine(&screen, 176),
                .line9 = try createLine(&screen, 200),
            };
        }

        pub fn setState(self: *Screen, wifi: WifiStaState, status: SmokeStatus) void {
            if (wifi.last_rssi) |rssi| {
                self.setLabelText(&self.line1_text, self.line1, "wifi signal: {d}dBm", .{rssi});
            } else {
                self.setLabelText(&self.line1_text, self.line1, "wifi signal: --", .{});
            }
            self.setLabelText(
                &self.line2_text,
                self.line2,
                "CPU0/CPU1: {d}%/{d}%",
                .{ status.cpu0_percent, status.cpu1_percent },
            );
            self.setLabelText(
                &self.line3_text,
                self.line3,
                "mem i/p: {d}/{d}KiB",
                .{ status.mem_internal_free_kib, status.mem_psram_free_kib },
            );
            self.setLabelText(
                &self.line4_text,
                self.line4,
                "tot down/up: {d}/{d}KiB",
                .{ @divTrunc(status.down_bytes, 1024), @divTrunc(status.up_bytes, 1024) },
            );
            self.setLabelText(&self.line5_text, self.line5, "test round: {d}", .{status.round});
            self.setLabelText(&self.line6_text, self.line6, "ping rtt: {d}ms", .{status.ping_rtt_ms});
            self.setLabelText(
                &self.line7_text,
                self.line7,
                "up speed: {d}.{d:0>3}Mbps",
                .{
                    @divTrunc(status.up_mbps_milli, 1000),
                    @mod(status.up_mbps_milli, 1000),
                },
            );
            self.setLabelText(
                &self.line8_text,
                self.line8,
                "down speed: {d}.{d:0>3}Mbps",
                .{
                    @divTrunc(status.down_mbps_milli, 1000),
                    @mod(status.down_mbps_milli, 1000),
                },
            );
            self.setLabelText(
                &self.line9_text,
                self.line9,
                "duplex d/u: {d}.{d:0>3}/{d}.{d:0>3}Mbps",
                .{
                    @divTrunc(status.duplex_down_mbps_milli, 1000),
                    @mod(status.duplex_down_mbps_milli, 1000),
                    @divTrunc(status.duplex_up_mbps_milli, 1000),
                    @mod(status.duplex_up_mbps_milli, 1000),
                },
            );
        }

        fn createLine(parent: *const lvgl.Obj, y: i32) !lvgl.Label {
            var label = lvgl.Label.create(parent) orelse return error.OutOfMemory;
            label.setTextStatic("");
            var obj = label.asObj();
            obj.alignTo(.top_left, 10, y);
            obj.setStyleTextColor(lvgl.Color.white(), selector_main);
            return label;
        }

        fn setLabelText(self: *Screen, buffer: anytype, label: lvgl.Label, comptime fmt: []const u8, args: anytype) void {
            _ = self;
            const text = glib.std.fmt.bufPrintZ(buffer, fmt, args) catch buffer[0..0 :0];
            label.setText(text);
        }
    };
}
