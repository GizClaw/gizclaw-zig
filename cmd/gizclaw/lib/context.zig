const std = @import("std");
const giznet = @import("giznet");
const gizclaw = @import("gizclaw");
const gstd = @import("gstd");

const key = gizclaw.make(gstd.runtime).key;

pub const Config = struct {
    server: ServerConfig,
};

pub const ServerConfig = struct {
    address: []const u8,
    public_key: giznet.Key,
};

pub const Context = struct {
    allocator: std.mem.Allocator,
    name: []u8,
    dir: []u8,
    config: Config,
    key_pair: giznet.KeyPair,

    pub fn deinit(self: *Context) void {
        self.allocator.free(self.name);
        self.allocator.free(self.dir);
        self.allocator.free(self.config.server.address);
        self.* = undefined;
    }
};

pub const Info = struct {
    name: []const u8,
    current: bool,
    server_address: []const u8,
    server_public_key: giznet.Key,
    identity_public: giznet.Key,
};

pub const Store = struct {
    allocator: std.mem.Allocator,
    root: []u8,

    pub fn default(allocator: std.mem.Allocator) !Store {
        return .{
            .allocator = allocator,
            .root = try defaultRoot(allocator),
        };
    }

    pub fn deinit(self: *Store) void {
        self.allocator.free(self.root);
        self.* = undefined;
    }

    pub fn create(self: Store, name: []const u8, server_addr: []const u8, server_pub_key: []const u8) !void {
        try validateName(name);
        const server_key = key.parse(server_pub_key) catch return error.InvalidServerPublicKey;
        const dir = try std.fs.path.join(self.allocator, &.{ self.root, name });
        defer self.allocator.free(dir);

        if (exists(dir)) return error.ContextAlreadyExists;
        try std.fs.cwd().makePath(dir);

        const pair = key.randomKeyPair();
        const identity_path = try std.fs.path.join(self.allocator, &.{ dir, "identity.key" });
        defer self.allocator.free(identity_path);
        try std.fs.cwd().writeFile(.{
            .sub_path = identity_path,
            .data = &pair.private.bytes,
        });

        var server_key_buf: [52]u8 = undefined;
        const config_path = try std.fs.path.join(self.allocator, &.{ dir, "config.yaml" });
        defer self.allocator.free(config_path);
        const config_data = try std.fmt.allocPrint(
            self.allocator,
            "server:\n  address: {s}\n  public-key: {s}\n",
            .{ server_addr, key.format(server_key, &server_key_buf) },
        );
        defer self.allocator.free(config_data);
        try std.fs.cwd().writeFile(.{
            .sub_path = config_path,
            .data = config_data,
        });

        try self.ensureCurrent(name);
    }

    pub fn use(self: Store, name: []const u8) !void {
        try validateName(name);
        const dir = try std.fs.path.join(self.allocator, &.{ self.root, name });
        defer self.allocator.free(dir);
        if (!exists(dir)) return error.ContextDoesNotExist;
        try self.replaceCurrent(name);
    }

    pub fn current(self: Store) !?Context {
        const link = try std.fs.path.join(self.allocator, &.{ self.root, "current" });
        defer self.allocator.free(link);

        var target_buf: [std.fs.max_path_bytes]u8 = undefined;
        const target = std.fs.cwd().readLink(link, &target_buf) catch |err| switch (err) {
            error.FileNotFound => return null,
            else => return err,
        };
        const dir = if (std.fs.path.isAbsolute(target))
            try self.allocator.dupe(u8, target)
        else
            try std.fs.path.join(self.allocator, &.{ self.root, target });
        defer self.allocator.free(dir);
        return try load(self.allocator, dir);
    }

    pub fn loadByName(self: Store, name: []const u8) !Context {
        try validateName(name);
        const dir = try std.fs.path.join(self.allocator, &.{ self.root, name });
        defer self.allocator.free(dir);
        if (!exists(dir)) return error.ContextDoesNotExist;
        return try load(self.allocator, dir);
    }

    pub fn list(self: Store) !ListResult {
        var names: std.ArrayList([]u8) = .{};
        errdefer {
            for (names.items) |name| self.allocator.free(name);
            names.deinit(self.allocator);
        }

        var current_name: ?[]u8 = null;
        errdefer if (current_name) |name| self.allocator.free(name);

        var root_dir = std.fs.cwd().openDir(self.root, .{ .iterate = true }) catch |err| switch (err) {
            error.FileNotFound => return .{
                .allocator = self.allocator,
                .names = try self.allocator.alloc([]u8, 0),
            },
            else => return err,
        };
        defer root_dir.close();

        var target_buf: [std.fs.max_path_bytes]u8 = undefined;
        if (root_dir.readLink("current", &target_buf)) |target| {
            current_name = try self.allocator.dupe(u8, std.fs.path.basename(target));
        } else |_| {}

        var iter = root_dir.iterate();
        while (try iter.next()) |entry| {
            if (std.mem.eql(u8, entry.name, "current")) continue;
            if (entry.kind != .directory) continue;
            try names.append(self.allocator, try self.allocator.dupe(u8, entry.name));
        }
        std.mem.sort([]u8, names.items, {}, lessThanString);

        return .{
            .allocator = self.allocator,
            .names = try names.toOwnedSlice(self.allocator),
            .current = current_name,
        };
    }

    fn ensureCurrent(self: Store, name: []const u8) !void {
        const link = try std.fs.path.join(self.allocator, &.{ self.root, "current" });
        defer self.allocator.free(link);
        if (existsAny(link)) return;
        try std.fs.cwd().symLink(name, link, .{});
    }

    fn replaceCurrent(self: Store, name: []const u8) !void {
        const link = try std.fs.path.join(self.allocator, &.{ self.root, "current" });
        defer self.allocator.free(link);
        std.fs.cwd().deleteFile(link) catch |err| switch (err) {
            error.FileNotFound => {},
            else => return err,
        };
        try std.fs.cwd().symLink(name, link, .{});
    }
};

pub const ListResult = struct {
    allocator: std.mem.Allocator,
    names: [][]u8,
    current: ?[]u8 = null,

    pub fn deinit(self: *ListResult) void {
        for (self.names) |name| self.allocator.free(name);
        self.allocator.free(self.names);
        if (self.current) |name| self.allocator.free(name);
        self.* = undefined;
    }
};

pub fn load(allocator: std.mem.Allocator, dir: []const u8) !Context {
    const config_path = try std.fs.path.join(allocator, &.{ dir, "config.yaml" });
    defer allocator.free(config_path);
    const data = try std.fs.cwd().readFileAlloc(allocator, config_path, 64 * 1024);
    defer allocator.free(data);
    const config = try parseConfig(allocator, data);
    errdefer allocator.free(config.server.address);

    const identity_path = try std.fs.path.join(allocator, &.{ dir, "identity.key" });
    defer allocator.free(identity_path);
    const identity = try std.fs.cwd().readFileAlloc(allocator, identity_path, 32);
    defer allocator.free(identity);
    if (identity.len != 32) return error.InvalidIdentityKey;

    var private: giznet.Key = .{};
    @memcpy(&private.bytes, identity);
    const pair = try key.fromPrivate(private);

    return .{
        .allocator = allocator,
        .name = try allocator.dupe(u8, std.fs.path.basename(dir)),
        .dir = try allocator.dupe(u8, dir),
        .config = config,
        .key_pair = pair,
    };
}

pub fn info(ctx: *const Context, current_name: []const u8) Info {
    return .{
        .name = ctx.name,
        .current = std.mem.eql(u8, ctx.name, current_name),
        .server_address = ctx.config.server.address,
        .server_public_key = ctx.config.server.public_key,
        .identity_public = ctx.key_pair.public,
    };
}

fn parseConfig(allocator: std.mem.Allocator, data: []const u8) !Config {
    var address: ?[]u8 = null;
    errdefer if (address) |value| allocator.free(value);
    var public_key: ?giznet.Key = null;

    var lines = std.mem.splitScalar(u8, data, '\n');
    while (lines.next()) |line| {
        const trimmed = std.mem.trim(u8, line, " \t\r");
        if (std.mem.startsWith(u8, trimmed, "address:")) {
            const raw = std.mem.trim(u8, trimmed["address:".len..], " \t\"'");
            address = try allocator.dupe(u8, raw);
        } else if (std.mem.startsWith(u8, trimmed, "public-key:")) {
            const raw = std.mem.trim(u8, trimmed["public-key:".len..], " \t\"'");
            public_key = key.parse(raw) catch return error.InvalidServerPublicKey;
        }
    }

    return .{
        .server = .{
            .address = address orelse return error.MissingServerAddress,
            .public_key = public_key orelse return error.MissingServerPublicKey,
        },
    };
}

fn defaultRoot(allocator: std.mem.Allocator) ![]u8 {
    if (@import("builtin").os.tag == .windows) {
        return try std.fs.getAppDataDir(allocator, "gizclaw");
    }
    if (std.process.getEnvVarOwned(allocator, "XDG_CONFIG_HOME")) |xdg| {
        defer allocator.free(xdg);
        return try std.fs.path.join(allocator, &.{ xdg, "gizclaw" });
    } else |_| {}
    const home = try std.process.getEnvVarOwned(allocator, "HOME");
    defer allocator.free(home);
    return try std.fs.path.join(allocator, &.{ home, ".config", "gizclaw" });
}

fn validateName(name: []const u8) !void {
    if (name.len == 0 or
        std.mem.eql(u8, name, ".") or
        std.mem.eql(u8, name, "..") or
        std.mem.indexOfAny(u8, name, "/\\") != null)
    {
        return error.InvalidContextName;
    }
}

fn exists(path: []const u8) bool {
    const stat = std.fs.cwd().statFile(path) catch return false;
    return stat.kind == .directory;
}

fn existsAny(path: []const u8) bool {
    _ = std.fs.cwd().statFile(path) catch return false;
    return true;
}

fn lessThanString(_: void, lhs: []u8, rhs: []u8) bool {
    return std.mem.lessThan(u8, lhs, rhs);
}
