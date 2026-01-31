const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    //--------------------------------------------------
    // Library Tests
    const mods = .{
        .dns = b.addModule("treebeard", .{
            .root_source_file = b.path("lib/dns/root.zig"),
            .target = target,
        }),
        .client = b.addModule("treeclient", .{
            .root_source_file = b.path("lib/client/root.zig"),
            .target = target,
        }),
        .net = b.addModule("treenet", .{
            .root_source_file = b.path("lib/net/root.zig"),
            .target = target,
        }),
    };

    // Allow mods to import themselves
    mods.dns.addImport("treebeard", mods.dns);
    mods.client.addImport("treeclient", mods.client);
    mods.net.addImport("treenet", mods.net);

    //--------------------------------------------------
    // Binary Builds
    const exe = b.addExecutable(.{
        .name = "treebeard",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "treebeard", .module = mods.dns },
                .{ .name = "treeclient", .module = mods.client },
                .{ .name = "treenet", .module = mods.net },
            },
        }),
    });

    b.installArtifact(exe);

    //--------------------------------------------------
    // Binary Execution steps
    const run_step = b.step("run", "Run the app");

    const run_cmd = b.addRunArtifact(exe);
    run_step.dependOn(&run_cmd.step);

    run_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| {
        run_cmd.addArgs(args);
    }

    //--------------------------------------------------
    // Tests

    //-----------------
    // Mod tests
    const mod_dns_tests = b.addTest(.{ .root_module = mods.dns });
    const run_mod_dns_tests = b.addRunArtifact(mod_dns_tests);

    const mod_client_tests = b.addTest(.{ .root_module = mods.client });
    const run_mod_client_tests = b.addRunArtifact(mod_client_tests);

    const mod_net_tests = b.addTest(.{ .root_module = mods.net });
    const run_mod_net_tests = b.addRunArtifact(mod_net_tests);

    //-----------------
    // Binary tests
    const exe_tests = b.addTest(.{ .root_module = exe.root_module });
    const run_exe_tests = b.addRunArtifact(exe_tests);

    //-----------------
    // Run steps
    const test_step = b.step("test", "Run tests");
    test_step.dependOn(&run_mod_dns_tests.step);
    test_step.dependOn(&run_mod_client_tests.step);
    test_step.dependOn(&run_mod_net_tests.step);
    test_step.dependOn(&run_exe_tests.step);
}
