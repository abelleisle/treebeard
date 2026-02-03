{
  description = "A Nix-flake-based Zig development environment";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixpkgs-unstable";
    flake-parts = {
      url = "github:hercules-ci/flake-parts";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    pre-commit-hooks = {
      url = "github:cachix/pre-commit-hooks.nix";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    zig-overlay = {
      url = "github:mitchellh/zig-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    zls = {
      url = "github:zigtools/zls";
      inputs.nixpkgs.follows = "nixpkgs";
      # inputs.zig-overlay.follows = "zig-overlay";
    };
  };

  outputs =
    inputs@{ flake-parts, ... }:
    flake-parts.lib.mkFlake { inherit inputs; } {
      systems = [ "x86_64-linux" "aarch64-linux" "aarch64-darwin" ];
      perSystem = { config, self', inputs', pkgs, system, ... }:
        let
          zig = inputs.zig-overlay.packages.${system}.master;
          zls = inputs.zls.packages.${system}.zls;
        in
        {

          formatter =
            let
              config = self'.checks.pre-commit-check.config;
              inherit (config) package configFile;
              script = ''
                ${pkgs.lib.getExe package} run --all-files --config ${configFile}
              '';
            in
            pkgs.writeShellScriptBin "pre-commit-run" script;

          checks = {
            pre-commit-check = inputs.pre-commit-hooks.lib.${system}.run {
              src = ./.;
              hooks = {
                # Zig formatting
                zig-fmt = {
                  enable = true;
                  name = "zig fmt";
                  entry = "${zig}/bin/zig fmt";
                  files = "\\.zig$";
                  pass_filenames = true;
                };
                # Nix formatting
                nixpkgs-fmt = {
                  enable = true;
                };
              };
            };
          };

          devShells.default = pkgs.mkShellNoCC {
            nativeBuildInputs = [
              zig
              zls
              pkgs.lldb
              pkgs.uv
              pkgs.python313
            ];
            env = {
              UV_PYTHON = "${pkgs.python313}/bin/python";
            };
            shellHook = ''
              ${config.checks.pre-commit-check.shellHook}
            '';
          };
        };

    };

  # let
  #   supportedSystems = [
  #     "x86_64-linux"
  #     "aarch64-linux"
  #     "x86_64-darwin"
  #     "aarch64-darwin"
  #   ];
  #   forEachSupportedSystem =
  #     f:
  #     inputs.nixpkgs.lib.genAttrs supportedSystems (
  #       system:
  #       f {
  #         pkgs = import inputs.nixpkgs {
  #           inherit system;
  #         };
  #       }
  #     );
  # in
  # {
  #   devShells = forEachSupportedSystem (
  #     { pkgs }:
  #     {
  #       default = pkgs.mkShellNoCC {
  #         packages = with pkgs; [
  #           zig
  #           zls
  #           lldb
  #         ];
  #       };
  #     }
  #   );
  # };
}
