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
  };

  outputs =
    inputs@{ flake-parts, ... }:
    flake-parts.lib.mkFlake { inherit inputs; } {
      systems = [ "x86_64-linux" "aarch64-linux" "aarch64-darwin" ];
      perSystem = { config, self', inputs', pkgs, system, ... }: {

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
                entry = "${pkgs.zig}/bin/zig fmt";
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
          nativeBuildInputs = with pkgs; [
            zig
            zls
            lldb
          ];
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
