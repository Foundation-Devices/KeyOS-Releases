# SPDX-FileCopyrightText: 2025 Foundation Devices, Inc. <hello@foundation.xyz>
# SPDX-License-Identifier: GPL-3.0-or-later
{
  description = "KeyOS-Releases development environment";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    keyos.url = "git+ssh://git@github.com/Foundation-Devices/KeyOS";
    updiff = {
      url = "git+ssh://git@github.com/Foundation-Devices/updiff";
      flake = false;
    };
  };

  outputs = {
    self,
    nixpkgs,
    keyos,
    updiff,
  }: let
    inherit (nixpkgs) lib;
    forAllSystems = f: lib.genAttrs ["aarch64-darwin" "x86_64-darwin" "aarch64-linux" "x86_64-linux"] f;
  in {
    devShells = forAllSystems (
      system: let
        pkgs = import nixpkgs {
          inherit system;
        };
        keyosShell = keyos.devShells.${system}.default;

        updiffPkg = pkgs.rustPlatform.buildRustPackage {
          pname = "updiff";
          version = "0.1.0";
          src = updiff;
          cargoLock.lockFile = "${updiff}/Cargo.lock";
        };
      in {
        default = pkgs.mkShellNoCC {
          inherit
            (keyosShell)
            strictDeps
            hardeningDisable
            buildInputs
            LD_LIBRARY_PATH
            LIBCLANG_PATH
            shellHook
            ;

          packages =
            keyosShell.packages
            ++ [
              updiffPkg
              pkgs.bzip2
            ];
        };
      }
    );
  };
}
