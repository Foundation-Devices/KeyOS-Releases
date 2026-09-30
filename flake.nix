# SPDX-FileCopyrightText: 2025 Foundation Devices, Inc. <hello@foundation.xyz>
# SPDX-License-Identifier: GPL-3.0-or-later
{
  description = "KeyOS-Releases development environment";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    keyos.url = "git+ssh://git@github.com/Foundation-Devices/KeyOS";
  };

  outputs = {
    self,
    nixpkgs,
    keyos,
  }: let
    inherit (nixpkgs) lib;
    forAllSystems = f: lib.genAttrs ["aarch64-darwin" "x86_64-darwin" "aarch64-linux" "x86_64-linux"] f;
  in {
    devShells = forAllSystems (
      system: let
        pkgs = import nixpkgs {
          inherit system;
        };
        # using build shell bc faster than full dev shell
        keyosShell = keyos.devShells.${system}.build;
        keyosPackages = keyos.packages.${system};

        customPackages =
          (with pkgs; [
            bzip2
            git-lfs
            gnutar
            gzip
          ])
          ++ (with keyosPackages; [
            # for local dev
            rust-analyzer
          ]);
      in {
        default = keyosShell.overrideAttrs (keyos: {
          nativeBuildInputs = keyos.nativeBuildInputs ++ customPackages;
          shellHook = (keyos.shellHook or "") + ''
            if [ -e .git ] && [ -f .gitattributes ] && grep -q "filter=lfs" .gitattributes; then
              git lfs install --local >/dev/null
            fi
          '';
        });
      }
    );
  };
}
