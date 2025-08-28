#!/bin/bash

# This script takes in two directories, representing two versions of KeyOS (we'll call them old
# and new), and produces two files:
#
# - `boot.img` - a bootable image representing the old version of KeyOS.
# - `release.tar` - a tarball that can be given to the KeyOS update service and will take KeyOS
#   from the old version to the new one.
#
# Both files will be generated in the directory where the script is run from.
#
# The third argument is the path to the `cosign2.toml` configuration file that will be used when
# signing various files.
#
# The fourth argument is the path to the `keyos` repository. This argument is optional and, if
# not provided, the script will assume that the `keyos` repository is in the same directory as
# `KeyOS-Releases`.
# ----------------------------------------------------------------------------------------------
#
# Usage
#
# > make_release.sh <old_version_dir> <new_version_dir> <path_to_cosign2_config> [<path_to_keyos_repo>]
#
# For simplicity, name the two input directories something like:
#
# - `v0.1.0` (the old version)
# - `v0.2.0` (the new version)
#
# because some of the commands require the versions to be specified and it is just simpler if we
# can use the directory name for that here. These don't have to be in the same directory as the
# script.
# ----------------------------------------------------------------------------------------------
#
# Prerequisites
#
# - This script uses the `keyos` build commands to produce `boot.img`. You can find `keyos` here:
#   https://github.com/Foundation-Devices/keyos.
#
# - This script calls `release-gen` (KeyOS-Releases/tools/release-gen) which needs the `updiff`
#   tool to function. This tool can be found here: https://github.com/Foundation-Devices/updiff.
#
# - To sign the release tarball, `cosign2` needs to be installed. It can be done by running the
#   following command in the root of the `keyos` repository:
#
#   > cargo install --path imports/cosign2/cosign2-bin
# ----------------------------------------------------------------------------------------------
#
# Notes about input directories
#
# The input directories should contain KeyOS firmware components inside them. These components and
# their locations inside the `keyos` repository are:
#
# - app.bin      | target/armv7a-unknown-xous-elf/release/images/app.bin
# - recovery.bin | target/armv7a-unknown-xous-elf/release/images/recovery.bin
# - apps/        | target/armv7a-unknown-xous-elf/release/apps/
#
# These files are generated inside inside `keyos` by running the following command:
#
# > cargo xtask build-all --dont-sign
#
# The `dont-sign` flag is required because we will be signing these files with the `signer` tool.
#
# You can create these directories and manually copy over the firmware components, or you can use
# use the `make_release_input_dir.sh` bash script to automate this process.

set -e

# Print an error message in bold red.
# Usage: error "Your error message"
error() {
    echo -e "\033[1;31mERROR\033[0m $1"
}

# Print a warning message in bold yellow.
# Usage: warn "Your warning message"
warn() {
    echo -e "\033[1;33mWARN\033[0m $1"
}

# Print an info message in bold green.
# Usage: info "Your info message"
info() {
    echo -e "\033[1;32mINFO\033[0m $1"
}

if [ ! -d .git ] || [ ! -f .git/config ] || ! grep -q "Foundation-Devices/KeyOS-Releases" .git/config; then
    error "please run the script from the root of the 'KeyOS-Releases' repository"
    exit 1
fi

if [ "$#" -ne 3 ] && [ "$#" -ne 4 ]; then
    echo "invalid number of arguments

Usage: make_release.sh <old_version_dir> <new_version_dir> <path_to_cosign2_config> [<path_to_keyos_repo>]"
    exit 1
fi

OLD_VERSION_DIR=$1
NEW_VERSION_DIR=$2
COSIGN2_CONFIG=$3
KEYOS_DIR=${4:-../keyos}

START_DIR=$(pwd)

info "checking required directories and tools"

if [ -f release.tar ] || [ -f boot.img ]; then
    warn "release.tar and/or boot.img already exist in the current directory. Would you like to overwrite them? (y/n)"
    read -r response
    if [[ "$response" == "y" ]]; then
        rm -f release.tar boot.img
    else
        info "Exiting without making any changes."
        exit 0
    fi
fi

if [ ! -d "$OLD_VERSION_DIR" ]; then
    error "directory '$OLD_VERSION_DIR' does not exist."
    exit 1
fi
if [ ! -d "$NEW_VERSION_DIR" ]; then
    error "directory '$NEW_VERSION_DIR' does not exist."
    exit 1
fi
if [ ! -f "$COSIGN2_CONFIG" ]; then
    error "file '$COSIGN2_CONFIG' does not exist."
    exit 1
fi

RELEASE_GEN_DIR=./tools/release-gen
RELEASE_GEN_TOOL=./tools/release-gen/target/release/release-gen
SIGNER_DIR=./tools/signer
SIGNER_TOOL=./tools/signer/target/release/signer

UPDIFF_TOOL_DIR=../updiff
UPDIFF_TOOL=../updiff/target/release/updiff

if [ ! -d "$KEYOS_DIR" ]; then
    error "keyos project not found at '$(realpath -m -q "$KEYOS_DIR")'. \
Please clone it from https://github.com/Foundation-Devices/keyos"
    exit 1
fi

info "building required tools"

# Build release-gen and signer.
if [ ! -d "$RELEASE_GEN_DIR" ]; then
    error "release-gen tool not found at '$(realpath -m -q "$RELEASE_GEN_DIR")'. It should be in the same repository as this script."
    exit 1
fi
cd "$RELEASE_GEN_DIR"
cargo build --release
cd "$START_DIR"

if [ ! -d "$SIGNER_DIR" ]; then
    error "signer tool not found at '$(realpath -m -q "$SIGNER_DIR")'. It should be in the same repository as this script."
    exit 1
fi
cd "$SIGNER_DIR"
cargo build --release
cd "$START_DIR"

# Build updiff.
if [ ! -d "$UPDIFF_TOOL_DIR" ]; then
    error "updiff tool not found at '$(realpath -m -q "$UPDIFF_TOOL_DIR")'. \
Please clone it from https://github.com/Foundation-Devices/updiff"
    exit 1
fi
cd "$UPDIFF_TOOL_DIR"
cargo build --release
cd "$START_DIR"

# Strip path to get the versions only.
OLD_VERSION=${OLD_VERSION_DIR##*/}
NEW_VERSION=${NEW_VERSION_DIR##*/}

# Strip the 'v'.
NEW_VERSION_NO_V=${NEW_VERSION#v}

info "signing files"

# Run the `signer` tool to sign both versions. It currently requires the input files to be in the
# current directory, so we copy it over, run it, then delete it.
cp "$SIGNER_TOOL" .
./signer sign-files "$OLD_VERSION" "$COSIGN2_CONFIG" --developer || {
    rm ./signer
    exit 1
}
./signer sign-files "$NEW_VERSION" "$COSIGN2_CONFIG" --developer || {
    rm ./signer
    exit 1
}
rm ./signer

info "creating release tarball"

# Run `release-gen` to create the release tarball.
"$RELEASE_GEN_TOOL" "$OLD_VERSION" "$OLD_VERSION_DIR" "$NEW_VERSION" "$NEW_VERSION_DIR" --updiff-path "$UPDIFF_TOOL" -o ./release.tar

info "signing release tarball with 'cosign2'"
cosign2 sign -c "$COSIGN2_CONFIG" -i ./release.tar --developer --in-place --binary-version "$NEW_VERSION_NO_V"

info "creating 'boot.img'"

# Restore old files and combine them into the image.
cp -r "$OLD_VERSION_DIR/apps" "$KEYOS_DIR/target/armv7a-unknown-xous-elf/release"
cp "$OLD_VERSION_DIR/app.bin" "$KEYOS_DIR/target/armv7a-unknown-xous-elf/release/images"
cp "$OLD_VERSION_DIR/recovery.bin" "$KEYOS_DIR/target/armv7a-unknown-xous-elf/release/images"

cd "$KEYOS_DIR"

info "building 'boot.img'"
cargo xtask build-firmware-image

cd "$START_DIR"

# Then copy the image over.
cp "$KEYOS_DIR/boot.img" .

info "done"
