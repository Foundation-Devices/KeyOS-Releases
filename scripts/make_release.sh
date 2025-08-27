#!/bin/bash

# This script takes in two directories, representing two versions of KeyOS (we'll call them old
# and new), and produces two files:
#
# - `boot.img` - a bootable image representing the old version of KeyOS.
# - `release.tar` - a tarball that can be given to the KeyOS update service and will take KeyOS
#   from the old version to the new one.
#
# Both files will be generated in the same directory as this script.
#
# The third argument is the path to the `cosign2.toml` configuration file that will be used when
# signing various files.
# ----------------------------------------------------------------------------------------------
#
# Usage
#
# > make_release.sh ./v0.1.0 ./v0.2.0 ./cosign.toml
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

if [ "$#" -ne 3 ]; then
    echo "Usage: $0 <old_version_dir> <new_version_dir> <cosign2_config>"
    exit 1
fi

OLD_VERSION_DIR=$1
NEW_VERSION_DIR=$2
COSIGN2_CONFIG=$3

START_DIR=$(pwd)

echo "[INFO] checking required directories and tools"

if [ ! -d "$OLD_VERSION_DIR" ]; then
    echo "[ERROR] Directory '$OLD_VERSION_DIR' does not exist."
    exit 1
fi
if [ ! -d "$NEW_VERSION_DIR" ]; then
    echo "[ERROR] Directory '$NEW_VERSION_DIR' does not exist."
    exit 1
fi
if [ ! -f "$COSIGN2_CONFIG" ]; then
    echo "[ERROR] File '$COSIGN2_CONFIG' does not exist."
    exit 1
fi

KEYOS_DIR=../../keyos

RELEASE_GEN_TOOL=../tools/release-gen/target/debug/release-gen
SIGNER_TOOL=../tools/signer/target/debug/signer

UPDIFF_TOOL_DIR=../../updiff
UPDIFF_TOOL=../../updiff/target/debug/updiff

if [ ! -d "$KEYOS_DIR" ]; then
    echo "[ERROR] keyos project not found at '$(realpath -m -q $KEYOS_DIR)'. \
Please clone it from https://github.com/Foundation-Devices/keyos"
    exit 1
fi

if [ ! -f "$RELEASE_GEN_TOOL" ]; then
    # Try the `release` directory instead of `debug`.
    echo "[WARN] release-gen tool not found at '$(realpath -m -q $RELEASE_GEN_TOOL)'. Trying release build..."
    RELEASE_GEN_TOOL=../tools/release-gen/target/release/release-gen
    if [ ! -f "$RELEASE_GEN_TOOL" ]; then
        # Could not find `release-gen`, build it.
        echo "[WARN] release-gen tool not found at '$(realpath -m -q $RELEASE_GEN_TOOL)'. Building it..."
        cd ../tools/release-gen
        cargo build --release
        RELEASE_GEN_TOOL=../tools/release-gen/target/release/release-gen
        cd "$START_DIR"
    fi
fi
if [ ! -f "$SIGNER_TOOL" ]; then
    # Try the `release` directory instead of `debug`.
    echo "[WARN] signer tool not found at '$(realpath -m -q $SIGNER_TOOL)'. Trying release build..."
    SIGNER_TOOL=../tools/signer/target/release/signer
    if [ ! -f "$SIGNER_TOOL" ]; then
        # Could not find `signer`, build it.
        echo "[WARN] signer tool not found at '$(realpath -m -q $SIGNER_TOOL)'. Building it..."
        cd ../tools/signer
        cargo build --release
        SIGNER_TOOL=../tools/signer/target/release/signer
        cd "$START_DIR"
    fi
fi

if [ ! -f "$UPDIFF_TOOL" ]; then
    # Try the `release` directory instead of `debug`.
    echo "[WARN] updiff tool not found at '$(realpath -m -q $UPDIFF_TOOL)'. Trying release build..."
    UPDIFF_TOOL=../../updiff/target/release/updiff
    if [ ! -f "$UPDIFF_TOOL" ]; then
        if [ ! -d "$UPDIFF_TOOL_DIR" ]; then
            echo "[ERROR] updiff tool not found at '$(realpath -m -q $UPDIFF_TOOL)'. \
Please clone it from https://github.com/Foundation-Devices/updiff"
            exit 1
        fi

        # Could not find `updiff`, but the repository exists. Build it.
        cd "$UPDIFF_TOOL_DIR"
        echo "[WARN] updiff tool not found at '$(realpath -m -q $UPDIFF_TOOL)'. Building it..."
        cargo build --release
        UPDIFF_TOOL=../../updiff/target/release/updiff
        cd "$START_DIR"
    fi
fi

# Strip path to get the versions only.
OLD_VERSION=${OLD_VERSION_DIR##*/}
NEW_VERSION=${NEW_VERSION_DIR##*/}

# Strip the 'v'.
NEW_VERSION_NO_V=${NEW_VERSION#v}

echo "[INFO] signing files"

# Run the `signer` tool to sign both versions.
cp "$SIGNER_TOOL" .
./signer sign-files "$OLD_VERSION" "$COSIGN2_CONFIG"
./signer sign-files "$NEW_VERSION" "$COSIGN2_CONFIG"
rm ./signer

echo "[INFO] creating release tarball"

# Run `release-gen` to create the release tarball.
"$RELEASE_GEN_TOOL" "$OLD_VERSION" "$OLD_VERSION_DIR" "$NEW_VERSION" "$NEW_VERSION_DIR" --updiff-path "$UPDIFF_TOOL" -o ./release.tar

echo "[INFO] signing release tarball with \`cosign2\`"
cosign2 sign -c "$COSIGN2_CONFIG" -i ./release.tar --developer --in-place --binary-version "$NEW_VERSION_NO_V"

echo "[INFO] creating \`boot.img\`"

# Restore old files and combine them into the image.
cp -r "$OLD_VERSION_DIR/apps" "$KEYOS_DIR/target/armv7a-unknown-xous-elf/release"
cp "$OLD_VERSION_DIR/app.bin" "$KEYOS_DIR/target/armv7a-unknown-xous-elf/release/images"
cp "$OLD_VERSION_DIR/recovery.bin" "$KEYOS_DIR/target/armv7a-unknown-xous-elf/release/images"

cd "$KEYOS_DIR"

echo "[INFO] building \`boot.img\`"
cargo xtask build-firmware-image

cd "$START_DIR"

# Then copy the image over.
cp "$KEYOS_DIR/boot.img" .

echo "[INFO] done"
