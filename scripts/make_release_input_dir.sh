#!/bin/bash

# A simple script that takes a firmware version as input and generates a new directory with the
# KeyOS firmware components inside it.
#
# These components and their locations inside the `keyos` repository are:
#
# - app.bin      | target/armv7a-unknown-xous-elf/release/images/app.bin
# - recovery.bin | target/armv7a-unknown-xous-elf/release/images/recovery.bin
# - apps/        | target/armv7a-unknown-xous-elf/release/apps/
#
# Requires the `keyos` repository to run.

set -e

if [ "$#" -ne 1 ]; then
    echo "Usage: $0 <firmware_version>"
    exit 1
fi

# Also the output directory.
FIRMWARE_VERSION=$1
START_DIR=$(pwd)

if [ -d "$FIRMWARE_VERSION" ]; then
    echo "[WARN] Directory '$FIRMWARE_VERSION' already exists. Would you like to overwrite its contents? (y/n)"
    read -r response
    if [[ "$response" == "y" ]]; then
        rm -rf "$FIRMWARE_VERSION"
    else
        echo "[INFO] Exiting without making any changes."
        exit 0
    fi
fi

KEYOS_DIR=../../keyos

echo "[INFO] checking \`keyos\` directory"

if [ ! -d "$KEYOS_DIR" ]; then
    echo "[ERROR] keyos project not found at '$(realpath -m -q $KEYOS_DIR)'. \
Please clone it from https://github.com/Foundation-Devices/keyos"
    exit 1
fi

cd "$KEYOS_DIR"

echo "[INFO] generating firmware components in \`keyos\`"
cargo xtask build-all --dont-sign

cd "$START_DIR"

echo "[INFO] preparing release input directory"
mkdir "$FIRMWARE_VERSION"

cp "$KEYOS_DIR/target/armv7a-unknown-xous-elf/release/images/app.bin" "$FIRMWARE_VERSION"
cp "$KEYOS_DIR/target/armv7a-unknown-xous-elf/release/images/recovery.bin" "$FIRMWARE_VERSION"
cp -r "$KEYOS_DIR/target/armv7a-unknown-xous-elf/release/apps/" "$FIRMWARE_VERSION"

echo "[INFO] done"
