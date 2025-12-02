#!/usr/bin/env bash

# A simple script that takes a firmware version as input and generates a new directory with the
# KeyOS firmware components inside it.
#
# These components and their locations inside the `keyos` repository are:
#
# - app.bin      | target/armv7a-unknown-xous-elf/release/images/app.bin
# - apps/        | target/armv7a-unknown-xous-elf/release/apps/
#
# Requires the `keyos` repository to run. Path to it can be passed as an optional last argument
# to this script.

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

if [ "$#" -ne 1 ] && [ "$#" -ne 2 ]; then
    error "invalid number of arguments

Usage: make_release_input_dir.sh <firmware_version> [<path_to_keyos_repo>]"
    exit 1
fi

# Also the output directory.
FIRMWARE_VERSION=$1
KEYOS_DIR=${2:-../keyos}

START_DIR=$(pwd)

if [ -d "$FIRMWARE_VERSION" ]; then
    warn "Directory '$FIRMWARE_VERSION' already exists. Would you like to overwrite its contents? (y/n)"
    read -r response
    if [[ "$response" == "y" ]]; then
        rm -rf "$FIRMWARE_VERSION"
    else
        info "Exiting without making any changes."
        exit 0
    fi
fi

info "checking 'keyos' directory"

if [ ! -d "$KEYOS_DIR" ]; then
    error "keyos project not found at '$(realpath -m -q "$KEYOS_DIR")'. \
Please clone it from https://github.com/Foundation-Devices/keyos"
    exit 1
fi

cd "$KEYOS_DIR"

info "generating firmware components in 'keyos'"
cargo xtask build --dont-sign --reproducible

cd "$START_DIR"

info "preparing release input directory"
mkdir "$FIRMWARE_VERSION"

cp "$KEYOS_DIR/target/armv7a-unknown-xous-elf/release/images/app.bin" "$FIRMWARE_VERSION"
cp -r "$KEYOS_DIR/target/armv7a-unknown-xous-elf/release/apps/" "$FIRMWARE_VERSION"

info "done"
