#!/usr/bin/env bash

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
# > make_release.sh <old_version_dir> <new_version_dir> <path_to_cosign2_config> [<path_to_keyos_repo>] [--reboot-required]
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

require_dir() {
    if [ ! -d "$1" ]; then
        error "directory '$1' does not exist."
        exit 1
    fi
}

require_file() {
    if [ ! -f "$1" ]; then
        error "file '$1' does not exist."
        exit 1
    fi
}

if [ ! -d .git ] || [ ! -f .git/config ] || ! grep -q "Foundation-Devices/KeyOS-Releases" .git/config; then
    error "please run the script from the root of the 'KeyOS-Releases' repository"
    exit 1
fi

if [ "$#" -lt 3 ] || [ "$#" -gt 5 ]; then
    echo "invalid number of arguments

Usage: make_release.sh <old_version_dir> <new_version_dir> <path_to_cosign2_config> [<path_to_keyos_repo>] [--reboot-required]"
    exit 1
fi

OLD_VERSION_DIR=$1
NEW_VERSION_DIR=$2
COSIGN2_CONFIG=$3
KEYOS_DIR=${4:-../keyos}
REBOOT_REQUIRED=false

if [ "$#" -ge 5 ] && [ "$5" = "--reboot-required" ]; then
    REBOOT_REQUIRED=true
elif [ "$#" -ge 4 ] && [ "$4" = "--reboot-required" ]; then
    REBOOT_REQUIRED=true
    KEYOS_DIR=../keyos
fi

START_DIR=$(pwd)
OUTPUT_ROOT_DIR="updates"
mkdir -p "$OUTPUT_ROOT_DIR"

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

require_file "$COSIGN2_CONFIG"

if [ ! -d "$KEYOS_DIR" ]; then
    error "keyos project not found at '$(realpath -m -q "$KEYOS_DIR")'. \
Please clone it from https://github.com/Foundation-Devices/keyos"
    exit 1
fi

OLD_KEYOS_DIR="$OLD_VERSION_DIR/keyos"
NEW_KEYOS_DIR="$NEW_VERSION_DIR/keyos"

for version_dir in "$OLD_VERSION_DIR" "$NEW_VERSION_DIR"; do
    require_dir "$version_dir/keyos"
    require_file "$version_dir/keyos/app.bin"
    require_dir "$version_dir/keyos/apps"
done

# Strip path to get the versions only.
OLD_VERSION=${OLD_VERSION_DIR##*/}
NEW_VERSION=${NEW_VERSION_DIR##*/}

UPDATE_DIR="$OUTPUT_ROOT_DIR/${OLD_VERSION}-${NEW_VERSION}"
mkdir -p "$UPDATE_DIR"

# Strip the 'v'.
OLD_VERSION_NO_V=${OLD_VERSION#v}
NEW_VERSION_NO_V=${NEW_VERSION#v}

info "signing files"

sign_keyos_file() {
    local version=$1
    local file=$2

    if cosign2 dump --input "$file" >/dev/null 2>&1; then
        info "skipping already signed file: $file"
        return
    fi

    cosign2 sign -c "$COSIGN2_CONFIG" -i "$file" --developer --in-place --binary-version "$version"
}

sign_keyos_files() {
    local version=$1
    local keyos_dir=$2

    sign_keyos_file "$version" "$keyos_dir/app.bin"

    while IFS= read -r -d '' app_elf; do
        sign_keyos_file "$version" "$app_elf"
    done < <(find "$keyos_dir/apps" -mindepth 2 -maxdepth 2 -type f -name app.elf -print0)
}

sign_keyos_files "$OLD_VERSION_NO_V" "$OLD_KEYOS_DIR"
sign_keyos_files "$NEW_VERSION_NO_V" "$NEW_KEYOS_DIR"

info "creating release tarball"

# Run `release-gen` to create the release tarball.
RELEASE_GEN_ARGS=("$OLD_VERSION" "$OLD_VERSION_DIR" "$NEW_VERSION" "$NEW_VERSION_DIR" -o ./release.tar)
if [ "$REBOOT_REQUIRED" = true ]; then
    RELEASE_GEN_ARGS+=(--reboot-required)
fi
cargo run --release -p release-gen -- "${RELEASE_GEN_ARGS[@]}"

info "calculating tar file hash before signing"
UNSIGNED_SHA256=$(sha256sum ./release.tar | awk '{print $1}')

info "signing release tarball with 'cosign2'"
cosign2 sign -c "$COSIGN2_CONFIG" -i ./release.tar --developer --in-place --binary-version "$NEW_VERSION_NO_V"

info "calculating tar file hash after signing"
SIGNED_SHA256=$(sha256sum ./release.tar | awk '{print $1}')

info "generating @manifest.json"
RELEASE_DATE=$(date +%Y-%m-%d)
UPDATE_FILENAME="release.tar"
SIGNATURE_FILENAME="release.tar.sig"

cat > "$UPDATE_DIR/manifest.json" <<EOF
{
	"baseVersion": "${OLD_VERSION_NO_V}",
	"version": "${NEW_VERSION_NO_V}",
	"signedSha256": "${SIGNED_SHA256}",
	"unsignedSha256": "${UNSIGNED_SHA256}",
	"updateFilename": "${UPDATE_FILENAME}",
	"signatureFilename": "${SIGNATURE_FILENAME}",
	"releaseDate": "${RELEASE_DATE}"
}
EOF

info "creating 'boot.img'"

# Restore old files and combine them into the image.
cp "$OLD_KEYOS_DIR/app.bin" "$KEYOS_DIR/target/armv7a-unknown-xous-elf/release/images"
cp -r "$OLD_KEYOS_DIR/apps" "$KEYOS_DIR/target/armv7a-unknown-xous-elf/release"

cd "$KEYOS_DIR"

info "building 'boot.img'"
cargo xtask build-firmware-image

cd "$START_DIR"

# Then copy the image over.
cp "$KEYOS_DIR/boot.img" "$UPDATE_DIR/boot.img"

info "compressing 'boot.img'"
gzip -c "$UPDATE_DIR/boot.img" > "$UPDATE_DIR/boot.img.gz"

if [ -f release.tar.sig ]; then
    mv release.tar.sig "$UPDATE_DIR/release.tar.sig"
fi
mv release.tar "$UPDATE_DIR/release.tar"

info "done"
