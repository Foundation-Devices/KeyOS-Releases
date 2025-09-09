#!/bin/bash

# Here's a brief explanation of what this script does.
#
# The main goal of the script it to produce a release tarball and then include it into the combined
# image (boot.img) that can be flashed in order to test whether the KeyOS update service works.
#
# Usage
#
# > make_release_for_update_demo.sh <old_version_dir> <new_version_dir> [<path_to_keyos_repo>]
#
# The script takes in two directories (two versions of `keyos`) and runs several commands that will,
# in the end, produce `boot.img`. The image will be generated in the `keyos` directory, not in the
# directory of this script. For simplicity, name the two input directories something like:
#
# - `v0.1.0` (the old version)
# - `v0.2.0` (the new version)
#
# because some of the commands require the versions to be specified and it is just simpler if we
# can use the directory name for that here. These don't have to be in the same directory as the
# script.
#
# The third argument is the path to the `keyos` repository. This argument is optional and, if
# not provided, the script will assume that the `keyos` repository is in the same directory as
# `KeyOS-Releases`.
#
# Prerequisites
#
# - This script uses the `keyos` build commands to produce `boot.img`. You can find `keyos` here:
#   https://github.com/Foundation-Devices/keyos.
#
# - This script calls `release-gen` (KeyOS-Releases/tools/release-gen) which needs the `updiff`
#   tool to function. This tool can be found here: https://github.com/Foundation-Devices/updiff.
#   For simplicity, make sure that both tools are compiled (`target/[debug|release]` is present)
#   before running this script.
#
# - To sign the release tarball, `cosign2` needs to be installed. It can be done by running the
#   following command in the root of the `keyos` repository:
#
#   > cargo install --path imports/cosign2/cosign2-bin
#
# - To test the update server, the demo client (called "update-test") needs to be added to the list
#   of default services before running the script. That is done here:
#   https://github.com/Foundation-Devices/keyos/blob/dev-v0.9.0/xtask/src/main.rs#L65
#
# --------------------------------------------------------------------------------------------------
#
# Now a (not so) brief explanation of why this script does the steps that it does. If you just
# want to run the script and generate a release, you don't need to read this part.
#
# The update demo includes the entire tarball from the host machine as a blob and writes its contents
# into the device file system. That means that, when compiling KeyOS into a single image (boot.img),
# the tarball is part of that image. This can usually be done by running the following in the `keyos`
# project:
#
# > cargo xtask build-all
#
# However, there is an issue with this approach because the files that are part of the release are
# signed with `cosign2`, whose signature contains (among other things) a timestamp, and the command
# above also signs files with `cosign2` before combining them into `boot.img`. What ends up happening
# then is:
#
# 1. We take the files that constitute the old version (which have been signed at the time they were
# created) and place them in one directory.
# 2. We take the files that constitute the new version and place them in another directory.
# 3. We run the tool that creates a release tarball given these two directories (`release-gen`, it is
# part of the same repository as this script).
# 4. We take the generated release tarball, copy it into the update demo directory and build the image
# again (presumably with the `build-all` command), because that is going to include the tarball into the
# image.
# 5. During step 4, the `build-all` command signs the files that are currently in the project (the old
# version) which leads to them getting a new timestamp (different from the one they had when creating
# the tarball).
# 6. Update server runs the update, checks the `cosign2` header for each file and gets an error because
# there is a mismatch in the timestamp values.
#
# To work around this issue, we will do the following:
#
# 1. Same as above.
# 2. Same as above.
# 3. Same as above.
# 4. Same as above, but this time we only need this step to create `app.bin` which is the OS and it is
# the part of the image that contains the tarball blob.
#
# NOTE: Since we have to build `app.bin` to include the tarball (which will change its cosign timestamp),
# this method can only be used to test changes in the dynamically loaded apps, not the OS itself.
#
# 5. We copy the content of the old version back from the directory where we stored it in step 1. This way
# the files in `keyos` and the release tarball have the same timestamps again.
# 6. Run the following command:
#
# > cargo xtask build-firmware-image
#
# which will take all the files and combine them into `boot.img`.

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

if [ "$#" -ne 2 ] && [ "$#" -ne 3 ]; then
    error "invalid number of arguments

Usage: make_test_release.sh <old_version_dir> <new_version_dir> [<path_to_keyos_repo>]"
    exit 1
fi

OLD_VERSION_DIR=$1
NEW_VERSION_DIR=$2
KEYOS_DIR=${3:-../keyos}

START_DIR=$(pwd)

info "checking required directories and tools"

if [ ! -d "$OLD_VERSION_DIR" ]; then
    error "directory '$OLD_VERSION_DIR' does not exist."
    exit 1
fi
if [ ! -d "$NEW_VERSION_DIR" ]; then
    error "directory '$NEW_VERSION_DIR' does not exist."
    exit 1
fi

UPDATE_DEMO_DIR="$KEYOS_DIR"/test-apps/update-test

if [ ! -d "$KEYOS_DIR" ]; then
    error "keyos project not found at '$KEYOS_DIR'. Please clone it from https://github.com/Foundation-Devices/keyos"
    exit 1
fi

info "checking required tools"

# Strip path to get the versions only
OLD_VERSION=${OLD_VERSION_DIR##*/}
NEW_VERSION=${NEW_VERSION_DIR##*/}

# Strip the 'v'
NEW_VERSION_FOR_COSIGN=${NEW_VERSION#v}

info "signing files"

# Run the `signer` tool to sign both versions.
cargo run --release -p signer -- sign-files "$OLD_VERSION" "$COSIGN2_CONFIG" --developer || exit 1
cargo run --release -p signer -- sign-files "$NEW_VERSION" "$COSIGN2_CONFIG" --developer || exit 1

info "creating release tarball and moving it into 'keyos'"

# Run `release-gen` and move the release tarball into the update demo.
cargo run --release -p release-gen -- "$OLD_VERSION" "$OLD_VERSION_DIR" "$NEW_VERSION" "$NEW_VERSION_DIR" -o ./release.tar
mv ./release.tar "$UPDATE_DEMO_DIR"

cd "$KEYOS_DIR"

info "signing release tarball with 'cosign2'"
cosign2 sign -c cosign2.toml -i test-apps/update-test/release.tar --developer --in-place --binary-version "$NEW_VERSION_FOR_COSIGN"

info "building 'app.bin'"
cargo xtask build-all

cd "$START_DIR"

info "restoring old files"
cp -r "$OLD_VERSION_DIR/apps" "$KEYOS_DIR/target/armv7a-unknown-xous-elf/release"

cd "$KEYOS_DIR"

info "building 'boot.img'"
cargo xtask build-firmware-image

info "done"
