# SPDX-FileCopyrightText: © 2025  Foundation Devices, Inc. <hello@foundation.xyz>
# SPDX-License-Identifier: GPL-3.0-or-later

# Sign individual files with the provided key
sign VERSION CONFIG_PATH=env_var_or_default("COSIGN_TOML_PATH", "~/cosign2.toml"):
    #!/usr/bin/env bash
    set -euo pipefail

    VER="{{VERSION}}"
    CFG="{{CONFIG_PATH}}"

    # Expand ~ in config path if present
    if [[ "$CFG" == "~/"* ]]; then
        CFG="$HOME/${CFG#~/}"
    fi


    # Ensure we are on the correct branch
    if ! git rev-parse --verify "$VER" >/dev/null 2>&1; then
        echo "ERROR: Branch '$VER' not found" >&2
        exit 1
    fi
    CURRENT_BRANCH=$(git rev-parse --abbrev-ref HEAD)
    if [ "$CURRENT_BRANCH" != "$VER" ]; then
        git checkout "$VER"
    fi
    git pull --rebase

    REL_DIR="$VER"
    if [ ! -d "$REL_DIR" ]; then
        echo "ERROR: Release directory not found: $REL_DIR" >&2
        exit 1
    fi

    # Abort if already double-signed
    if cargo run --manifest-path tools/signer/Cargo.toml -- validate "$VER" --files-only >/dev/null 2>&1; then
        echo "ERROR: Files are already double-signed for version $VER" >&2
        exit 1
    fi

    echo "Signing all files for version $VER with config $CFG"
    cargo run --manifest-path tools/signer/Cargo.toml -- sign-files "$VER" "$CFG"

    # Determine commit message based on signature state after signing
    if cargo run --manifest-path tools/signer/Cargo.toml -- validate "$VER" --files-only >/dev/null 2>&1; then
        MSG="Second signatures applied and pushed"
    else
        MSG="First signatures applied and pushed"
    fi

    # Stage and commit only the release folder changes
    git -C "$REL_DIR" add -A .
    if git -C "$REL_DIR" diff --cached --quiet -- .; then
        echo "No changes detected in $REL_DIR; aborting commit." >&2
        exit 1
    fi

    git commit -m "$MSG"
    # Push to upstream or set it if missing
    if git rev-parse --abbrev-ref --symbolic-full-name @{u} >/dev/null 2>&1; then
        git push
    else
        git push -u origin "$VER"
    fi

    echo "✅ $MSG"

# Create tar file (only when all files have two signatures)
create-tar VERSION:
    @echo "Creating tar file for version {{VERSION}}"
    cargo run --manifest-path tools/signer/Cargo.toml -- create-tar {{VERSION}}

create-recovery-tar VERSION:
    @echo "Creating recovery tar file for version {{VERSION}}"
    cargo run --manifest-path tools/signer/Cargo.toml -- create-tar {{VERSION}} --recovery

create-recovery-tar-dev VERSION:
    @echo "Creating recovery tar file for version {{VERSION}} (one signature)"
    cargo run --manifest-path tools/signer/Cargo.toml -- create-tar {{VERSION}} --recovery --allow-one-signature

# Sign the tar file with the provided key
sign-tar VERSION CONFIG_PATH=env_var_or_default("COSIGN_TOML_PATH", "~/cosign2.toml"):
    @echo "Signing tar file for version {{VERSION}} with config {{CONFIG_PATH}}"
    cargo run --manifest-path tools/signer/Cargo.toml -- sign-tar {{VERSION}} {{CONFIG_PATH}}

# Unsign all files for a version by resetting them to their original state
unsign VERSION:
    @echo "Unsigning all files for version {{VERSION}} (git reset)"
    @echo "Resetting KeyOS image..."
    git checkout -- {{VERSION}}/app.bin
    @echo "Resetting app files..."
    git checkout -- {{VERSION}}/apps/*/app.elf
    @echo "Removing tar file if it exists..."
    rm -f {{VERSION}}/KeyOS-v{{VERSION}}.bin
    @echo "Removing manifest file if it exists..."
    rm -f {{VERSION}}/manifest.json
    @echo "✓ All files have been reset to their unsigned state"

# Validate that all files for a version are properly signed
validate VERSION:
    @echo "Validating signatures for version {{VERSION}}..."
    cargo run --manifest-path tools/signer/Cargo.toml -- validate {{VERSION}}

# Generate a new release.tar between two versions
release-gen *args:
    cargo run --manifest-path tools/release-gen/Cargo.toml -- {{args}}

# Create a bootable disk image from firmware components (production)
create-image VERSION OUTPUT="boot.img":
    @echo "Creating disk image for version {{VERSION}}"
    cargo run --manifest-path tools/image-builder/Cargo.toml -- --production create-image {{VERSION}} --output {{OUTPUT}}

# Create a bootable disk image from firmware components (production)
create-image-dev VERSION OUTPUT="boot.img":
    @echo "Creating disk image for version {{VERSION}}"
    cargo run --manifest-path tools/image-builder/Cargo.toml -- create-image {{VERSION}} --output {{OUTPUT}}

# Print SHA256 hashes of firmware components
print-hashes VERSION:
    @echo "Printing hashes for version {{VERSION}}"
    cargo run --manifest-path tools/image-builder/Cargo.toml -- print-hashes {{VERSION}}
