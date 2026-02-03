# SPDX-FileCopyrightText: © 2025  Foundation Devices, Inc. <hello@foundation.xyz>
# SPDX-License-Identifier: GPL-3.0-or-later

# Create a complete release: factory image, recovery tars, update file, sign everything, and commit
# Usage: just create-release 1.0.0 1.0.1 ~/cosign2.toml
create-release BASE_VERSION NEW_VERSION CONFIG_PATH:
    #!/usr/bin/env bash
    set -eu

    BASE_VER="{{BASE_VERSION}}"
    NEW_VER="{{NEW_VERSION}}"
    CFG="{{CONFIG_PATH}}"
    ROOT="{{justfile_directory()}}"
    WORKTREES_DIR="${KEYOS_RELEASES_WORKTREES_DIR:-"$ROOT/.worktrees"}"
    BASE_WT="$WORKTREES_DIR/$BASE_VER"
    NEW_WT="$WORKTREES_DIR/$NEW_VER"

    # Expand ~ in config path if present
    if [[ "$CFG" == "~/"* ]]; then
        CFG="$HOME/${CFG#~/}"
    fi
    if [ ! -f "$CFG" ]; then
        echo "ERROR: Config file not found: $CFG" >&2
        exit 1
    fi

    mkdir -p "$WORKTREES_DIR"

    # Setup/update worktrees for both versions
    source "$ROOT/tools/worktree-helper.sh"
    if ! setup_worktree "$ROOT" "$BASE_VER" "$BASE_WT"; then
        exit 1
    fi
    if ! setup_worktree "$ROOT" "$NEW_VER" "$NEW_WT"; then
        exit 1
    fi

    # Verify the release directories exist
    if [ ! -d "$BASE_WT/$BASE_VER" ]; then
        echo "ERROR: Base release directory not found: $BASE_WT/$BASE_VER" >&2
        exit 1
    fi
    if [ ! -d "$NEW_WT/$NEW_VER" ]; then
        echo "ERROR: New release directory not found: $NEW_WT/$NEW_VER" >&2
        exit 1
    fi

    echo "=== Creating release $NEW_VER (updating from $BASE_VER) ==="
    echo ""

    # Step 1: Create factory image
    echo "Step 1/5: Creating factory image..."
    OUTPUT="KeyOS-v$NEW_VER-Factory.img"
    REL_WT=".worktrees/$NEW_VER"
    (cd "$ROOT" && cargo run --manifest-path "tools/image-builder/Cargo.toml" -- --production create-image "$REL_WT/$NEW_VER" --output "$REL_WT/$NEW_VER/$OUTPUT")
    echo ""

    # Step 2: Create core system recovery tar
    echo "Step 2/5: Creating core system recovery tar..."
    (cd "$NEW_WT" && cargo run --manifest-path "$ROOT/tools/signer/Cargo.toml" -- create-recovery-tar "$NEW_VER" "$CFG" --core-system-recovery)
    echo ""

    # Step 3: Create recovery tar
    echo "Step 3/5: Creating recovery tar..."
    (cd "$NEW_WT" && cargo run --manifest-path "$ROOT/tools/signer/Cargo.toml" -- create-recovery-tar "$NEW_VER" "$CFG")
    echo ""

    # Step 4: Create update file
    echo "Step 4/5: Creating update file..."
    UPDATE_OUTPUT="$NEW_WT/$NEW_VER/KeyOS-v$BASE_VER-to-v$NEW_VER-Update.tar"
    cargo run --manifest-path "$ROOT/tools/release-gen/Cargo.toml" -- \
        "$BASE_VER" "$BASE_WT/$BASE_VER" \
        "$NEW_VER" "$NEW_WT/$NEW_VER" \
        --out "$UPDATE_OUTPUT" \
        --force
    echo ""

    # Step 5: Sign recovery tars
    echo "Step 5/5: Signing recovery tars..."
    (cd "$NEW_WT" && cargo run --manifest-path "$ROOT/tools/signer/Cargo.toml" -- sign-recovery-tars "$NEW_VER" "$CFG")
    echo ""

    # Commit and push
    echo "Committing changes..."
    git -C "$NEW_WT" add -A "$NEW_VER"
    if git -C "$NEW_WT" diff --cached --quiet -- "$NEW_VER"; then
        echo "No changes detected in $NEW_VER; nothing to commit."
    else
        MSG="Release $NEW_VER created"
        git -C "$NEW_WT" commit -m "$MSG"
        if git -C "$NEW_WT" rev-parse --abbrev-ref --symbolic-full-name @{u} >/dev/null 2>&1; then
            git -C "$NEW_WT" push
        else
            git -C "$NEW_WT" push -u origin "$NEW_VER"
        fi
        echo "✅ Committed and pushed: $MSG"
    fi

    echo ""
    echo "✅ Release $NEW_VER complete!"
    echo "   Factory image: $NEW_WT/$NEW_VER/$OUTPUT"
    echo "   Core system recovery: $NEW_WT/$NEW_VER/KeyOS-v$NEW_VER-CoreSystemRecovery.bin"
    echo "   Recovery: $NEW_WT/$NEW_VER/KeyOS-v$NEW_VER-Recovery.bin"
    echo "   Update file: $UPDATE_OUTPUT"

# Sign individual files with the provided key (uses a dedicated git worktree to avoid switching your current branch)
sign VERSION CONFIG_PATH=env_var_or_default("COSIGN_TOML_PATH", "~/cosign2.toml"):
    #!/usr/bin/env bash
    set -u

    VER="{{VERSION}}"
    CFG="{{CONFIG_PATH}}"
    ROOT="{{justfile_directory()}}"
    WORKTREES_DIR="${KEYOS_RELEASES_WORKTREES_DIR:-"$ROOT/.worktrees"}"
    WT="$WORKTREES_DIR/$VER"

    # Expand ~ in config path if present
    if [[ "$CFG" == "~/"* ]]; then
        CFG="$HOME/${CFG#~/}"
    fi
    if [ ! -f "$CFG" ]; then
        echo "ERROR: Config file not found: $CFG" >&2
        exit 1
    fi

    mkdir -p "$WORKTREES_DIR"

    # Setup/update worktree using helper function
    source "$ROOT/tools/worktree-helper.sh"
    if ! setup_worktree "$ROOT" "$VER" "$WT"; then
        exit 1
    fi

    # Verify the release directory exists in the worktree
    if [ ! -d "$WT/$VER" ]; then
        echo "ERROR: Release directory not found: $WT/$VER" >&2
        exit 1
    fi

    # Abort if already double-signed (worktree)
    if (cd "$WT" && cargo run --manifest-path "$ROOT/tools/signer/Cargo.toml" -- validate "$VER" --files-only) >/dev/null 2>&1; then
        echo "ERROR: Files are already double-signed for version $VER" >&2
        exit 1
    fi

    echo "Signing all files for version $VER with config $CFG"
    (cd "$WT" && cargo run --manifest-path "$ROOT/tools/signer/Cargo.toml" -- sign-files "$VER" "$CFG")

    # Determine commit message based on signature state after signing
    if (cd "$WT" && cargo run --manifest-path "$ROOT/tools/signer/Cargo.toml" -- validate "$VER" --files-only) >/dev/null 2>&1; then
        MSG="Second signatures applied and pushed"
    else
        MSG="First signatures applied and pushed"
    fi

    # Stage and commit only the release folder changes within the worktree
    git -C "$WT" add -A "$VER"
    if git -C "$WT" diff --cached --quiet -- "$VER"; then
        echo "No changes detected in $VER; aborting commit." >&2
        exit 1
    fi

    git -C "$WT" commit -m "$MSG"
    # Push to upstream or set it if missing
    # Use refs/heads/ prefix to explicitly push to the branch, not a tag
    if git -C "$WT" rev-parse --abbrev-ref --symbolic-full-name @{u} >/dev/null 2>&1; then
        git -C "$WT" push
    else
        git -C "$WT" push -u origin "refs/heads/$VER"
    fi

    echo "✅ $MSG"

# Create recovery tar file (only when all files have two signatures)
create-recovery-tar VERSION CONFIG_PATH=env_var_or_default("COSIGN_TOML_PATH", "~/cosign2.toml"):
    #!/usr/bin/env bash
    set -u

    VER="{{VERSION}}"
    CFG="{{CONFIG_PATH}}"
    ROOT="{{justfile_directory()}}"
    WORKTREES_DIR="${KEYOS_RELEASES_WORKTREES_DIR:-"$ROOT/.worktrees"}"
    WT="$WORKTREES_DIR/$VER"

    # Expand ~ in config path if present
    if [[ "$CFG" == "~/"* ]]; then
        CFG="$HOME/${CFG#~/}"
    fi
    if [ ! -f "$CFG" ]; then
        echo "ERROR: Config file not found: $CFG" >&2
        exit 1
    fi

    # Check if worktree exists
    if [ ! -d "$WT" ]; then
        echo "ERROR: Worktree not found at $WT" >&2
        echo "Please run 'just sign $VER' first to create the worktree" >&2
        exit 1
    fi

    echo "Creating recovery tar file for version $VER"
    (cd "$WT" && cargo run --manifest-path "$ROOT/tools/signer/Cargo.toml" -- create-recovery-tar "$VER" "$CFG")

# Create recovery tar for development (allows one signature)
create-recovery-tar-dev VERSION CONFIG_PATH=env_var_or_default("COSIGN_TOML_PATH", "~/cosign2.toml"):
    #!/usr/bin/env bash
    set -u

    VER="{{VERSION}}"
    CFG="{{CONFIG_PATH}}"
    ROOT="{{justfile_directory()}}"
    WORKTREES_DIR="${KEYOS_RELEASES_WORKTREES_DIR:-"$ROOT/.worktrees"}"
    WT="$WORKTREES_DIR/$VER"

    # Expand ~ in config path if present
    if [[ "$CFG" == "~/"* ]]; then
        CFG="$HOME/${CFG#~/}"
    fi
    if [ ! -f "$CFG" ]; then
        echo "ERROR: Config file not found: $CFG" >&2
        exit 1
    fi

    # Check if worktree exists
    if [ ! -d "$WT" ]; then
        echo "ERROR: Worktree not found at $WT" >&2
        echo "Please run 'just sign $VER' first to create the worktree" >&2
        exit 1
    fi

    echo "Creating recovery tar file for version $VER (one signature)"
    (cd "$WT" && cargo run --manifest-path "$ROOT/tools/signer/Cargo.toml" -- create-recovery-tar "$VER" "$CFG" --allow-one-signature)

# Create core system recovery tar (includes ONLY bootloader and recovery.bin)
create-core-system-recovery-tar VERSION CONFIG_PATH=env_var_or_default("COSIGN_TOML_PATH", "~/cosign2.toml"):
    #!/usr/bin/env bash
    set -u

    VER="{{VERSION}}"
    CFG="{{CONFIG_PATH}}"
    ROOT="{{justfile_directory()}}"
    WORKTREES_DIR="${KEYOS_RELEASES_WORKTREES_DIR:-"$ROOT/.worktrees"}"
    WT="$WORKTREES_DIR/$VER"

    # Expand ~ in config path if present
    if [[ "$CFG" == "~/"* ]]; then
        CFG="$HOME/${CFG#~/}"
    fi
    if [ ! -f "$CFG" ]; then
        echo "ERROR: Config file not found: $CFG" >&2
        exit 1
    fi

    # Check if worktree exists
    if [ ! -d "$WT" ]; then
        echo "ERROR: Worktree not found at $WT" >&2
        echo "Please run 'just sign $VER' first to create the worktree" >&2
        exit 1
    fi

    echo "Creating core system recovery tar file for version $VER"
    (cd "$WT" && cargo run --manifest-path "$ROOT/tools/signer/Cargo.toml" -- create-recovery-tar "$VER" "$CFG" --core-system-recovery)

# Create core system recovery tar for development (allows one signature)
create-core-system-recovery-tar-dev VERSION CONFIG_PATH=env_var_or_default("COSIGN_TOML_PATH", "~/cosign2.toml"):
    #!/usr/bin/env bash
    set -u

    VER="{{VERSION}}"
    CFG="{{CONFIG_PATH}}"
    ROOT="{{justfile_directory()}}"
    WORKTREES_DIR="${KEYOS_RELEASES_WORKTREES_DIR:-"$ROOT/.worktrees"}"
    WT="$WORKTREES_DIR/$VER"

    # Expand ~ in config path if present
    if [[ "$CFG" == "~/"* ]]; then
        CFG="$HOME/${CFG#~/}"
    fi
    if [ ! -f "$CFG" ]; then
        echo "ERROR: Config file not found: $CFG" >&2
        exit 1
    fi

    # Check if worktree exists
    if [ ! -d "$WT" ]; then
        echo "ERROR: Worktree not found at $WT" >&2
        echo "Please run 'just sign $VER' first to create the worktree" >&2
        exit 1
    fi

    echo "Creating core system recovery tar file for version $VER (one signature)"
    (cd "$WT" && cargo run --manifest-path "$ROOT/tools/signer/Cargo.toml" -- create-recovery-tar "$VER" "$CFG" --core-system-recovery --allow-one-signature)


# Sign the recovery tar files with the provided key
sign-recovery-tars VERSION CONFIG_PATH=env_var_or_default("COSIGN_TOML_PATH", "~/cosign2.toml"):
    #!/usr/bin/env bash
    set -u

    VER="{{VERSION}}"
    CFG="{{CONFIG_PATH}}"
    ROOT="{{justfile_directory()}}"
    WORKTREES_DIR="${KEYOS_RELEASES_WORKTREES_DIR:-"$ROOT/.worktrees"}"
    WT="$WORKTREES_DIR/$VER"

    # Expand ~ in config path if present
    if [[ "$CFG" == "~/"* ]]; then
        CFG="$HOME/${CFG#~/}"
    fi
    if [ ! -f "$CFG" ]; then
        echo "ERROR: Config file not found: $CFG" >&2
        exit 1
    fi

    # Check if worktree exists
    if [ ! -d "$WT" ]; then
        echo "ERROR: Worktree not found at $WT" >&2
        echo "Please run 'just sign $VER' first to create the worktree" >&2
        exit 1
    fi

    echo "Signing recovery tar files for version $VER with config $CFG"
    (cd "$WT" && cargo run --manifest-path "$ROOT/tools/signer/Cargo.toml" -- sign-recovery-tars "$VER" "$CFG")


# Revert signing commits for a version and remove its worktree (full reset)
unsign VERSION:
    #!/usr/bin/env bash
    set -u

    VER="{{VERSION}}"
    ROOT="{{justfile_directory()}}"
    WORKTREES_DIR="${KEYOS_RELEASES_WORKTREES_DIR:-"$ROOT/.worktrees"}"
    WT="$WORKTREES_DIR/$VER"

    echo "Unsigning version $VER: reverting signing commits and removing worktree"

    # Ensure the release branch exists
    mkdir -p "$WORKTREES_DIR"
    # Setup/update worktree using helper function
    source "$ROOT/tools/worktree-helper.sh"
    if ! setup_worktree "$ROOT" "$VER" "$WT" CREATED_WT; then
        exit 1
    fi


    # Find signing commits that touched this version directory (newest first)
    COMMITS=$(git -C "$WT" log --pretty=format:%H --grep='signatures applied and pushed' --regexp-ignore-case -- "$VER" || true)

    if [ -z "$COMMITS" ]; then
        echo "No signing commits found for $VER; nothing to revert."
    else
        for SHA in $COMMITS; do
            echo "Reverting signing commit $SHA ..."
            if ! git -C "$WT" revert --no-edit "$SHA"; then
                echo "ERROR: Revert failed for $SHA. Resolve conflicts in worktree: $WT" >&2
                exit 1
            fi
        done

        # Push to upstream or set it if missing
        # Use refs/heads/ prefix to explicitly push to the branch, not a tag
        if git -C "$WT" rev-parse --abbrev-ref --symbolic-full-name @{u} >/dev/null 2>&1; then
            git -C "$WT" push
        else
            git -C "$WT" push -u origin "refs/heads/$VER"
        fi
    fi

    # Remove local build artifacts (not committed)
    rm -f "$WT/$VER/KeyOS-$VER.bin" "$WT/$VER/manifest.json" || true

    # Remove the worktree to restore local state
    if git -C "$ROOT" worktree remove -f "$WT"; then
        git -C "$ROOT" worktree prune || true
        echo "✓ Worktree removed: $WT"
    else
        echo "WARNING: Failed to remove worktree $WT; please remove manually if desired" >&2
    fi

    echo "✓ Unsign complete for version $VER"

# Validate that all files for a version are properly signed (production - requires 2 signatures)
validate VERSION:
    #!/usr/bin/env bash
    set -u

    VER="{{VERSION}}"
    ROOT="{{justfile_directory()}}"
    WORKTREES_DIR="${KEYOS_RELEASES_WORKTREES_DIR:-"$ROOT/.worktrees"}"
    WT="$WORKTREES_DIR/$VER"

    # Check if worktree exists
    if [ ! -d "$WT" ]; then
        echo "ERROR: Worktree not found at $WT" >&2
        echo "Please run 'just sign $VER' first to create the worktree" >&2
        exit 1
    fi

    echo "Validating signatures for version $VER (production)"
    (cd "$WT" && cargo run --manifest-path "$ROOT/tools/signer/Cargo.toml" -- validate "$VER")

# Validate that all files for a version are signed (development - requires 1 signature)
validate-dev VERSION:
    #!/usr/bin/env bash
    set -u

    VER="{{VERSION}}"
    ROOT="{{justfile_directory()}}"
    WORKTREES_DIR="${KEYOS_RELEASES_WORKTREES_DIR:-"$ROOT/.worktrees"}"
    WT="$WORKTREES_DIR/$VER"

    # Check if worktree exists
    if [ ! -d "$WT" ]; then
        echo "ERROR: Worktree not found at $WT" >&2
        echo "Please run 'just sign $VER' first to create the worktree" >&2
        exit 1
    fi

    echo "Validating signatures for version $VER (development)"
    (cd "$WT" && cargo run --manifest-path "$ROOT/tools/signer/Cargo.toml" -- validate "$VER" --dev)

# Create an update tar between two versions
create-update BASE_VERSION NEW_VERSION *EXTRA_ARGS:
    #!/usr/bin/env bash
    set -u

    BASE_VER="{{BASE_VERSION}}"
    NEW_VER="{{NEW_VERSION}}"
    ROOT="{{justfile_directory()}}"
    WORKTREES_DIR="${KEYOS_RELEASES_WORKTREES_DIR:-"$ROOT/.worktrees"}"
    BASE_WT="$WORKTREES_DIR/$BASE_VER"
    NEW_WT="$WORKTREES_DIR/$NEW_VER"

    # Check if base worktree exists
    if [ ! -d "$BASE_WT" ]; then
        echo "ERROR: Worktree not found at $BASE_WT" >&2
        echo "Please run 'just sign $BASE_VER' first to create the worktree" >&2
        exit 1
    fi

    # Check if new worktree exists
    if [ ! -d "$NEW_WT" ]; then
        echo "ERROR: Worktree not found at $NEW_WT" >&2
        echo "Please run 'just sign $NEW_VER' first to create the worktree" >&2
        exit 1
    fi

    # Output name includes both versions with v prefix: KeyOS-v{base}-to-v{new}-Update.tar
    OUTPUT_FILE="$NEW_WT/$NEW_VER/KeyOS-v$BASE_VER-to-v$NEW_VER-Update.tar"

    echo "Creating update tar from $BASE_VER to $NEW_VER"
    cargo run --manifest-path "$ROOT/tools/release-gen/Cargo.toml" -- \
        "$BASE_VER" "$BASE_WT/$BASE_VER" \
        "$NEW_VER" "$NEW_WT/$NEW_VER" \
        --out "$OUTPUT_FILE" \
        {{EXTRA_ARGS}}

# Create a bootable disk image from firmware components (production)
# Default output: KeyOS-v{VERSION}-Factory.img
create-factory-image VERSION:
    #!/usr/bin/env bash
    set -u

    VER="{{VERSION}}"
    ROOT="{{justfile_directory()}}"
    WORKTREES_DIR="${KEYOS_RELEASES_WORKTREES_DIR:-"$ROOT/.worktrees"}"
    WT="$WORKTREES_DIR/$VER"
    OUTPUT="KeyOS-v$VER-Factory.img"
    # Relative path for cleaner output
    REL_WT=".worktrees/$VER"

    mkdir -p "$WORKTREES_DIR"

    # Setup/update worktree using helper function
    source "$ROOT/tools/worktree-helper.sh"
    if ! setup_worktree "$ROOT" "$VER" "$WT"; then
        exit 1
    fi

    if [ ! -d "$WT/$VER" ]; then
        echo "ERROR: Release directory not found: $WT/$VER" >&2
        exit 1
    fi

    echo "Creating disk image for version $VER from worktree: $REL_WT/$VER"
    (cd "$ROOT" && cargo run --manifest-path "tools/image-builder/Cargo.toml" -- --production create-image "$REL_WT/$VER" --output "$REL_WT/$VER/$OUTPUT")
    echo "✅ Image created: $REL_WT/$VER/$OUTPUT"

# Create a bootable disk image from firmware components (development)
# Default output: KeyOS-v{VERSION}-Factory.img
create-image-dev VERSION:
    #!/usr/bin/env bash
    set -u

    VER="{{VERSION}}"
    ROOT="{{justfile_directory()}}"
    WORKTREES_DIR="${KEYOS_RELEASES_WORKTREES_DIR:-"$ROOT/.worktrees"}"
    WT="$WORKTREES_DIR/$VER"
    OUTPUT="KeyOS-v$VER-Factory.img"
    # Relative path for cleaner output
    REL_WT=".worktrees/$VER"

    mkdir -p "$WORKTREES_DIR"

    # Setup/update worktree using helper function
    source "$ROOT/tools/worktree-helper.sh"
    if ! setup_worktree "$ROOT" "$VER" "$WT"; then
        exit 1
    fi

    if [ ! -d "$WT/$VER" ]; then
        echo "ERROR: Release directory not found: $WT/$VER" >&2
        exit 1
    fi

    echo "Creating disk image for version $VER from worktree: $REL_WT/$VER"
    (cd "$ROOT" && cargo run --manifest-path "tools/image-builder/Cargo.toml" -- create-image "$REL_WT/$VER" --output "$REL_WT/$VER/$OUTPUT")
    echo "✅ Image created: $REL_WT/$VER/$OUTPUT"

# Print SHA256 hashes of firmware components
print-hashes VERSION:
    @echo "Printing hashes for version {{VERSION}}"
    cargo run --manifest-path tools/image-builder/Cargo.toml -- print-hashes {{VERSION}}


# Finalize a release: update worktree, create production disk image, and recovery tar
finalize VERSION:
    #!/usr/bin/env bash
    set -u

    VER="{{VERSION}}"
    ROOT="{{justfile_directory()}}"
    WORKTREES_DIR="${KEYOS_RELEASES_WORKTREES_DIR:-"$ROOT/.worktrees"}"
    WT="$WORKTREES_DIR/$VER"

    mkdir -p "$WORKTREES_DIR"

    # Setup/update worktree using helper function
    source "$ROOT/tools/worktree-helper.sh"
    if ! setup_worktree "$ROOT" "$VER" "$WT"; then
        exit 1
    fi

    # Verify the release directory exists in the worktree
    if [ ! -d "$WT/$VER" ]; then
        echo "ERROR: Release directory not found: $WT/$VER" >&2
        exit 1
    fi

    echo "Creating production disk image..."
    (cd "$WT" && just -f "$ROOT/Justfile" create-factory-image "$VER")

    echo "Creating core system recovery tar..."
    (cd "$WT" && just -f "$ROOT/Justfile" create-core-system-recovery-tar "$VER")

    echo "✅ Finalize complete for version $VER"


# Package signable binary files into a zip for sending to another signer
# The output filename depends on current signature status:
#   - 0 signatures: KeyOS-v{version}-unsigned.zip
#   - 1 signature:  KeyOS-v{version}-partially-signed.zip
#   - 2 signatures: No zip created (already fully signed)
# Usage: just make-zip 1.1.0
make-zip VERSION:
    #!/usr/bin/env bash
    set -eu

    VER="{{VERSION}}"
    ROOT="{{justfile_directory()}}"
    WORKTREES_DIR="${KEYOS_RELEASES_WORKTREES_DIR:-"$ROOT/.worktrees"}"
    WT="$WORKTREES_DIR/$VER"

    mkdir -p "$WORKTREES_DIR"

    # Setup/update worktree using helper function
    source "$ROOT/tools/worktree-helper.sh"
    if ! setup_worktree "$ROOT" "$VER" "$WT"; then
        exit 1
    fi

    if [ ! -d "$WT/$VER" ]; then
        echo "ERROR: Release directory not found: $WT/$VER" >&2
        exit 1
    fi

    (cd "$WT" && cargo run --manifest-path "$ROOT/tools/signer/Cargo.toml" -- package "$VER" -o "KeyOS-v$VER.zip")
    echo "Send the zip file to the other signer."

# Unpack a signed zip back into the version folder and commit
# Usage: just push-zip 1.1.0 /path/to/Release-1.1.0-signed.zip
push-zip VERSION ZIP_PATH:
    #!/usr/bin/env bash
    set -eu

    VER="{{VERSION}}"
    ZIP="{{ZIP_PATH}}"
    ROOT="{{justfile_directory()}}"
    WORKTREES_DIR="${KEYOS_RELEASES_WORKTREES_DIR:-"$ROOT/.worktrees"}"
    WT="$WORKTREES_DIR/$VER"

    mkdir -p "$WORKTREES_DIR"

    # Setup/update worktree using helper function
    source "$ROOT/tools/worktree-helper.sh"
    if ! setup_worktree "$ROOT" "$VER" "$WT"; then
        exit 1
    fi

    if [ ! -d "$WT/$VER" ]; then
        echo "ERROR: Release directory not found: $WT/$VER" >&2
        exit 1
    fi

    # Resolve relative path to absolute
    if [[ "$ZIP" != /* ]]; then
        ZIP="$(pwd)/$ZIP"
    fi

    if [ ! -f "$ZIP" ]; then
        echo "ERROR: Zip file not found: $ZIP" >&2
        exit 1
    fi

    echo "Unpacking $ZIP into version $VER..."
    (cd "$WT" && cargo run --manifest-path "$ROOT/tools/signer/Cargo.toml" -- unpack "$VER" "$ZIP")

    # Determine commit message based on signature state after unpacking
    if (cd "$WT" && cargo run --manifest-path "$ROOT/tools/signer/Cargo.toml" -- validate "$VER" --files-only) >/dev/null 2>&1; then
        MSG="Second signatures applied from zip"
    else
        MSG="First signatures applied from zip"
    fi

    # Commit the changes
    git -C "$WT" add -A "$VER"
    if git -C "$WT" diff --cached --quiet -- "$VER"; then
        echo "No changes detected; nothing to commit."
    else
        git -C "$WT" commit -m "$MSG"
        if git -C "$WT" rev-parse --abbrev-ref --symbolic-full-name @{u} >/dev/null 2>&1; then
            git -C "$WT" push
        else
            git -C "$WT" push -u origin "refs/heads/$VER"
        fi
        echo "✅ $MSG"
    fi

# Build the signer binary for x86_64 Linux (Chromebook)
# Produces a static musl binary that runs on any x86_64 Linux
build-chromebook-signer:
    #!/usr/bin/env bash
    set -eu

    ROOT="{{justfile_directory()}}"
    TARGET="x86_64-unknown-linux-musl"
    LINKER="x86_64-linux-musl-gcc"

    echo "Building signer for Chromebook (x86_64 Linux)..."
    echo ""

    # Check for rustup target
    if ! rustup target list --installed | grep -q "$TARGET"; then
        echo "ERROR: Rust target '$TARGET' is not installed." >&2
        echo "" >&2
        echo "Install it with:" >&2
        echo "  rustup target add $TARGET" >&2
        echo "" >&2
        exit 1
    fi

    # Check for musl-cross linker
    if ! command -v "$LINKER" &>/dev/null; then
        echo "ERROR: musl-cross linker '$LINKER' is not installed." >&2
        echo "" >&2
        echo "Install it with:" >&2
        echo "  brew install filosottile/musl-cross/musl-cross" >&2
        echo "" >&2
        exit 1
    fi

    echo "✓ Rust target '$TARGET' is installed"
    echo "✓ musl-cross linker '$LINKER' is installed"
    echo ""

    # Build the signer
    CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER="$LINKER" \
        cargo build --release -p signer --target "$TARGET"

    OUTPUT="$ROOT/target/$TARGET/release/signer"
    if [ -f "$OUTPUT" ]; then
        SIZE=$(du -h "$OUTPUT" | cut -f1)
        echo ""
        echo "✅ Build complete!"
        echo ""
        echo "Binary: $OUTPUT"
        echo "Size:   $SIZE"
        echo ""
        echo "Copy this file to your Chromebook along with cosign2."
    else
        echo "ERROR: Build failed - output binary not found" >&2
        exit 1
    fi

# NUCLEAR OPTION: Completely remove a release version (branches, tags, worktrees)
# Usage: just nuke-release 1.1.0 (or just remove-release 1.1.0)
# WARNING: This is destructive and cannot be undone!
nuke-release VERSION:
    #!/usr/bin/env bash
    set -u
    VER="{{VERSION}}"
    ROOT="{{justfile_directory()}}"
    WORKTREES_DIR="${KEYOS_RELEASES_WORKTREES_DIR:-$ROOT/.worktrees}"
    WT="$WORKTREES_DIR/$VER"

    echo ""
    echo "========================================================================"
    echo "                    WARNING: NUCLEAR OPTION"
    echo "========================================================================"
    echo ""
    echo "  This will PERMANENTLY DELETE the following for version $VER:"
    echo ""
    echo "    - All worktrees for $VER"
    echo "    - Local branch refs/heads/$VER"
    echo "    - Remote branch origin/$VER"
    echo "    - Local tag refs/tags/$VER"
    echo "    - Remote tag origin/$VER"
    echo ""
    echo "  THIS CANNOT BE UNDONE!"
    echo ""
    echo "========================================================================"
    echo ""
    read -p "Are you sure you want to nuke release $VER? (yes/no): " CONFIRM1
    if [ "$CONFIRM1" != "yes" ]; then echo "Aborted."; exit 1; fi

    echo ""
    read -p "Type the version number '$VER' to confirm: " CONFIRM2
    if [ "$CONFIRM2" != "$VER" ]; then echo "Version mismatch. Aborted."; exit 1; fi

    echo ""
    echo "Proceeding with nuclear removal of release $VER..."
    echo ""

    # Fetch latest from remote
    echo "Fetching latest from remote..."
    git -C "$ROOT" fetch --all --prune || true

    # Find and remove ALL worktrees for this version
    echo "Searching for all worktrees for version $VER..."
    WORKTREE_LIST=$(git -C "$ROOT" worktree list --porcelain 2>/dev/null || true)
    if [ -n "$WORKTREE_LIST" ]; then
        echo "$WORKTREE_LIST" | while IFS= read -r line; do
            if [[ "$line" =~ ^worktree\ (.+)$ ]]; then
                CURRENT_WT="${BASH_REMATCH[1]}"
            elif [[ "$line" =~ ^branch\ refs/heads/(.+)$ ]]; then
                CURRENT_BRANCH="${BASH_REMATCH[1]}"
                if [ "$CURRENT_BRANCH" = "$VER" ]; then
                    echo "  Found worktree at $CURRENT_WT (branch: $CURRENT_BRANCH)"
                    # Check if we're currently in this worktree
                    if [ "$(pwd)" = "$CURRENT_WT" ] || [[ "$(pwd)" == "$CURRENT_WT"/* ]]; then
                        echo "  WARNING: You are currently in this worktree!"
                        echo "  Switching to main branch in main repository..."
                        cd "$ROOT"
                        git -C "$ROOT" checkout main 2>/dev/null || git -C "$ROOT" checkout master 2>/dev/null || true
                    fi
                    echo "  Removing worktree at $CURRENT_WT..."
                    git -C "$ROOT" worktree remove --force "$CURRENT_WT" 2>/dev/null || rm -rf "$CURRENT_WT" 2>/dev/null || true
                fi
            fi
        done
    fi

    # Also check the default worktree location
    if [ -d "$WT" ]; then
        echo "Removing worktree at $WT..."
        git -C "$ROOT" worktree remove --force "$WT" 2>/dev/null || rm -rf "$WT" 2>/dev/null || true
    fi

    # Prune stale worktree references
    git -C "$ROOT" worktree prune 2>/dev/null || true

    # Delete local branch using explicit refs/heads/ prefix
    if git -C "$ROOT" rev-parse --verify "refs/heads/$VER" >/dev/null 2>&1; then
        echo "Deleting local branch refs/heads/$VER..."
        git -C "$ROOT" branch -D "$VER"
    else
        echo "No local branch refs/heads/$VER found"
    fi

    # Delete remote branch using explicit refs/heads/ prefix
    if git -C "$ROOT" ls-remote --exit-code --heads origin "$VER" >/dev/null 2>&1; then
        echo "Deleting remote branch origin/$VER..."
        git -C "$ROOT" -c core.hooksPath=/dev/null push origin --delete "refs/heads/$VER" 2>/dev/null || true
    else
        echo "No remote branch origin/$VER found"
    fi

    # Delete local tag using explicit refs/tags/ prefix
    if git -C "$ROOT" rev-parse --verify "refs/tags/$VER" >/dev/null 2>&1; then
        echo "Deleting local tag refs/tags/$VER..."
        git -C "$ROOT" tag -d "$VER"
    else
        echo "No local tag refs/tags/$VER found"
    fi

    # Delete remote tag using explicit refs/tags/ prefix
    if git -C "$ROOT" ls-remote --exit-code --tags origin "$VER" >/dev/null 2>&1; then
        echo "Deleting remote tag origin/$VER..."
        git -C "$ROOT" -c core.hooksPath=/dev/null push origin --delete "refs/tags/$VER" 2>/dev/null || true
    else
        echo "No remote tag origin/$VER found"
    fi

    echo ""
    echo "========================================================================"
    echo "  ☢️  Release $VER has been completely nuked  ☢️"
    echo "========================================================================"
    echo ""

# Alias for nuke-release (for backwards compatibility)
remove-release VERSION:
    @just nuke-release {{VERSION}}
