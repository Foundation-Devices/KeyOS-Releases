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
    (cd "$NEW_WT" && cargo run --manifest-path "$ROOT/tools/signer/Cargo.toml" -- create-recovery-tar "$NEW_VER" --core-system-recovery)
    echo ""

    # Step 3: Create recovery tar
    echo "Step 3/5: Creating recovery tar..."
    (cd "$NEW_WT" && cargo run --manifest-path "$ROOT/tools/signer/Cargo.toml" -- create-recovery-tar "$NEW_VER")
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
    echo "   Core system recovery: $NEW_WT/$NEW_VER/KeyOS-v$NEW_VER-CoreSystemRecovery.tar"
    echo "   Recovery tar: $NEW_WT/$NEW_VER/KeyOS-v$NEW_VER-Recovery.tar"
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
create-recovery-tar VERSION:
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

    echo "Creating recovery tar file for version $VER"
    (cd "$WT" && cargo run --manifest-path "$ROOT/tools/signer/Cargo.toml" -- create-recovery-tar "$VER")


# Create core system recovery tar (includes bootloader and recovery OS)
create-core-system-recovery-tar VERSION:
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

    echo "Creating core system recovery tar file for version $VER"
    (cd "$WT" && cargo run --manifest-path "$ROOT/tools/signer/Cargo.toml" -- create-recovery-tar "$VER" --core-system-recovery)

# Create core system recovery tar for development (allows one signature)
create-core-system-recovery-tar-dev VERSION:
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

    echo "Creating core system recovery tar file for version $VER (one signature)"
    (cd "$WT" && cargo run --manifest-path "$ROOT/tools/signer/Cargo.toml" -- create-recovery-tar "$VER" --core-system-recovery --allow-one-signature)


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


# Sign bootloader (boot.bin) with Atmel/Microchip SAM-BA cipher using provided secrets directory
# Usage: just sign-bl 1.0.0 ~/secrets
# Requires: SECURE_SAMBA_CIPHER_PATH env var pointing to secure-sam-ba-cipher.py
# Optional: SECURE_SAMBA_PYTHON to choose interpreter; otherwise auto-detects venv near the tool or falls back to python3
sign-bl VERSION SECRETS_DIR:
    #!/usr/bin/env bash
    set -u

    VER="{{VERSION}}"
    SEC_DIR_RAW="{{SECRETS_DIR}}"
    ROOT="{{justfile_directory()}}"
    WORKTREES_DIR="${KEYOS_RELEASES_WORKTREES_DIR:-"$ROOT/.worktrees"}"
    WT="$WORKTREES_DIR/$VER"

    # Expand ~ in secrets dir path if present
    SEC_DIR="$SEC_DIR_RAW"
    if [[ "$SEC_DIR" == "~/"* ]]; then
        SEC_DIR="$HOME/${SEC_DIR#~/}"
    fi

    # Locate secure-sam-ba-cipher script from env var and expand ~
    if [ -z "${SECURE_SAMBA_CIPHER_PATH:-}" ]; then
        echo "ERROR: SECURE_SAMBA_CIPHER_PATH is not set. Set it to the path of secure-sam-ba-cipher.py" >&2
        exit 1
    fi
    SAMBA="$SECURE_SAMBA_CIPHER_PATH"
    if [[ "$SAMBA" == "~/"* ]]; then
        SAMBA="$HOME/${SAMBA#~/}"
    fi
    if [ ! -f "$SAMBA" ]; then
        echo "ERROR: secure-sam-ba-cipher.py not found at: $SAMBA" >&2
        exit 1
    fi

    # Determine Python interpreter for SAM-BA tool
    if [ -n "${SECURE_SAMBA_PYTHON:-}" ]; then
        PY="$SECURE_SAMBA_PYTHON"
        if [[ "$PY" == "~/"* ]]; then
            PY="$HOME/${PY#~/}"
        fi
        if [ ! -x "$PY" ]; then
            echo "ERROR: SECURE_SAMBA_PYTHON is set but not executable: $PY" >&2
            exit 1
        fi
    else
        SAMBA_DIR="$(cd "$(dirname "$SAMBA")" && pwd)"
        PY=""
        if [ -x "$SAMBA_DIR/venv/bin/python" ]; then
            PY="$SAMBA_DIR/venv/bin/python"
        elif [ -x "$SAMBA_DIR/.venv/bin/python" ]; then
            PY="$SAMBA_DIR/.venv/bin/python"
        else
            PY="$(command -v python3 || true)"
        fi
        if [ -z "$PY" ]; then
            echo "ERROR: Could not locate a Python interpreter. Set SECURE_SAMBA_PYTHON or ensure python3 is available." >&2
            exit 1
        fi
    fi
    echo "Using Python interpreter: $PY"


    if [ ! -d "$SEC_DIR" ]; then
        echo "ERROR: Secrets directory not found: $SEC_DIR" >&2
        exit 1
    fi

    ACT="$SEC_DIR/sam-ba-license-activation.txt"
    CUST="$SEC_DIR/cust.key"

    for f in "$ACT" "$CUST"; do
        if [ ! -f "$f" ]; then
            echo "ERROR: Missing required secrets file: $f" >&2
            exit 1
        fi
    done

    # Setup/update worktree using helper function (force reset mode)
    source "$ROOT/tools/worktree-helper.sh"
    if ! setup_worktree_force_reset "$ROOT" "$VER" "$WT"; then
        exit 1
    fi

    # Verify the release directory exists and boot.bin is present
    if [ ! -d "$WT/$VER" ]; then
        echo "ERROR: Release directory not found: $WT/$VER" >&2
        exit 1
    fi

    BOOT_IN="$WT/$VER/boot.bin"
    if [ ! -f "$BOOT_IN" ]; then
        echo "ERROR: boot.bin not found in $WT/$VER" >&2
        exit 1
    fi

    echo "Signing bootloader for version $VER using secrets at $SEC_DIR"
    echo "Working directory: $WT/$VER"
    echo "SAM-BA tool: $SAMBA"
    echo "Python interpreter: $PY"
    "$PY" -V 2>&1 || true

    # Quick, non-secret file size checks
    echo "Input file sizes (bytes):"
    wc -c "$BOOT_IN" "$CUST" "$ACT" 2>/dev/null || true

    # Build exact command as an array for reliability
    CMD=("$PY" "$SAMBA" bootstrap -d sama5d2x -l "$ACT" -k "$CUST" -i "$BOOT_IN" -o boot.cip)

    # Print an exact, copy/pastable command line the user can run manually
    printf 'Manual repro:\n  cd %q && ' "$WT/$VER"
    printf '%q ' "${CMD[@]}"
    echo

    # Ensure unbuffered Python so logs are flushed immediately
    export PYTHONUNBUFFERED=1

    # Execute the command with tee to capture a log file, preserving original exit code
    status=0
    (
      cd "$WT/$VER"
      ( "${CMD[@]}" ) 2>&1 | tee samba.log
      exit "${PIPESTATUS[0]}"
    ) || status=$?
    echo "Command exit code: $status"
    if [ "$status" -ne 0 ]; then
        echo "---- Last 50 lines of $WT/$VER/samba.log ----"
        tail -n 50 "$WT/$VER/samba.log" || true
        echo "--------------------------------------------"
        exit "$status"
    fi

    # Normalize device-specific output (e.g., boot_sama5d2x.cip) to boot.cip
    if [ ! -f "$WT/$VER/boot.cip" ]; then
        if [ -f "$WT/$VER/boot_sama5d2x.cip" ]; then
            mv -f "$WT/$VER/boot_sama5d2x.cip" "$WT/$VER/boot.cip"
        else
            CAND="$(ls -1 "$WT/$VER"/boot_*.cip 2>/dev/null | head -n1 || true)"
            if [ -n "$CAND" ]; then
                mv -f "$CAND" "$WT/$VER/boot.cip"
            fi
        fi
    fi
    if [ -f "$WT/$VER/boot.cip" ]; then
        echo "✅ boot.cip created: $WT/$VER/boot.cip"
    else
        echo "ERROR: boot.cip was not created" >&2
        ls -l "$WT/$VER"/*.cip 2>/dev/null || true
        exit 1
    fi

    # Stage and commit the signed bootloader changes within the worktree
    git -C "$WT" add -A "$VER"
    if git -C "$WT" diff --cached --quiet -- "$VER"; then
        echo "No changes detected in $VER; aborting commit." >&2
        exit 1
    fi

    MSG="Bootloader signed and pushed"
    git -C "$WT" commit -m "$MSG"
    # Push to upstream or set it if missing
    # Use refs/heads/ prefix to explicitly push to the branch, not a tag
    if git -C "$WT" rev-parse --abbrev-ref --symbolic-full-name @{u} >/dev/null 2>&1; then
        git -C "$WT" push
    else
        git -C "$WT" push -u origin "refs/heads/$VER"
    fi

    echo "✅ $MSG"
