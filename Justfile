# SPDX-FileCopyrightText: © 2025  Foundation Devices, Inc. <hello@foundation.xyz>
# SPDX-License-Identifier: GPL-3.0-or-later

# Sign individual files with the provided key (uses a dedicated git worktree to avoid switching your current branch)
sign VERSION CONFIG_PATH=env_var_or_default("COSIGN_TOML_PATH", "~/cosign2.toml"):
    #!/usr/bin/env bash
    set -euo pipefail

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

    # Ensure the release branch exists locally
    if ! git -C "$ROOT" rev-parse --verify "$VER" >/dev/null 2>&1; then
        echo "ERROR: Branch '$VER' not found" >&2
        exit 1
    fi

    # Prepare/update a dedicated worktree for this version
    git -C "$ROOT" fetch --all --prune
    if git -C "$WT" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
        :
    elif [ -e "$WT" ]; then
        echo "ERROR: Worktree path exists but is not a git worktree: $WT" >&2
        exit 1
    else
        git -C "$ROOT" worktree add "$WT" "$VER"
    fi
    git -C "$WT" pull --rebase

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
    if git -C "$WT" rev-parse --abbrev-ref --symbolic-full-name @{u} >/dev/null 2>&1; then
        git -C "$WT" push
    else
        git -C "$WT" push -u origin "$VER"
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


# Revert signing commits for a version and remove its worktree (full reset)
unsign VERSION:
    #!/usr/bin/env bash
    set -euo pipefail

    VER="{{VERSION}}"
    ROOT="{{justfile_directory()}}"
    WORKTREES_DIR="${KEYOS_RELEASES_WORKTREES_DIR:-"$ROOT/.worktrees"}"
    WT="$WORKTREES_DIR/$VER"

    echo "Unsigning version $VER: reverting signing commits and removing worktree"

    # Ensure the release branch exists
    if ! git -C "$ROOT" rev-parse --verify "$VER" >/dev/null 2>&1; then
        echo "ERROR: Branch '$VER' not found" >&2
        exit 1
    fi

    mkdir -p "$WORKTREES_DIR"
    CREATED_WT=0
    if git -C "$WT" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
        :
    else
        if [ -e "$WT" ]; then
            echo "ERROR: Worktree path exists but is not a git worktree: $WT" >&2
            exit 1
        fi
        git -C "$ROOT" worktree add "$WT" "$VER"
        CREATED_WT=1
    fi

    # Make sure worktree is up-to-date
    git -C "$WT" fetch --all --prune || true
    git -C "$WT" pull --rebase || true

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
        if git -C "$WT" rev-parse --abbrev-ref --symbolic-full-name @{u} >/dev/null 2>&1; then
            git -C "$WT" push
        else
            git -C "$WT" push -u origin "$VER"
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

# Validate that all files for a version are properly signed
validate VERSION:
    @echo "Validating signatures for version {{VERSION}}..."
    cargo run --manifest-path tools/signer/Cargo.toml -- validate {{VERSION}}

# Generate a new release.tar between two versions
release-gen *args:
    cargo run --manifest-path tools/release-gen/Cargo.toml -- {{args}}

# Create a bootable disk image from firmware components (production)
create-image VERSION OUTPUT="boot.img":
    #!/usr/bin/env bash
    set -euo pipefail

    VER="{{VERSION}}"
    ROOT="{{justfile_directory()}}"
    WORKTREES_DIR="${KEYOS_RELEASES_WORKTREES_DIR:-"$ROOT/.worktrees"}"
    WT="$WORKTREES_DIR/$VER"

    # Determine the folder that contains the version's files
    VERSION_FOLDER="$VER"
    if [ -d "$WT/$VER" ]; then
        VERSION_FOLDER="$WT/$VER"
    fi

    echo "Creating disk image for version $VER (folder: $VERSION_FOLDER)"
    cargo run --manifest-path "$ROOT/tools/image-builder/Cargo.toml" -- --production create-image "$VERSION_FOLDER" --output "{{OUTPUT}}"

# Create a bootable disk image from firmware components (development)
create-image-dev VERSION OUTPUT="boot.img":
    #!/usr/bin/env bash
    set -euo pipefail

    VER="{{VERSION}}"
    ROOT="{{justfile_directory()}}"
    WORKTREES_DIR="${KEYOS_RELEASES_WORKTREES_DIR:-"$ROOT/.worktrees"}"
    WT="$WORKTREES_DIR/$VER"

    VERSION_FOLDER="$VER"
    if [ -d "$WT/$VER" ]; then
        VERSION_FOLDER="$WT/$VER"
    fi

    echo "Creating disk image for version $VER (folder: $VERSION_FOLDER)"
    cargo run --manifest-path "$ROOT/tools/image-builder/Cargo.toml" -- create-image "$VERSION_FOLDER" --output "{{OUTPUT}}"

# Print SHA256 hashes of firmware components
print-hashes VERSION:
    @echo "Printing hashes for version {{VERSION}}"
    cargo run --manifest-path tools/image-builder/Cargo.toml -- print-hashes {{VERSION}}


# Finalize a release: update worktree, create production disk image, and recovery tar
finalize VERSION:
    #!/usr/bin/env bash
    set -euo pipefail

    VER="{{VERSION}}"
    ROOT="{{justfile_directory()}}"
    WORKTREES_DIR="${KEYOS_RELEASES_WORKTREES_DIR:-"$ROOT/.worktrees"}"
    WT="$WORKTREES_DIR/$VER"

    mkdir -p "$WORKTREES_DIR"

    # Ensure the release branch exists locally
    if ! git -C "$ROOT" rev-parse --verify "$VER" >/dev/null 2>&1; then
        echo "ERROR: Branch '$VER' not found" >&2
        exit 1
    fi

    echo "Preparing worktree for $VER"
    git -C "$ROOT" fetch --all --prune
    if git -C "$WT" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
        :
    elif [ -e "$WT" ]; then
        echo "ERROR: Worktree path exists but is not a git worktree: $WT" >&2
        exit 1
    else
        git -C "$ROOT" worktree add "$WT" "$VER"
    fi
    git -C "$WT" pull --rebase || true

    # Verify the release directory exists in the worktree
    if [ ! -d "$WT/$VER" ]; then
        echo "ERROR: Release directory not found: $WT/$VER" >&2
        exit 1
    fi

    echo "Creating production disk image..."
    (cd "$WT" && just -f "$ROOT/Justfile" create-image "$VER")

    echo "Creating recovery tar..."
    (cd "$WT" && just -f "$ROOT/Justfile" create-recovery-tar "$VER")

    echo "✅ Finalize complete for version $VER"


# Sign bootloader (boot.bin) with Atmel/Microchip SAM-BA cipher using provided secrets directory
# Usage: just sign-bl 1.0.0 ~/secrets
# Requires: SECURE_SAMBA_CIPHER_PATH env var pointing to secure-sam-ba-cipher.py
# Optional: SECURE_SAMBA_PYTHON to choose interpreter; otherwise auto-detects venv near the tool or falls back to python3
sign-bl VERSION SECRETS_DIR:
    #!/usr/bin/env bash
    set -euo pipefail

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

    # Ensure the release branch exists locally
    if ! git -C "$ROOT" rev-parse --verify "$VER" >/dev/null 2>&1; then
        echo "ERROR: Branch '$VER' not found" >&2
        exit 1
    fi

    # Prepare/update a dedicated worktree for this version
    mkdir -p "$WORKTREES_DIR"
    git -C "$ROOT" fetch --all --prune
    if git -C "$WT" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
        echo "Updating existing worktree at $WT to origin/$VER..."
        # Ensure we're on the correct branch name locally
        git -C "$WT" checkout -B "$VER" || true
    elif [ -e "$WT" ]; then
        echo "ERROR: Worktree path exists but is not a git worktree: $WT" >&2
        exit 1
    else
        git -C "$ROOT" worktree add "$WT" "$VER"
    fi
    # Force sync with latest remote state (handles force-pushes)
    git -C "$WT" fetch --all --prune || true
    git -C "$WT" reset --hard "origin/$VER"
    git -C "$WT" clean -fdx

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
