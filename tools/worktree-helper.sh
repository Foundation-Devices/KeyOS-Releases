#!/usr/bin/env bash
# SPDX-FileCopyrightText: © 2025  Foundation Devices, Inc. <hello@foundation.xyz>
# SPDX-License-Identifier: GPL-3.0-or-later

# Helper script for managing git worktrees in KeyOS-Releases
# This script provides a common function to set up and update worktrees

# Setup or update a worktree for a given version
# Usage: setup_worktree <ROOT> <VER> <WT> [CREATED_WT_VAR]
#   ROOT: Repository root directory
#   VER:  Version/branch name (e.g., "1.0.0")
#   WT:   Worktree path (e.g., ".worktrees/1.0.0")
#   CREATED_WT_VAR: Optional variable name to set to 1 if worktree was created, 0 if existed
#
# Behavior:
#   - If worktree doesn't exist: creates it
#   - If worktree exists with no changes: updates it (git pull)
#   - If worktree exists with changes: prompts user to continue or abort
setup_worktree() {
    local ROOT="$1"
    local VER="$2"
    local WT="$3"
    local CREATED_WT_VAR="${4:-}"  # Optional: variable name to export creation status

    # Ensure the release branch exists locally
    # Use refs/heads/ prefix to check specifically for LOCAL branches.
    # Without this, git rev-parse would match tags with the same name,
    # causing "refname is ambiguous" warnings.
    if ! git -C "$ROOT" rev-parse --verify "refs/heads/$VER" >/dev/null 2>&1; then
        echo "ERROR: Branch '$VER' not found" >&2
        return 1
    fi

    # Fetch latest from remote
    echo "Fetching latest changes from remote..."
    git -C "$ROOT" fetch --all --prune

    # Check if worktree exists
    if git -C "$WT" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
        # Worktree exists - check for uncommitted changes
        echo "Worktree exists at: $WT"
        [ -n "$CREATED_WT_VAR" ] && eval "$CREATED_WT_VAR=0"

        if [ -n "$(git -C "$WT" status --porcelain)" ]; then
            # Has uncommitted changes
            echo ""
            echo "WARNING: Worktree has uncommitted changes:"
            git -C "$WT" status --short
            echo ""
            read -p "Continue with existing files? (y/n) " -n 1 -r
            echo
            if [[ ! $REPLY =~ ^[Yy]$ ]]; then
                echo "Aborted. Please commit or stash your changes, then try again."
                return 1
            fi
            echo "Continuing with existing files (not updating from remote)..."
        else
            # No uncommitted changes - safe to update
            echo "Updating worktree to latest..."
            # Ensure we're on the branch (not detached HEAD) before pulling
            # Use refs/heads/ prefix to explicitly refer to the branch, not a tag
            git -C "$WT" checkout -B "$VER" "refs/heads/$VER" >/dev/null 2>&1 || true
            if git -C "$WT" pull --rebase; then
                echo "Worktree updated successfully"
            else
                echo "ERROR: Failed to update worktree" >&2
                return 1
            fi
        fi
    elif [ -e "$WT" ]; then
        # Path exists but is not a git worktree
        echo "ERROR: Worktree path exists but is not a git worktree: $WT" >&2
        return 1
    else
        # Worktree doesn't exist - create it
        echo "Creating worktree at: $WT"
        [ -n "$CREATED_WT_VAR" ] && eval "$CREATED_WT_VAR=1"
        # Use -B flag to explicitly checkout the branch by name, avoiding ambiguity with tags
        # This ensures we're on the branch, not in detached HEAD state
        # -B will create or reset the branch to point at the specified commit
        if git -C "$ROOT" worktree add -B "$VER" "$WT" "refs/heads/$VER"; then
            echo "Worktree created successfully"
        else
            echo "ERROR: Failed to create worktree" >&2
            return 1
        fi
    fi

    return 0
}

# Setup or update a worktree with force reset to remote
# Usage: setup_worktree_force_reset <ROOT> <VER> <WT>
#   ROOT: Repository root directory
#   VER:  Version/branch name (e.g., "1.0.0")
#   WT:   Worktree path (e.g., ".worktrees/1.0.0")
#
# Behavior:
#   - If worktree doesn't exist: creates it
#   - If worktree exists: force resets to origin/$VER (handles force-pushes)
#   - Always cleans untracked files
setup_worktree_force_reset() {
    local ROOT="$1"
    local VER="$2"
    local WT="$3"

    # Ensure the release branch exists locally
    # Use refs/heads/ prefix to check specifically for LOCAL branches.
    # Without this, git rev-parse would match tags with the same name,
    # causing "refname is ambiguous" warnings.
    if ! git -C "$ROOT" rev-parse --verify "refs/heads/$VER" >/dev/null 2>&1; then
        echo "ERROR: Branch '$VER' not found" >&2
        return 1
    fi

    # Fetch latest from remote
    echo "Fetching latest changes from remote..."
    git -C "$ROOT" fetch --all --prune

    # Check if worktree exists
    if git -C "$WT" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
        echo "Updating existing worktree at $WT to origin/$VER..."
        # Ensure we're on the correct branch name locally
        # Use refs/heads/ prefix to explicitly refer to the branch, not a tag
        git -C "$WT" checkout -B "$VER" "refs/heads/$VER" || true
    elif [ -e "$WT" ]; then
        echo "ERROR: Worktree path exists but is not a git worktree: $WT" >&2
        return 1
    else
        echo "Creating worktree at: $WT"
        # Use -B flag to explicitly checkout the branch by name, avoiding ambiguity with tags
        # This ensures we're on the branch, not in detached HEAD state
        if ! git -C "$ROOT" worktree add -B "$VER" "$WT" "refs/heads/$VER"; then
            echo "ERROR: Failed to create worktree" >&2
            return 1
        fi
    fi

    # Force sync with latest remote state (handles force-pushes)
    echo "Force resetting to origin/$VER..."
    git -C "$WT" fetch --all --prune || true
    git -C "$WT" reset --hard "origin/$VER"
    git -C "$WT" clean -fdx

    return 0
}

