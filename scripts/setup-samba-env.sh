#!/bin/bash

# SPDX-FileCopyrightText: 2024 Foundation Devices, Inc. <hello@foundation.xyz>
# SPDX-License-Identifier: GPL-3.0-or-later

# Set SAM-BA environment variables from FINAL-SECRETS directory
# Usage: source scripts/setup-samba-env.sh

# set -uo pipefail

# Get the directory where this script is located (works in both bash and zsh)
if [[ -n "${BASH_SOURCE[0]:-}" ]]; then
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
elif [[ -n "${(%):-%x}" ]]; then
    # zsh
    SCRIPT_DIR="$(cd "$(dirname "${(%):-%x}")" && pwd)"
else
    # Fallback: assume we're in the scripts directory
    SCRIPT_DIR="$(pwd)"
fi

SAMBA_SECRETS_DIR="/Users/kenc/FINAL-SECRETS/SAM-BA"
PROVISIONING_DIR="/Users/kenc/FINAL-SECRETS/provisioning"
# Store venv locally in the scripts directory
VENV_DIR="$SCRIPT_DIR/secure-sam-ba-cipher-3.7/venv"

# Check if required files exist
missing_files=()

# Required: Path to sam-ba-cipher tool
SAMBA_CIPHER_TOOL="/Users/kenc/secure-sam-ba-cipher-3.7/secure-sam-ba-cipher.py"
if [[ ! -f "$SAMBA_CIPHER_TOOL" ]]; then
    missing_files+=("$SAMBA_CIPHER_TOOL")
fi
export SAMBA_CIPHER_TOOL

# SAM-BA files from your secrets directory
SAMBA_CUSTOMER_KEY="$SAMBA_SECRETS_DIR/cust.key"
SAMBA_CIPHER_LICENSE="$SAMBA_SECRETS_DIR/sam-ba-license-activation.txt"
SAMBA_CIPHER_LICENSE_KEY="$SAMBA_SECRETS_DIR/sam-ba-license-request-private-key.pem"
SAMBA_PASSWORD_FILE="$SAMBA_SECRETS_DIR/sam-ba-license-passphrase.txt"
EXTRA_ENTROPY_FILE="$PROVISIONING_DIR/extra-entropy.hex"

# Check if SAM-BA files exist
for file in "$SAMBA_CUSTOMER_KEY" "$SAMBA_CIPHER_LICENSE" "$SAMBA_CIPHER_LICENSE_KEY" "$SAMBA_PASSWORD_FILE" "$EXTRA_ENTROPY_FILE"; do
    if [[ ! -f "$file" ]]; then
        missing_files+=("$file")
    fi
done

# Export SAM-BA environment variables
export SAMBA_CUSTOMER_KEY
export SAMBA_CIPHER_LICENSE
export SAMBA_CIPHER_LICENSE_KEY
export SAMBA_PASSWORD_FILE

# Read and export EXTRA_ENTROPY from file
if [[ -f "$EXTRA_ENTROPY_FILE" ]]; then
    export EXTRA_ENTROPY=$(cat "$EXTRA_ENTROPY_FILE" | tr -d '\n\r ')
else
    missing_files+=("$EXTRA_ENTROPY_FILE")
fi

# Check for missing files and warn
if [[ ${#missing_files[@]} -gt 0 ]]; then
    echo "WARNING: The following required files are missing:"
    for file in "${missing_files[@]}"; do
        echo "  - $file"
    done
    echo ""
    echo "Factory releases will not work until these files are available."
    echo ""
fi

echo "SAM-BA environment variables set:"
echo "SAMBA_CIPHER_TOOL=<set>"
echo "SAMBA_CUSTOMER_KEY=<set>"
echo "SAMBA_CIPHER_LICENSE=<set>"
echo "SAMBA_CIPHER_LICENSE_KEY=<set>"
echo "SAMBA_PASSWORD_FILE=<set>"

if [[ -n "${EXTRA_ENTROPY:-}" ]]; then
    echo "EXTRA_ENTROPY=<set>"
    echo ""

    # Setup virtual environment for SAM-BA cipher tool
    if [[ -f "$SAMBA_CIPHER_TOOL" ]]; then
        echo "Setting up SAM-BA cipher tool environment..."

        # Get the directory where the actual tool is located
        SAMBA_TOOL_DIR="$(dirname "$SAMBA_CIPHER_TOOL")"

        # Create virtual environment if it doesn't exist
        if [[ ! -d "$VENV_DIR" ]]; then
            echo "Creating Python virtual environment at $VENV_DIR..."
            mkdir -p "$(dirname "$VENV_DIR")"
            python3 -m venv "$VENV_DIR"
            echo "Upgrading pip..."
            "$VENV_DIR/bin/pip" install -q --upgrade pip
        fi

        # Always install/update dependencies
        if [[ -f "$SAMBA_TOOL_DIR/requirements.txt" ]]; then
            echo "Installing/updating dependencies from requirements.txt..."
            "$VENV_DIR/bin/pip" install -q -r "$SAMBA_TOOL_DIR/requirements.txt"
        else
            echo "No requirements.txt found. Installing common dependencies..."
            "$VENV_DIR/bin/pip" install -q pycryptodome pyOpenSSL
        fi

        # Test the tool with virtual environment
        # Need to cd to the tool directory so it can find its local modules
        if (cd "$SAMBA_TOOL_DIR" && "$VENV_DIR/bin/python" "$(basename "$SAMBA_CIPHER_TOOL")" --help) >/dev/null 2>&1; then
            echo "SAM-BA cipher tool is working with virtual environment."
            # Export the venv python path for xtask to use
            export SAMBA_PYTHON="$VENV_DIR/bin/python"
        else
            echo "WARNING: SAM-BA cipher tool failed test with virtual environment."
            echo "Trying to debug the issue..."
            (cd "$SAMBA_TOOL_DIR" && "$VENV_DIR/bin/python" "$(basename "$SAMBA_CIPHER_TOOL")" --help)
        fi
    fi

    # Add ARM toolchain to PATH if not already present
    ARM_TOOLCHAIN_PATH="/Applications/ArmGNUToolchain/13.2.Rel1/arm-none-eabi/bin"
    if [[ -d "$ARM_TOOLCHAIN_PATH" ]] && [[ ":$PATH:" != *":$ARM_TOOLCHAIN_PATH:"* ]]; then
        export PATH="$ARM_TOOLCHAIN_PATH:$PATH"
        echo "Added ARM toolchain to PATH: $ARM_TOOLCHAIN_PATH"
    fi

    echo "All environment variables set. Ready for factory releases!"
else
    echo ""
    echo "EXTRA_ENTROPY could not be loaded from $EXTRA_ENTROPY_FILE"
fi
