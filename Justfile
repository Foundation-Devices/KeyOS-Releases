# SPDX-FileCopyrightText: © 2025  Foundation Devices, Inc. <hello@foundation.xyz>
# SPDX-License-Identifier: GPL-3.0-or-later

# Sign individual files with the provided key
sign VERSION CONFIG_PATH=env_var_or_default("COSIGN_TOML_PATH", "~/cosign2.toml"):
    @echo "Signing all files for version {{VERSION}} with config {{CONFIG_PATH}}"
    cargo run --manifest-path tools/signer/Cargo.toml -- sign-files {{VERSION}} {{CONFIG_PATH}}

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
    git checkout -- v{{VERSION}}/app.bin
    @echo "Resetting app files..."
    git checkout -- v{{VERSION}}/apps/*.elf
    @echo "Removing tar file if it exists..."
    rm -f v{{VERSION}}/KeyOS-v{{VERSION}}.tar
    @echo "Removing manifest file if it exists..."
    rm -f v{{VERSION}}/manifest.json
    @echo "✓ All files have been reset to their unsigned state"

# Validate that all files for a version are properly signed
validate VERSION:
    @echo "Validating signatures for version {{VERSION}}..."
    cargo run --manifest-path tools/signer/Cargo.toml -- validate {{VERSION}}

# Generate a new release.tar between two versions
release-gen *args:
    cargo run --manifest-path tools/release-gen/Cargo.toml -- {{args}}
