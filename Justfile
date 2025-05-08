# SPDX-FileCopyrightText: © 2025  Foundation Devices, Inc. <hello@foundation.xyz>
# SPDX-License-Identifier: GPL-3.0-or-later

# Sign individual files with the provided key
sign-files VERSION CONFIG_PATH=env_var_or_default("COSIGN_TOML_PATH", "~/cosign2.toml"):
    @echo "Signing all files for version {{VERSION}} with config {{CONFIG_PATH}}"
    cargo run --manifest-path tools/signer/Cargo.toml -- sign-files {{VERSION}} {{CONFIG_PATH}}

# Create tar file (only when all files have two signatures)
create-tar VERSION:
    @echo "Creating tar file for version {{VERSION}}"
    cargo run --manifest-path tools/signer/Cargo.toml -- create-tar {{VERSION}}

# Sign the tar file with the provided key
sign-tar VERSION CONFIG_PATH=env_var_or_default("COSIGN_TOML_PATH", "~/cosign2.toml"):
    @echo "Signing tar file for version {{VERSION}} with config {{CONFIG_PATH}}"
    cargo run --manifest-path tools/signer/Cargo.toml -- sign-tar {{VERSION}} {{CONFIG_PATH}}
