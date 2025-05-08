# SPDX-FileCopyrightText: © 2025  Foundation Devices, Inc. <hello@foundation.xyz>
# SPDX-License-Identifier: GPL-3.0-or-later

# Sign individual files with the provided key
sign-files VERSION CONFIG_PATH=env_var_or_default("COSIGN_TOML_PATH", "~/cosign2.toml"):
    @echo "Signing individual files for version {{VERSION}} with config {{CONFIG_PATH}}"
    ./scripts/sign.sh sign-files {{VERSION}} {{CONFIG_PATH}}

# Create tar file (only when all files have two signatures)
create-tar VERSION:
    @echo "Creating tar file for version {{VERSION}}"
    ./scripts/sign.sh create-tar {{VERSION}}

# Sign the tar file with the provided key
sign-tar VERSION CONFIG_PATH=env_var_or_default("COSIGN_TOML_PATH", "~/cosign2.toml"):
    @echo "Signing tar file for version {{VERSION}} with config {{CONFIG_PATH}}"
    ./scripts/sign.sh sign-tar {{VERSION}} {{CONFIG_PATH}}

# Help command to explain the workflow
sign:
    @echo "KeyOS Firmware Signing Workflow:"
    @echo ""
    @echo "For a multi-signer workflow, use these commands in sequence:"
    @echo ""
    @echo "1. First signer: Sign individual files"
    @echo "   just sign-files VERSION ~/path/to/first-signer-key.toml"
    @echo ""
    @echo "2. Second signer: Sign individual files"
    @echo "   just sign-files VERSION ~/path/to/second-signer-key.toml"
    @echo ""
    @echo "3. After all files have two signatures, create the tar file"
    @echo "   just create-tar VERSION"
    @echo ""
    @echo "4. First signer: Sign the tar file"
    @echo "   just sign-tar VERSION ~/path/to/first-signer-key.toml"
    @echo ""
    @echo "5. Second signer: Sign the tar file"
    @echo "   just sign-tar VERSION ~/path/to/second-signer-key.toml"
    @echo ""
    @echo "Example: just sign-files v1.0.2 ~/cosign2.toml"
