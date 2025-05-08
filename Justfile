# SPDX-FileCopyrightText: © 2025  Foundation Devices, Inc. <hello@foundation.xyz>
# SPDX-License-Identifier: GPL-3.0-or-later

sign VERSION CONFIG_PATH=env_var_or_default("COSIGN_TOML_PATH", "~/cosign2.toml"):
    @echo "Signing release version {{VERSION}} with config {{CONFIG_PATH}}"
    ./scripts/sign.sh {{VERSION}} {{CONFIG_PATH}}
