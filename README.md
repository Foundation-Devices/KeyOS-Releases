# KeyOS-Releases

This repository contains various tools and scripts that are needed to generate KeyOS releases.

### Tools

#### [image-builder](./tools/image-builder/README.md)

A Rust CLI tool for creating bootable disk images from signed KeyOS firmware components. See [this](/tools/image-builder/README.md) for more info.

#### [signer](./tools/signer/README.md)

A Rust CLI tool for signing KeyOS firmware components. See [this](/tools/signer/README.md) for more info.

#### [release-gen](./tools/release-gen/README.md)

A Rust CLI tool for generating KeyOS release tarballs. See [this](/tools/release-gen/README.md) for more info.

### Scripts

#### [make_release.sh](./scripts/make_release.sh)

A bash script that automates creation of KeyOS releases, by using the above tools.

It takes two versions (old and new) of KeyOS (its firmware components) and performs the following steps:

1. Signs the files in both versions.
2. Creates a bootable disk image for the old version.
3. Creates a signed release tarball that the KeyOS update service can use to update from the old version to the new.

These two files (the image and the tarball) can be used for a complete E2E test of the update procedure.

#### [make_release_input_dir.sh](./scripts/make_release_input_dir.sh)

A simple bash script that takes a firmware version `vX.Y.Z` as input and generates a directory named `vX.Y.Z` that
will contain all the necessary firmware components (based on the local `keyos` repository).

#### [make_release_for_update_demo.sh](./scripts/make_release_for_update_demo.sh)

A bash script that creates a bootable disk image for the purposes of the `update-test` app. Used only for update service development as it does not require a complete E2E update procedure to be performed. Read the script docs for more info.

# Principle

It is extremely important that the binaries for each version are built deterministically, and that each of the three types of releases are created from the same set of signed binaries.

The `prepare-release` script in the `KeyOS` repo is used to create a branch like `1.1.0 `in the `KeyOS-Releases` repo, which contains all the necessary files for creating a release. For official releases, we then need to run:

- `just sign 1.1.0` - Runs `cosign2` twice, once for each signer
- `just signl-bl 1.1.0` - Signs the bootloader using SAM-BA and the customer key (does NOT use `cosign2`)

At this point, all files for 1.1.0 are signed and ready for packaging. We have three options for packaging:

- **Patch-based, incremental update** - Updates files one by one from the previous version to the new one.
- **Normal Recovery Image** - Installs a specific version of the operating system, overwriting the previous one.
- **Core System Recovery Image** - Installs a specific version of the operating system as in Normal Recovery, but in addition, can update the bootloader and/or the Recovery OS image

The sources for each of these are the files in the corresponding worktree (e.g., `.worktrees/1.1.0/1.1.0`).
