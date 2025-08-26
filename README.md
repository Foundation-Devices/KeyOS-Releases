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

#### make_release.sh

A bash script that automates creation of KeyOS releases, by using the above tools. See [this](./scripts/make_release.sh) for more info.

It takes two versions (old and new) of KeyOS (its firmware components) and performs the following steps:

1. Signs the files in both versions.
2. Creates a bootable disk image for the old version.
3. Creates a signed release tarball that the KeyOS update service can use to update from the old version to the new.

These two files (the image and the tarball) can be used for a complete E2E test of the update procedure.

#### make_release_for_update_demo.sh

A bash script that creates a bootable disk image for the purposes of the `update-test` app. Used only for update service development as it does not require a complete E2E update procedure to be performed. Read the [script docs](./scripts/make_release_for_update_demo.sh) for more info.
