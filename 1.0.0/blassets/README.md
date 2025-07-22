## `assets` directory

This directory contains the assets used in the `at91bootstrap-ffi` crate.

The PNG images are automatically converted into raw ARGB8888 images and hashed, with the hash being baked into the binary
through inclusion of a generated `assets_metadata.rs` file.

See [assets.rs] module.

To access an asset, use an `assets::UPPER_CASE_NAME` constant provided by the [assets.rs] module that contains all the information about the asset.

### QR codes

If an asset is a QR code, it's getting automatically recognized and the content of the QR code is stored in the `assets_metadata.rs` file as `qr_url` field.

[assets.rs]: ../src/assets.rs
