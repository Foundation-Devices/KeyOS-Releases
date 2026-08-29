# release-gen

A Rust CLI tool for automatically generating KeyOS releases. See `--help` for more info.

## Dependencies

- A checkout of [keyos](https://github.com/Foundation-Devices/keyos), which builds the patch
  bodies through `cargo xtask build-patches`. Pass its path with `--keyos-dir` if it is not at
  `../keyos`.
