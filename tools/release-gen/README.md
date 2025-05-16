# release-gen

Command line tool for automatically generating KeyOS releases. See `--help` for more info.

## Dependencies

- [updiff](https://github.com/sistemd/updiff)

## Testing

- In order to run the tests, `updiff` tool has to be visible to `release-gen`. This means that you have to either:
  - Have it in `PATH`
  - Set the `UPDIFF_PATH` environment variable before running the tests.
