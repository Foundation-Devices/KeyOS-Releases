# Manifest Generator

A Rust tool for generating firmware manifest.json files for KeyOS releases.

## Features

- Reads version information from release-config.toml files
- Calculates signed SHA256 hash of the entire firmware file
- Calculates unsigned SHA256 hash (skipping first 2048 bytes for cosign2 signature header)
- Generates structured manifest.json with firmware and metadata information
- Supports custom descriptions, release dates, and build numbers
- Provides visual feedback with colored output

## Usage

### Using Just (Recommended)

```bash
# Generate 1.0.0/manifest.json for a version
just generate-manifest 1.0.0

# Generate with custom output path
just generate-manifest 1.0.0 custom-manifest.json
```

### Direct Cargo Usage

```bash
cargo run -- 1.0.0 \
  --description "Custom update description" \
  --release-date "2025-07-30" \
  --output "manifest.json"
```

### Required Arguments

- `version`: The version number (e.g., "1.0.0") - reads from `{version}/release-config.toml`

### Optional Arguments

- `--description`: Custom description (defaults to "Firmware update from vX to vY")
- `--release-date`: Release date in YYYY-MM-DD format (defaults to today)
- `--output`: Output path for manifest.json (defaults to "{version}/manifest.json")

## How it works

1. Reads the `{version}/release-config.toml` file to get base-version and version
2. Looks for the firmware file at `{version}/KeyOS-v{version}.bin`
3. Calculates both signed and unsigned SHA256 hashes
4. Generates the `{version}/manifest.json` with all required information

## Output Format

The tool generates a manifest.json file with the following structure:

```json
{
  "baseVersion": "1.0.2",
  "version": "1.2.0",
  "signedSha256": "a1b2c3d4e5f6789012345678901234567890abcdef1234567890abcdef123456",
  "unsignedSha256": "f6e5d4c3b2a1098765432109876543210987fedcba0987654321fedcba098765",
  "updateFilename": "KeyOS-v1.2.0.bin",
  "signatureFilename": "KeyOS-v1.2.0.bin.sig",
  "description": "Firmware update from v1.0.2 to v1.2.0",
  "releaseDate": "2025-07-30"
}
```

## Hash Calculation

- **signedSha256**: SHA256 hash of the entire firmware file
- **unsignedSha256**: SHA256 hash of the firmware file starting from byte 2048 (skipping the cosign2 signature header)

This allows verification of both the signed firmware package and the underlying firmware content separately.
