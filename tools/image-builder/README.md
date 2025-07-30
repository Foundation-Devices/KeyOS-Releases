# KeyOS Image Builder

A Rust CLI tool for creating bootable disk images from signed KeyOS firmware components.

## Overview

The `image-builder` tool creates complete bootable disk images by combining:
- `boot.bin` (bootloader)
- `recovery.bin` (recovery firmware)
- `app.bin` (main signed firmware)
- Apps directory (signed dynamically loadable applications)

The resulting disk image contains properly formatted FAT32 partitions with MBR partition table, suitable for flashing to KeyOS devices.

## Commands

### Create Disk Image

```bash
# Create a disk image from version folder
just create-image 1.0.0

# Create with custom output filename
just create-image 1.0.0 my-keyos-image.img

# Direct cargo command
cargo run --manifest-path tools/image-builder/Cargo.toml -- create-image 1.0.0 --output boot.img
```

### Print Component Hashes

```bash
# Print SHA256 hashes of all firmware components
just print-hashes 1.0.0

# Direct cargo command
cargo run --manifest-path tools/image-builder/Cargo.toml -- print-hashes 1.0.0
```

## Disk Layout

The tool creates a disk image with the following partition structure:

1. **Boot Partition** (32MB, FAT32, bootable)
   - `boot.bin` - Bootloader
   - `recovery.bin` - Recovery firmware

2. **System Partition** (10GB, FAT32)
   - `app.bin` - Main signed firmware
   - `apps/` - Directory containing signed applications

3. **User Partition** (45GB, FAT32)
   - Reserved for user data (partition table only)

## Prerequisites

Before creating a disk image, ensure:

1. **All firmware components exist** in the version folder:
   - `{version}/boot.bin`
   - `{version}/recovery.bin` 
   - `{version}/app.bin`
   - `{version}/apps/` (optional)

2. **Firmware is properly signed** (for production images):
   - Run the complete signing workflow first
   - Use `just validate {version}` to verify signatures

## Workflow Integration

The image builder fits into the complete KeyOS release workflow:

```bash
# 1. Sign individual files (both signers)
just sign 1.0.0

# 2. Create firmware update package
just create-tar 1.0.0

# 3. Sign the tar package (both signers)
just sign-tar 1.0.0

# 4. Create bootable disk image
just create-image 1.0.0

# 5. Verify everything
just validate 1.0.0
just print-hashes 1.0.0
```

## Output

- **Disk Image**: `boot.img` (or custom filename)
- **Size**: ~55GB (sparse file, actual size depends on content)
- **Format**: Raw disk image with MBR partition table
- **Filesystems**: FAT32 partitions

## Usage Notes

- The tool creates sparse files, so the actual disk usage is much smaller than the apparent file size
- Images can be flashed directly to storage devices using tools like `dd`
- The partition layout is optimized for KeyOS device requirements
- Hash verification helps ensure firmware integrity before deployment
