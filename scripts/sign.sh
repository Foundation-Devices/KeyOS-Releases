#!/bin/bash
set -e

VERSION=$1
CONFIG_PATH=$2
VERSION_FOLDER="${VERSION}"
# Remove any 'v' prefix from VERSION for consistency
if [[ "${VERSION}" == v* ]]; then
    VERSION="${VERSION#v}"
fi

# Detect the correct hash command to use (sha256sum on Linux, shasum -a 256 on macOS)
if command -v sha256sum > /dev/null 2>&1; then
    HASH_CMD="sha256sum"
    HASH_CUT_FIELD="1"
elif command -v shasum > /dev/null 2>&1; then
    HASH_CMD="shasum -a 256"
    HASH_CUT_FIELD="1"
else
    echo "Error: Neither sha256sum nor shasum command found"
    exit 1
fi

if [ -z "$VERSION" ]; then
    echo "Error: Version not specified"
    echo "Usage: $0 <version> [config_path]"
    exit 1
fi

# Use default config path if not provided
if [ -z "$CONFIG_PATH" ]; then
    CONFIG_PATH="~/cosign2.toml"
fi

# Remove 'v' prefix from version for cosign2 --firmware-version parameter
# cosign2 expects a semver without the 'v' prefix
FIRMWARE_VERSION="${VERSION}"
if [[ "${FIRMWARE_VERSION}" == v* ]]; then
    FIRMWARE_VERSION="${FIRMWARE_VERSION#v}"
fi

echo "Signing files for version $VERSION"

# Check if version folder exists
if [ ! -d "${VERSION_FOLDER}" ]; then
    echo "Error: Version folder ${VERSION_FOLDER} does not exist"
    exit 1
fi

# Sign the recovery image
if [ -f "${VERSION_FOLDER}/recovery.bin" ]; then
    echo "Signing recovery image..."
    echo "  File: ${VERSION_FOLDER}/recovery.bin"
    echo "  Config path: ${CONFIG_PATH}"
    echo "  Firmware version: ${FIRMWARE_VERSION}"
    cosign2 sign -i ${VERSION_FOLDER}/recovery.bin -c ${CONFIG_PATH} --in-place --firmware-version "${FIRMWARE_VERSION}"
else
    echo "Warning: Recovery image ${VERSION_FOLDER}/recovery.bin not found"
fi

# Sign the main firmware image
if [ -f "${VERSION_FOLDER}/app.bin" ]; then
    echo "Signing main firmware image..."
    cosign2 sign -i ${VERSION_FOLDER}/app.bin -c ${CONFIG_PATH} --in-place --firmware-version "${FIRMWARE_VERSION}"
else
    echo "Warning: Main firmware image ${VERSION_FOLDER}/app.bin not found"
fi

# Sign each dynamically loadable app
echo "Looking for dynamically loadable apps in ${VERSION_FOLDER}/apps/..."
if ls ${VERSION_FOLDER}/apps/gui-app*.elf 1> /dev/null 2>&1; then
    for app in ${VERSION_FOLDER}/apps/gui-app*.elf; do
        app_name=$(basename "$app")
        echo "Signing app: $app_name..."
        cosign2 sign -i "$app" -c ${CONFIG_PATH} --in-place --firmware-version "${FIRMWARE_VERSION}"
    done
else
    echo "No dynamically loadable apps found in ${VERSION_FOLDER}/apps/"
fi

# Generate manifest file
echo "Generating manifest file..."
manifest_file="${VERSION_FOLDER}/manifest.json"
echo "{" > $manifest_file
echo "  \"version\": \"v${VERSION}\"," >> $manifest_file
echo "  \"files\": [" >> $manifest_file

# Add recovery.bin to manifest if it exists
if [ -f "${VERSION_FOLDER}/recovery.bin" ]; then
    recovery_hash=$(${HASH_CMD} ${VERSION_FOLDER}/recovery.bin | cut -d' ' -f${HASH_CUT_FIELD})
    echo "    {" >> $manifest_file
    echo "      \"name\": \"recovery.bin\"," >> $manifest_file
    echo "      \"hash\": \"0x${recovery_hash}\"" >> $manifest_file
    echo "    }," >> $manifest_file
else
    echo "Warning: Recovery image not found, skipping in manifest"
    echo "    {" >> $manifest_file
    echo "      \"name\": \"recovery.bin\"," >> $manifest_file
    echo "      \"hash\": \"0x0000000000000000000000000000000000000000000000000000000000000000\"" >> $manifest_file
    echo "    }," >> $manifest_file
fi

# Add app.bin to manifest if it exists
if [ -f "${VERSION_FOLDER}/app.bin" ]; then
    app_hash=$(${HASH_CMD} ${VERSION_FOLDER}/app.bin | cut -d' ' -f${HASH_CUT_FIELD})
    echo "    {" >> $manifest_file
    echo "      \"name\": \"app.bin\"," >> $manifest_file
    echo "      \"hash\": \"0x${app_hash}\"" >> $manifest_file
    echo "    }" >> $manifest_file
else
    echo "Warning: Main firmware image not found, skipping in manifest"
    echo "    {" >> $manifest_file
    echo "      \"name\": \"app.bin\"," >> $manifest_file
    echo "      \"hash\": \"0x0000000000000000000000000000000000000000000000000000000000000000\"" >> $manifest_file
    echo "    }" >> $manifest_file
fi

# Add each app to manifest
if ls ${VERSION_FOLDER}/apps/gui-app*.elf 1> /dev/null 2>&1; then
    for app in ${VERSION_FOLDER}/apps/gui-app*.elf; do
        app_name=$(basename "$app")
        app_hash=$(${HASH_CMD} "$app" | cut -d' ' -f${HASH_CUT_FIELD})

        echo "    ," >> $manifest_file
        echo "    {" >> $manifest_file
        echo "      \"name\": \"apps/${app_name}\"," >> $manifest_file
        echo "      \"hash\": \"0x${app_hash}\"" >> $manifest_file
        echo "    }" >> $manifest_file
    done
else
    echo "No dynamically loadable apps to add to manifest"
fi

echo "  ]" >> $manifest_file
echo "}" >> $manifest_file

# Check if tar file already exists
tar_file="${VERSION_FOLDER}/KeyOS-v${VERSION}.bin"
if [ -f "$tar_file" ]; then
    echo "Tar file already exists. Will sign the existing tar file."
else
    # Create tar file
    echo "Creating tar file..."
    # Check if there are any files to include in the tar
    files_to_tar=""
    if ls ${VERSION_FOLDER}/*.bin 1> /dev/null 2>&1; then
        files_to_tar="${files_to_tar} ${VERSION_FOLDER}/*.bin"
    fi
    if ls ${VERSION_FOLDER}/apps/*.elf 1> /dev/null 2>&1; then
        files_to_tar="${files_to_tar} ${VERSION_FOLDER}/apps/*.elf"
    fi
    if [ -f "${VERSION_FOLDER}/manifest.json" ]; then
        files_to_tar="${files_to_tar} ${VERSION_FOLDER}/manifest.json"
    fi

    if [ -n "$files_to_tar" ]; then
        echo "Creating tar file with: $files_to_tar"
        tar -cf "$tar_file" ${VERSION_FOLDER}/*.bin ${VERSION_FOLDER}/apps/*.elf ${VERSION_FOLDER}/manifest.json 2>/dev/null || true

        if [ ! -f "$tar_file" ]; then
            echo "Warning: Failed to create tar file"
            exit 1
        fi
    else
        echo "Warning: No files found to include in tar file"
        exit 1
    fi
fi

# Sign the final tar file
if [ -f "$tar_file" ]; then
    echo "Checking existing signatures on tar file..."

    # Run cosign2 dump and capture output and exit status
    dump_output=$(cosign2 dump --input "$tar_file" 2>&1)
    dump_status=$?

    # Check if the file has no header
    if [ $dump_status -ne 0 ] || echo "$dump_output" | grep -q "no header found"; then
        echo "Tar file has no signature header. Adding first signature..."
        cosign2 sign -i "$tar_file" -c ${CONFIG_PATH} --in-place --firmware-version "${FIRMWARE_VERSION}"
    # Check if the file has one signature
    elif echo "$dump_output" | grep -q "signature2.*0000000000000000000000000000000000000000000000000000000000000000"; then
        echo "Tar file has one signature. Adding second signature..."
        cosign2 sign -i "$tar_file" -c ${CONFIG_PATH} --in-place --firmware-version "${FIRMWARE_VERSION}"
    # Check if the file has no valid signatures (but has a header)
    elif echo "$dump_output" | grep -q "signature1.*0000000000000000000000000000000000000000000000000000000000000000"; then
        echo "Tar file has a header but no valid signatures. Adding first signature..."
        cosign2 sign -i "$tar_file" -c ${CONFIG_PATH} --in-place --firmware-version "${FIRMWARE_VERSION}"
    # File must have two signatures
    else
        echo "Tar file already has two signatures. No more signatures can be added."
        echo "Current signatures:"
        echo "$dump_output" | grep -E "pubkey|signature"
    fi
else
    echo "Error: Tar file not found"
    exit 1
fi

echo "Signing complete for version $VERSION"
