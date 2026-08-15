use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use colored::Colorize;
use flate2::{read::GzDecoder, write::GzEncoder, Compression};
use regex::Regex;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashSet};
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::path::{Component, Path, PathBuf};
use std::process::Command;
use tempfile::TempDir;
use thiserror::Error;
use zip::write::SimpleFileOptions;
use zip::{ZipArchive, ZipWriter};

#[derive(Error, Debug)]
enum SignerError {
    #[error("File not found: {0}")]
    FileNotFound(String),

    #[error("Directory not found: {0}")]
    DirectoryNotFound(String),

    #[error("Failed to execute command: {0}")]
    CommandFailed(String),

    #[error("Not all files have two signatures")]
    InsufficientSignatures,

    #[allow(dead_code)]
    #[error("Invalid version format: {0}")]
    InvalidVersion(String),
}

#[derive(Parser)]
#[command(
    author,
    version = concat!("v", env!("CARGO_PKG_VERSION")),
    about = concat!("KeyOS firmware signing tool (v", env!("CARGO_PKG_VERSION"), ")"),
    long_about = None
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Sign individual files with the provided key
    SignFiles {
        /// Version number (e.g., 1.0.2)
        version: String,

        /// Path to cosign2 configuration file
        #[arg(default_value = "~/cosign2.toml")]
        config_path: String,

        #[arg(long)]
        developer: bool,
    },

    /// Pack fully signed sideload bundles into installable .app archives
    PackSideloadApps {
        /// Version number (e.g., 1.0.2)
        version: String,

        /// Accept one developer signature instead of requiring two production signatures
        #[arg(long)]
        developer: bool,
    },

    /// Create recovery tar file (only when all files have two signatures)
    CreateRecoveryTar {
        /// Version number (e.g., 1.0.2)
        version: String,

        /// Path to cosign2 configuration file (for signing manifest.json)
        #[arg(default_value = "~/cosign2.toml")]
        config_path: String,

        /// Supply this argument to produce a Core System Recovery tar file that includes
        /// ONLY the bootloader (boot.cip or boot.bin) and recovery OS (recovery.bin).
        /// This tar does NOT include app.bin or dynamically loaded apps.
        #[arg(long)]
        core_system_recovery: bool,

        #[arg(long)]
        allow_one_signature: bool,
    },

    /// Sign the recovery tar files with the provided key
    SignRecoveryTars {
        /// Version number (e.g., 1.0.2)
        version: String,

        /// Path to cosign2 configuration file
        #[arg(default_value = "~/cosign2.toml")]
        config_path: String,
    },

    /// Validate that files for a version are properly signed
    Validate {
        /// Version number (e.g., 1.0.2)
        version: String,

        /// Only check individual signed files (app.bin, recovery.bin, apps);
        /// skip manifest and tar file validation
        #[arg(long)]
        files_only: bool,

        /// Development mode: accept files with only one signature instead of requiring two
        #[arg(long)]
        dev: bool,
    },

    /// Package signable binary files into a zip for sending to another signer
    Package {
        /// Version number (e.g., 1.1.0)
        version: String,

        /// Output zip file path (default: KeyOS-v{version}.zip, with status suffix added)
        #[arg(short, long)]
        output: Option<String>,
    },

    /// Sign files from a zip archive and create a new signed zip
    SignZip {
        /// Input zip file path
        input: String,

        /// Path to cosign2 configuration file (default: cosign2.toml in current directory)
        #[arg(default_value = "cosign2.toml")]
        config_path: String,

        /// Output zip file path (default: {input-basename}-signed.zip)
        #[arg(short, long)]
        output: Option<String>,

        /// Developer mode for app signing
        #[arg(long)]
        developer: bool,
    },

    /// Unpack a signed zip back into the version folder
    Unpack {
        /// Version number (e.g., 1.1.0)
        version: String,

        /// Input zip file path
        input: String,
    },
}

#[derive(Serialize, Deserialize)]
struct FileEntry {
    name: String,
    hash: String,
}

#[derive(Serialize, Deserialize)]
struct Manifest {
    version: String,
    files: Vec<FileEntry>,
}

/// Version info stored in version.json inside the zip
#[derive(Serialize, Deserialize)]
struct VersionInfo {
    version: String,
}

struct SignatureStatus {
    has_header: bool,
    has_first_signature: bool,
    has_second_signature: bool,
}

impl SignatureStatus {
    fn signature_count(&self) -> u8 {
        if self.has_second_signature {
            2
        } else if self.has_first_signature {
            1
        } else {
            0
        }
    }
}

fn main() -> Result<()> {
    env_logger::init();

    let cli = Cli::parse();

    match &cli.command {
        Commands::SignFiles {
            version,
            config_path,
            developer,
        } => {
            let version_folder = version.clone();
            let firmware_version = strip_v_prefix(version);
            sign_files(&version_folder, config_path, &firmware_version, *developer)?;
        }
        Commands::PackSideloadApps { version, developer } => {
            pack_sideload_apps(version, *developer, false)?;
        }
        Commands::CreateRecoveryTar {
            version,
            config_path,
            core_system_recovery,
            allow_one_signature,
        } => {
            let version_folder = version.clone();
            let firmware_version = strip_v_prefix(version);
            create_tar(
                &version_folder,
                config_path,
                &firmware_version,
                *core_system_recovery,
                *allow_one_signature,
            )?;
        }
        Commands::SignRecoveryTars {
            version,
            config_path,
        } => {
            let version_folder = version.clone();
            let firmware_version = strip_v_prefix(version);
            sign_tar(&version_folder, config_path, &firmware_version)?;
        }
        Commands::Validate {
            version,
            files_only,
            dev,
        } => {
            let version_folder = version.clone();
            let firmware_version = strip_v_prefix(version);
            validate(&version_folder, &firmware_version, *files_only, *dev)?;
        }
        Commands::Package { version, output } => {
            let version_folder = version.clone();
            let firmware_version = strip_v_prefix(&version);
            let output_path = output
                .clone()
                .unwrap_or_else(|| format!("KeyOS-v{}.zip", firmware_version));
            package_release(&version_folder, &firmware_version, &output_path)?;
        }
        Commands::SignZip {
            input,
            config_path,
            output,
            developer,
        } => {
            let output_path = output.clone().unwrap_or_else(|| {
                let input_stem = Path::new(input)
                    .file_stem()
                    .and_then(|s| s.to_str())
                    .unwrap_or("release");
                // Strip any existing status suffix (-unsigned, -partially-signed, -fully-signed)
                let clean_stem = input_stem
                    .trim_end_matches("-unsigned")
                    .trim_end_matches("-partially-signed")
                    .trim_end_matches("-fully-signed");
                // Return base name without suffix - sign_zip will add the appropriate suffix
                format!("{}.zip", clean_stem)
            });
            sign_zip(input, config_path, &output_path, *developer)?;
        }
        Commands::Unpack { version, input } => {
            unpack_zip(version, input)?;
        }
    }

    Ok(())
}

fn strip_v_prefix(version: &str) -> String {
    // Remove 'v' prefix if present for cosign2 --binary-version parameter
    if version.starts_with('v') {
        version[1..].to_string()
    } else {
        version.to_string()
    }
}

const APP_BUNDLE_DIRS: [&str; 2] = ["keyos/apps", "sideload-apps"];
const APP_MANIFEST_FILE: &str = "manifest.json";
const APP_ARCHIVE_EXTENSION: &str = "app";
const MAX_APP_BUNDLE_BYTES: u64 = 64 * 1024 * 1024;

#[derive(Deserialize)]
struct AppArchiveManifest {
    #[serde(rename = "fileHashes")]
    file_hashes: BTreeMap<String, String>,
}

fn collect_app_bundles(apps_dir: &Path) -> Result<Vec<(std::path::PathBuf, std::path::PathBuf)>> {
    let mut apps = Vec::new();
    for entry in fs::read_dir(apps_dir).context("Failed to read apps directory")? {
        let entry = entry.context("Failed to read directory entry")?;
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }

        let elf_path = path.join("app.elf");
        let manifest_path = path.join("manifest.json");
        if elf_path.exists() && manifest_path.exists() {
            apps.push((elf_path, manifest_path));
        }
    }
    apps.sort_by(|left, right| left.0.cmp(&right.0));
    Ok(apps)
}

fn app_manifest_hashed_files(bundle_dir: &Path) -> Result<Vec<String>> {
    let manifest_path = bundle_dir.join(APP_MANIFEST_FILE);
    let bytes = fs::read(&manifest_path)
        .with_context(|| format!("Failed to read app manifest {}", manifest_path.display()))?;

    // Release preparation emits plain JSON. Each signer subsequently adds or updates the fixed
    // cosign2 header, so accept either representation for signing-zip transport and final packing.
    let manifest: AppArchiveManifest = serde_json::from_slice(&bytes)
        .or_else(|_| {
            let json = bytes.get(COSIGN2_HEADER_SIZE..).ok_or_else(|| {
                serde_json::Error::io(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "manifest is too short to contain a cosign2 header",
                ))
            })?;
            serde_json::from_slice(json)
        })
        .with_context(|| format!("Failed to parse fileHashes from {}", manifest_path.display()))?;

    let mut names: Vec<String> = manifest.file_hashes.into_keys().collect();
    names.sort_unstable();
    for name in &names {
        let path = Path::new(name);
        anyhow::ensure!(
            !name.is_empty()
                && name != APP_MANIFEST_FILE
                && !path.is_absolute()
                && path.components().all(|component| matches!(component, Component::Normal(_))),
            "Invalid fileHashes path in {}: {}",
            manifest_path.display(),
            name
        );
    }
    Ok(names)
}

fn app_bundle_files(bundle_dir: &Path) -> Result<Vec<PathBuf>> {
    let mut files = vec![bundle_dir.join(APP_MANIFEST_FILE)];
    files.extend(app_manifest_hashed_files(bundle_dir)?.into_iter().map(|name| bundle_dir.join(name)));
    for path in &files {
        anyhow::ensure!(path.is_file(), "App bundle file is missing: {}", path.display());
    }
    Ok(files)
}

fn pack_app_bundle(bundle_dir: &Path, archive_path: &Path) -> Result<()> {
    // Keep this wire format aligned with KeyOS-dev/app-archive::pack_bundle, which is what the
    // SDK's `foundation pack` command uses.
    anyhow::ensure!(
        !fs::symlink_metadata(archive_path).is_ok_and(|metadata| metadata.file_type().is_symlink()),
        "Refusing to replace symlinked app archive {}",
        archive_path.display()
    );
    let files = app_bundle_files(bundle_dir)?;
    let mut stream_bytes = 1024u64;
    for path in &files {
        let size = fs::metadata(path)
            .with_context(|| format!("Failed to read app bundle file metadata: {}", path.display()))?
            .len();
        let relative = path.strip_prefix(bundle_dir).expect("bundle file is below its root");
        let framing = if relative.as_os_str().len() > 100 { 2048 } else { 1024 };
        stream_bytes = stream_bytes.saturating_add(size).saturating_add(framing);
    }
    anyhow::ensure!(
        stream_bytes <= MAX_APP_BUNDLE_BYTES,
        "App bundle {} unpacks to {} bytes, over the {} byte install limit",
        bundle_dir.display(),
        stream_bytes,
        MAX_APP_BUNDLE_BYTES
    );

    let archive = File::create(archive_path)
        .with_context(|| format!("Failed to create app archive {}", archive_path.display()))?;
    let encoder = GzEncoder::new(archive, Compression::default());
    let mut builder = tar::Builder::new(encoder);
    for path in files {
        let relative = path.strip_prefix(bundle_dir).expect("bundle file is below its root");
        let data = fs::read(&path)
            .with_context(|| format!("Failed to read app bundle file {}", path.display()))?;
        let mut header = tar::Header::new_gnu();
        header.set_entry_type(tar::EntryType::Regular);
        header.set_size(data.len() as u64);
        header.set_mode(0o644);
        header.set_mtime(0);
        header.set_uid(0);
        header.set_gid(0);
        builder
            .append_data(&mut header, relative, data.as_slice())
            .with_context(|| format!("Failed to write app archive {}", archive_path.display()))?;
    }
    let encoder = builder
        .into_inner()
        .with_context(|| format!("Failed to finish app archive {}", archive_path.display()))?;
    encoder
        .finish()
        .with_context(|| format!("Failed to finish app archive {}", archive_path.display()))?;
    Ok(())
}

fn validate_app_archive(bundle_dir: &Path, archive_path: &Path) -> Result<()> {
    let expected_files = app_bundle_files(bundle_dir)?;
    let archive = File::open(archive_path)
        .with_context(|| format!("Failed to open app archive {}", archive_path.display()))?;
    let mut archive = tar::Archive::new(GzDecoder::new(archive));
    let mut entries = archive
        .entries()
        .with_context(|| format!("Failed to read app archive {}", archive_path.display()))?;

    for expected_path in expected_files {
        let expected_name = expected_path.strip_prefix(bundle_dir).expect("bundle file is below its root");
        let mut entry = entries
            .next()
            .transpose()
            .with_context(|| format!("Failed to read app archive {}", archive_path.display()))?
            .with_context(|| format!("App archive {} is missing {}", archive_path.display(), expected_name.display()))?;
        anyhow::ensure!(
            entry.path()?.as_ref() == expected_name,
            "App archive {} has an unexpected entry; expected {}",
            archive_path.display(),
            expected_name.display()
        );
        anyhow::ensure!(
            entry.header().entry_type().is_file(),
            "App archive {} entry {} is not a regular file",
            archive_path.display(),
            expected_name.display()
        );
        let mut archived_data = Vec::new();
        entry.read_to_end(&mut archived_data)?;
        anyhow::ensure!(
            archived_data == fs::read(&expected_path)?,
            "App archive {} contains stale data for {}",
            archive_path.display(),
            expected_name.display()
        );
    }
    anyhow::ensure!(entries.next().is_none(), "App archive {} has unexpected extra entries", archive_path.display());
    Ok(())
}

fn pack_sideload_apps(version_folder: &str, developer: bool, defer_if_not_ready: bool) -> Result<()> {
    let apps_dir = Path::new(version_folder).join("sideload-apps");
    if !apps_dir.is_dir() {
        if defer_if_not_ready {
            return Ok(());
        }
        return Err(SignerError::DirectoryNotFound(apps_dir.display().to_string()).into());
    }

    let bundles = collect_app_bundles(&apps_dir)?;
    if bundles.is_empty() {
        if defer_if_not_ready {
            return Ok(());
        }
        return Err(SignerError::FileNotFound(format!(
            "No sideload app bundles found in {}",
            apps_dir.display()
        ))
        .into());
    }
    let mut ready = true;
    for (elf_path, manifest_path) in &bundles {
        for path in [elf_path, manifest_path] {
            let status = check_signatures_quiet(&path.to_string_lossy())?;
            ready &= if developer { status.has_first_signature } else { status.has_second_signature };
        }
    }
    if !ready {
        if defer_if_not_ready {
            println!("Sideload app archives will be packed after the final signatures are applied");
            return Ok(());
        }
        return Err(SignerError::InsufficientSignatures.into());
    }

    println!("\n{}", "Packing installable sideload app archives...".bold());
    let expected_archives: HashSet<String> = bundles
        .iter()
        .filter_map(|(elf_path, _)| elf_path.parent()?.file_name()?.to_str())
        .map(|app_name| format!("{app_name}.{APP_ARCHIVE_EXTENSION}"))
        .collect();
    for entry in fs::read_dir(&apps_dir)? {
        let path = entry?.path();
        if path.extension().is_some_and(|extension| extension == APP_ARCHIVE_EXTENSION)
            && path
                .file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| !expected_archives.contains(name))
        {
            fs::remove_file(&path)
                .with_context(|| format!("Failed to remove stale app archive {}", path.display()))?;
        }
    }
    for (elf_path, _) in bundles {
        let bundle_dir = elf_path.parent().expect("app.elf is inside its bundle");
        let app_name = bundle_dir.file_name().and_then(|name| name.to_str()).with_context(|| {
            format!("App bundle directory name is not valid UTF-8: {}", bundle_dir.display())
        })?;
        let archive_path = apps_dir.join(format!("{app_name}.{APP_ARCHIVE_EXTENSION}"));
        pack_app_bundle(bundle_dir, &archive_path)?;
        println!("  {} {}", "✓".green(), archive_path.display());
    }
    Ok(())
}

fn sign_file_if_needed(
    file_path: &Path,
    description: &str,
    config_path: &str,
    firmware_version: &str,
    is_developer: bool,
) -> Result<()> {
    let file_path_str = file_path
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("File path is not valid UTF-8: {}", file_path.display()))?;

    // Production signing is resumable so a partially signed release can be completed without
    // attempting to add a third signature to files that are already complete.
    if !is_developer && check_signatures_quiet(file_path_str)?.has_second_signature {
        println!("Skipping {} (already has two signatures)", description);
        return Ok(());
    }

    print!("Signing {}...", description);
    let mut args = vec![
        "sign",
        "-i",
        file_path_str,
        "-c",
        config_path,
        "--in-place",
        "--binary-version",
        firmware_version,
    ];
    if is_developer {
        args.push("--developer");
    }

    let output = Command::new("cosign2")
        .args(args)
        .output()
        .context(format!("{} cosign2 error", "✗".red()))?;

    if !output.status.success() {
        println!("{} Failed to sign", "✗".red());
        return Err(SignerError::CommandFailed(
            String::from_utf8_lossy(&output.stderr).to_string(),
        )
        .into());
    }

    println!("{}", "✓ Success".green());
    Ok(())
}

fn sign_files(
    version_folder: &str,
    config_path: &str,
    firmware_version: &str,
    is_developer: bool,
) -> Result<()> {
    println!(
        "{}",
        format!("Signing files for version {}", firmware_version).bold()
    );

    // Check if version folder exists
    if !Path::new(version_folder).is_dir() {
        return Err(SignerError::DirectoryNotFound(version_folder.to_string()).into());
    }

    // Check for required files
    let app_bin = format!("{}/keyos/app.bin", version_folder);
    let recovery_bin = format!("{}/recovery.bin", version_folder);

    if !Path::new(&app_bin).exists() {
        return Err(SignerError::FileNotFound(app_bin).into());
    }

    if !Path::new(&recovery_bin).exists() {
        return Err(SignerError::FileNotFound(recovery_bin).into());
    }

    sign_file_if_needed(
        Path::new(&app_bin),
        "KeyOS image (app.bin)",
        config_path,
        firmware_version,
        false,
    )?;
    sign_file_if_needed(
        Path::new(&recovery_bin),
        "recovery image (recovery.bin)",
        config_path,
        firmware_version,
        false,
    )?;

    // Built-in and sideload bundles use the same independently signed ELF and manifest format.
    for relative_dir in APP_BUNDLE_DIRS {
        let apps_path = Path::new(version_folder).join(relative_dir);
        println!(
            "\n{}",
            format!("Looking for app bundles in {}...", apps_path.display()).bold()
        );
        if !apps_path.is_dir() {
            println!("{}", format!("No apps directory found at {}", apps_path.display()).yellow());
            continue;
        }

        let apps = collect_app_bundles(&apps_path)?;
        println!("Found {} app bundles", apps.len());
        for (elf_path, manifest_path) in apps {
            sign_file_if_needed(
                &elf_path,
                &format!("app binary {}", elf_path.display()),
                config_path,
                firmware_version,
                is_developer,
            )?;
            sign_file_if_needed(
                &manifest_path,
                &format!("app manifest {}", manifest_path.display()),
                config_path,
                firmware_version,
                is_developer,
            )?;
        }
    }

    // Sign bootloader (boot.cip -> boot-signed.cip or boot.bin -> boot-signed.bin)
    // This creates a signed copy that recovery OS can verify
    println!(
        "\n{}",
        "Signing bootloader for core system recovery...".bold()
    );

    let boot_cip = format!("{}/boot.cip", version_folder);
    let boot_bin = format!("{}/boot.bin", version_folder);
    let boot_signed_cip = format!("{}/boot-signed.cip", version_folder);
    let boot_signed_bin = format!("{}/boot-signed.bin", version_folder);

    if Path::new(&boot_signed_cip).exists() {
        // boot-signed.cip already exists (second signer adds another signature)
        sign_file_if_needed(
            Path::new(&boot_signed_cip),
            "boot-signed.cip",
            config_path,
            firmware_version,
            false,
        )?;
    } else if Path::new(&boot_cip).exists() {
        // First signer: create boot-signed.cip from boot.cip
        fs::copy(&boot_cip, &boot_signed_cip)
            .context("Failed to copy boot.cip to boot-signed.cip")?;

        sign_file_if_needed(
            Path::new(&boot_signed_cip),
            "boot-signed.cip",
            config_path,
            firmware_version,
            false,
        )?;
    } else if Path::new(&boot_signed_bin).exists() {
        // boot-signed.bin already exists (second signer adds another signature)
        sign_file_if_needed(
            Path::new(&boot_signed_bin),
            "boot-signed.bin",
            config_path,
            firmware_version,
            false,
        )?;
    } else if Path::new(&boot_bin).exists() {
        // First signer (dev build): create boot-signed.bin from boot.bin
        fs::copy(&boot_bin, &boot_signed_bin)
            .context("Failed to copy boot.bin to boot-signed.bin")?;

        sign_file_if_needed(
            Path::new(&boot_signed_bin),
            "boot-signed.bin",
            config_path,
            firmware_version,
            false,
        )?;
    } else {
        println!(
            "{}",
            "No bootloader found (boot.cip or boot.bin) - skipping bootloader signing".yellow()
        );
    }

    // The installable archive must contain the final signed bytes. A first production signer
    // leaves only the directory bundle; the signer that completes every app causes packing.
    pack_sideload_apps(version_folder, is_developer, true)?;

    println!(
        "\n{} {}",
        "✓".green().bold(),
        format!("Signing complete for version {}", firmware_version)
            .green()
            .bold()
    );
    Ok(())
}

fn create_tar(
    version_folder: &str,
    config_path: &str,
    firmware_version: &str,
    is_core_system_recovery: bool,
    allow_one_signature: bool,
) -> Result<()> {
    let tar_type = if is_core_system_recovery {
        "core system recovery "
    } else {
        ""
    };
    println!(
        "{}",
        format!(
            "Creating {}tar file for version {}",
            tar_type, firmware_version
        )
        .bold()
    );

    // Check if version folder exists
    if !Path::new(version_folder).is_dir() {
        return Err(SignerError::DirectoryNotFound(version_folder.to_string()).into());
    }

    println!("Checking signatures on all files...");

    let mut all_signed = true;
    let mut unsigned_files = Vec::new();

    // Check recovery.bin (required for both recovery tar types)
    let recovery_bin = format!("{}/recovery.bin", version_folder);
    let recovery_status = check_signatures(&recovery_bin)?;
    if !recovery_status.has_second_signature && !allow_one_signature {
        all_signed = false;
        unsigned_files.push("recovery.bin".to_string());
    }

    // For core system recovery, we only need bootloader + recovery.bin
    // For regular recovery tar, we also need app.bin and apps
    if !is_core_system_recovery {
        let app_bin = format!("{}/keyos/app.bin", version_folder);
        let app_status = check_signatures(&app_bin)?;
        if !app_status.has_second_signature && !allow_one_signature {
            all_signed = false;
            unsigned_files.push("keyos/app.bin".to_string());
        }

        // Check all app binaries and manifests
        let apps_dir = format!("{}/keyos/apps", version_folder);
        let apps_path = Path::new(&apps_dir);

        if apps_path.is_dir() {
            for entry in fs::read_dir(apps_path).context("Failed to read apps directory")? {
                let entry = entry.context("Failed to read directory entry")?;
                let path = entry.path();

                // Found an app dir, it should contain a signed app.elf and manifest.json.
                if path.is_dir() {
                    for file_name in ["app.elf", "manifest.json"] {
                        let app_file = path.join(file_name);
                        let app_file_str = app_file.to_string_lossy().to_string();
                        let app_status = check_signatures(&app_file_str)?;
                        if !app_status.has_second_signature && !allow_one_signature {
                            all_signed = false;
                            unsigned_files.push(app_file_str);
                        }
                    }
                }
            }
        }
    }

    // Only proceed with tar file creation if all files are properly signed
    if !all_signed && !allow_one_signature {
        println!("{} Some files don't have two signatures", "✗".red());
        println!(
            "{}",
            "The following files need to be signed with a second key:".red()
        );
        for file in unsigned_files {
            println!("  - {}", file);
        }
        return Err(SignerError::InsufficientSignatures.into());
    }

    println!("{} All files have sufficient signatures", "✓".green());

    // Expand ~ in config path
    let expanded_config = if config_path.starts_with("~/") {
        let home = std::env::var("HOME").context("HOME environment variable not set")?;
        format!("{}/{}", home, &config_path[2..])
    } else {
        config_path.to_string()
    };

    if !Path::new(&expanded_config).exists() {
        println!("{} Config file not found: {}", "✗".red(), config_path);
        return Err(SignerError::FileNotFound(format!("Config file: {}", config_path)).into());
    }

    // Generate manifest file
    println!("Generating manifest file...");

    generate_manifest(version_folder, firmware_version, is_core_system_recovery)?;

    println!("{} Manifest file generated successfully", "✓".green());

    // Sign manifest.json with cosign2
    let manifest_file = format!("{}/manifest.json", version_folder);
    print!("Signing manifest.json...");

    let output = Command::new("cosign2")
        .args([
            "sign",
            "-i",
            &manifest_file,
            "-c",
            &expanded_config,
            "--in-place",
            "--binary-version",
            firmware_version,
        ])
        .output()
        .context(format!("{} cosign2 error", "✗".red()))?;

    if !output.status.success() {
        println!("{} Failed to sign manifest", "✗".red());
        return Err(SignerError::CommandFailed(
            String::from_utf8_lossy(&output.stderr).to_string(),
        )
        .into());
    }

    println!("{}", "✓ Success".green());

    // Create tar file with appropriate naming (v prefix for customer-facing files)
    let tar_file = if is_core_system_recovery {
        format!(
            "{}/KeyOS-v{}-CoreSystemRecovery.bin",
            version_folder, firmware_version
        )
    } else {
        format!(
            "{}/KeyOS-v{}-Recovery.bin",
            version_folder, firmware_version
        )
    };

    // Collect all files to include in the tar
    let mut files_to_include = Vec::new();
    let mut is_dev_build = false;
    // Track bootloader rename: (from, to) for tar --transform
    let mut bootloader_rename: Option<(String, String)> = None;

    // For core system recovery, include ONLY bootloader and recovery OS
    if is_core_system_recovery {
        // Add signed bootloader - boot-signed.cip has a cosign2 header for verification by recovery OS
        // This is created by 'signer sign-zip' from the original boot.cip
        // We rename it to boot.cip/boot.bin in the tar (recovery OS expects these names)
        let boot_signed_cip = format!("{}/boot-signed.cip", version_folder);
        let boot_signed_bin = format!("{}/boot-signed.bin", version_folder);

        if Path::new(&boot_signed_cip).exists() {
            println!(
                "{} Including signed bootloader: boot-signed.cip (renamed to boot.cip in tar)",
                "→".blue()
            );
            files_to_include.push(boot_signed_cip);
            bootloader_rename = Some(("boot-signed.cip".to_string(), "boot.cip".to_string()));
        } else if Path::new(&boot_signed_bin).exists() {
            println!("{} Including signed bootloader: boot-signed.bin (renamed to boot.bin in tar)", "→".blue());
            files_to_include.push(boot_signed_bin);
            bootloader_rename = Some(("boot-signed.bin".to_string(), "boot.bin".to_string()));
            is_dev_build = true;
        } else {
            return Err(SignerError::FileNotFound(
                "Neither boot-signed.cip nor boot-signed.bin found. Run 'signer sign-zip' first to create signed bootloader.".to_string()
            ).into());
        }

        // Add recovery.bin
        println!("{} Including recovery OS: recovery.bin", "→".blue());
        files_to_include.push(recovery_bin);

        // Add manifest.json (contains bootloader, recovery.bin, and boot assets for core system recovery)
        let manifest_file = format!("{}/manifest.json", version_folder);
        files_to_include.push(manifest_file.clone());

        // Add blassets folder (bootloader assets) recursively
        let blassets_dir = format!("{}/blassets", version_folder);
        let blassets_path = Path::new(&blassets_dir);
        if blassets_path.is_dir() {
            let mut blassets_files = Vec::new();
            collect_files_recursive(blassets_path, &mut blassets_files)?;
            println!(
                "{} Including {} bootloader assets from blassets/",
                "→".blue(),
                blassets_files.len()
            );
            files_to_include.extend(blassets_files);
        }

        // Add common-boot folder (common boot assets) recursively
        let common_boot_dir = format!("{}/common-boot", version_folder);
        let common_boot_path = Path::new(&common_boot_dir);
        if common_boot_path.is_dir() {
            let mut common_boot_files = Vec::new();
            collect_files_recursive(common_boot_path, &mut common_boot_files)?;
            println!(
                "{} Including {} common boot assets from common-boot/",
                "→".blue(),
                common_boot_files.len()
            );
            files_to_include.extend(common_boot_files);
        }
    } else {
        // For regular recovery tar, include app.bin, apps, and common assets
        // Add keyos/app.bin
        let app_bin = format!("{}/keyos/app.bin", version_folder);
        files_to_include.push(app_bin);

        // Add manifest.json
        let manifest_file = format!("{}/manifest.json", version_folder);
        files_to_include.push(manifest_file.clone());

        // Add all .elf files in the apps directory
        let apps_dir = format!("{}/keyos/apps", version_folder);
        let apps_path = Path::new(&apps_dir);
        if apps_path.is_dir() {
            for entry in fs::read_dir(apps_path).context("Failed to read apps directory")? {
                let entry = entry.context("Failed to read directory entry")?;
                let path = entry.path();

                // Found an app dir, it should contain an app .elf and a manifest
                if path.is_dir() {
                    let elf_path = path.clone().join("app.elf");
                    let manifest_path = path.clone().join("manifest.json");
                    if elf_path.exists() && manifest_path.exists() {
                        files_to_include.push(elf_path.to_string_lossy().to_string());
                        files_to_include.push(manifest_path.to_string_lossy().to_string());
                    }
                }
            }
        }

        // Add all assets in the common directory
        let mut num_assets = 0;
        let common_dir = format!("{}/keyos/common", version_folder);
        let common_path = Path::new(&common_dir);
        if common_path.is_dir() {
            for entry in fs::read_dir(common_path).context("Failed to read common directory")? {
                let entry = entry.context("Failed to read directory entry")?;
                let path = entry.path();

                if path.is_file() {
                    files_to_include.push(path.to_string_lossy().to_string());
                    num_assets += 1;
                } else if path.is_dir() {
                    // If it's a directory, include all files in it
                    for sub_entry in fs::read_dir(&path).context("Failed to read subdirectory")? {
                        let sub_entry = sub_entry.context("Failed to read subdirectory entry")?;
                        files_to_include.push(sub_entry.path().to_string_lossy().to_string());
                        num_assets += 1;
                    }
                }
            }
        }

        println!("{} Included {num_assets} assets", "✓".green());
    }

    // Print file sizes for each file to be included
    println!("\n{}", "Files to include:".bold());
    for file in &files_to_include {
        let file_path = Path::new(file);
        let file_name = file_path.file_name().unwrap_or_default().to_string_lossy();
        if let Ok(metadata) = fs::metadata(file) {
            let size = metadata.len();
            let size_str = if size >= 1024 * 1024 {
                format!("{:.2} MB", size as f64 / (1024.0 * 1024.0))
            } else if size >= 1024 {
                format!("{:.2} KB", size as f64 / 1024.0)
            } else {
                format!("{} bytes", size)
            };
            println!("  {} {} ({})", "→".blue(), file_name, size_str);
        } else {
            println!("  {} {} (size unknown)", "→".blue(), file_name);
        }
    }

    // Print manifest contents (skip 2048-byte cosign2 header)
    let manifest_file = format!("{}/manifest.json", version_folder);
    println!("\n{}", "Manifest contents:".bold());
    if let Ok(manifest_bytes) = fs::read(&manifest_file) {
        // cosign2 header is 2048 bytes
        const COSIGN2_HEADER_SIZE: usize = 2048;
        let json_bytes = if manifest_bytes.len() > COSIGN2_HEADER_SIZE {
            &manifest_bytes[COSIGN2_HEADER_SIZE..]
        } else {
            &manifest_bytes[..]
        };
        if let Ok(manifest_content) = std::str::from_utf8(json_bytes) {
            for line in manifest_content.lines() {
                println!("  {}", line);
            }
        }
    }

    println!(
        "\nCreating tar file: {}...",
        Path::new(&tar_file).file_name().unwrap().to_string_lossy()
    );

    // If we need to rename the bootloader, do it before creating the tar
    // (macOS tar doesn't support --transform, so we rename the file temporarily)
    // We also need to temporarily move the original boot.cip out of the way
    let bootloader_renamed_path: Option<(String, String, Option<String>)> = if let Some((from, to)) = &bootloader_rename {
        let from_path = format!("{}/{}", version_folder, from);
        let to_path = format!("{}/{}", version_folder, to);
        let backup_path = format!("{}/{}.original", version_folder, to);

        // If the target file exists (e.g., boot.cip), move it out of the way
        let had_original = if Path::new(&to_path).exists() {
            fs::rename(&to_path, &backup_path).context(format!("Failed to backup {} to {}", to, backup_path))?;
            Some(backup_path)
        } else {
            None
        };

        fs::rename(&from_path, &to_path).context(format!("Failed to rename {} to {}", from, to))?;
        // Update files_to_include to use the new name
        for file in &mut files_to_include {
            if file.ends_with(from) {
                *file = to_path.clone();
            }
        }
        Some((from_path, to_path, had_original))
    } else {
        None
    };

    // Build the tar command with an explicit file list
    let mut tar_cmd = Command::new("tar");
    tar_cmd.arg("-cf").arg(&tar_file);

    // Add all collected files
    for file in &files_to_include {
        tar_cmd.arg(file);
    }

    // Execute the tar command
    let output = tar_cmd.output().context("Failed to execute tar command")?;

    // Restore the original bootloader filenames (even if tar failed)
    if let Some((from_path, to_path, backup_path)) = &bootloader_renamed_path {
        fs::rename(to_path, from_path).context("Failed to restore bootloader filename")?;
        // Restore the original boot.cip if we backed it up
        if let Some(backup) = backup_path {
            fs::rename(backup, to_path).context("Failed to restore original bootloader")?;
        }
    }

    if !output.status.success() {
        println!("{} Failed to create tar file", "✗".red());
        return Err(SignerError::CommandFailed(
            String::from_utf8_lossy(&output.stderr).to_string(),
        )
        .into());
    }

    if !Path::new(&tar_file).exists() {
        println!("{} Tar file not found after creation", "✗".red());
        return Err(SignerError::FileNotFound(tar_file).into());
    }

    // Get path relative to repo root (find .worktrees in CWD and use that as prefix)
    let display_path = std::env::current_dir()
        .ok()
        .and_then(|cwd| {
            let path_str = cwd.to_string_lossy();
            path_str.find(".worktrees").map(|idx| {
                format!("{}/{}", &path_str[idx..], tar_file)
            })
        })
        .unwrap_or_else(|| tar_file.clone());

    // Get tar file size
    let tar_size_str = if let Ok(metadata) = fs::metadata(&tar_file) {
        let size = metadata.len();
        if size >= 1024 * 1024 {
            format!(" ({:.2} MB)", size as f64 / (1024.0 * 1024.0))
        } else if size >= 1024 {
            format!(" ({:.2} KB)", size as f64 / 1024.0)
        } else {
            format!(" ({} bytes)", size)
        }
    } else {
        String::new()
    };

    println!(
        "{} Tar file created successfully: {}{}",
        "✓".green(),
        display_path,
        tar_size_str
    );

    println!(
        "\n{} {}",
        "✓".green().bold(),
        format!(
            "{} creation complete for version {}",
            if is_core_system_recovery {
                "Core system recovery tar"
            } else {
                "Recovery tar"
            },
            firmware_version
        )
        .green()
        .bold()
    );

    // Warn if boot.bin was used instead of boot.cip (development build only)
    if is_dev_build {
        println!(
            "\n{}\n",
            "⚠️  DEVELOPMENT BUILD ONLY -- boot.bin found -- NOT USABLE FOR PRODUCTION!"
                .yellow()
                .bold()
        );
    }

    Ok(())
}

fn sign_tar(version_folder: &str, _config_path: &str, firmware_version: &str) -> Result<()> {
    // Recovery tars are intentionally left unsigned - the signed manifest inside provides integrity.
    // This command is kept for backwards compatibility but is now a no-op.
    println!(
        "{}",
        format!(
            "Recovery tar signing skipped for version {} (tars are left unsigned; manifest is signed)",
            firmware_version
        )
        .bold()
    );

    // Verify that the tar files exist
    let recovery_tar = format!(
        "{}/KeyOS-v{}-Recovery.bin",
        version_folder, firmware_version
    );
    let core_recovery_tar = format!(
        "{}/KeyOS-v{}-CoreSystemRecovery.bin",
        version_folder, firmware_version
    );

    let recovery_exists = Path::new(&recovery_tar).exists();
    let core_recovery_exists = Path::new(&core_recovery_tar).exists();

    if recovery_exists {
        println!(
            "  {} KeyOS-v{}-Recovery.bin exists (unsigned)",
            "✓".green(),
            firmware_version
        );
    }

    if core_recovery_exists {
        println!(
            "  {} KeyOS-v{}-CoreSystemRecovery.bin exists (unsigned)",
            "✓".green(),
            firmware_version
        );
    }

    if !recovery_exists && !core_recovery_exists {
        return Err(SignerError::FileNotFound(
            "No recovery tar files found. Please run create-recovery-tar command first."
                .to_string(),
        )
        .into());
    }

    println!(
        "\n{} {}",
        "✓".green().bold(),
        format!(
            "Recovery tar files verified for version {} (intentionally unsigned)",
            firmware_version
        )
        .green()
        .bold()
    );
    Ok(())
}

fn validate(
    version_folder: &str,
    firmware_version: &str,
    files_only: bool,
    dev_mode: bool,
) -> Result<()> {
    let mode_str = if dev_mode {
        " (dev mode - 1 signature)"
    } else {
        " (production - 2 signatures)"
    };
    println!(
        "{}",
        format!(
            "Validating signatures for version {}{}",
            firmware_version, mode_str
        )
        .bold()
    );

    // Check if version folder exists
    if !Path::new(version_folder).is_dir() {
        println!("{} Version folder not found: {}", "✗".red(), version_folder);
        return Err(SignerError::DirectoryNotFound(version_folder.to_string()).into());
    }

    println!("Checking required files and signatures...\n");

    let mut all_valid = true;
    let mut missing_files = Vec::new();
    let mut insufficient_sigs = Vec::new();
    let required_sigs = if dev_mode { 1 } else { 2 };

    // Helper to check if signature count meets requirement
    let check_sig_requirement = |status: &SignatureStatus| -> bool {
        if dev_mode {
            status.has_first_signature
        } else {
            status.has_second_signature
        }
    };

    // === Bootloader (boot.cip or boot.bin) ===
    // Bootloader doesn't use cosign2, just check existence
    let boot_cip = format!("{}/boot.cip", version_folder);
    let boot_bin = format!("{}/boot.bin", version_folder);
    if Path::new(&boot_cip).exists() {
        println!("  {} boot.cip (secure boot mode)", "✓".green());
    } else if Path::new(&boot_bin).exists() {
        println!("  {} boot.bin", "✓".green());
    } else {
        println!(
            "  {} bootloader (boot.cip or boot.bin) is missing",
            "✗".red()
        );
        missing_files.push("boot.cip or boot.bin".to_string());
        all_valid = false;
    }

    // === Recovery OS (recovery.bin) ===
    let recovery_bin = format!("{}/recovery.bin", version_folder);
    if !Path::new(&recovery_bin).exists() {
        println!("  {} recovery.bin is missing", "✗".red());
        missing_files.push("recovery.bin".to_string());
        all_valid = false;
    } else {
        let recovery_status = check_signatures_quiet(&recovery_bin)?;
        if check_sig_requirement(&recovery_status) {
            println!("  {} recovery.bin", "✓".green());
        } else {
            println!(
                "  {} recovery.bin ({} of {} signatures)",
                "✗".red(),
                recovery_status.signature_count(),
                required_sigs
            );
            insufficient_sigs.push("recovery.bin".to_string());
            all_valid = false;
        }
    }

    // === KeyOS (keyos/app.bin) ===
    let app_bin = format!("{}/keyos/app.bin", version_folder);
    if !Path::new(&app_bin).exists() {
        println!("  {} keyos/app.bin is missing", "✗".red());
        missing_files.push("keyos/app.bin".to_string());
        all_valid = false;
    } else {
        let app_status = check_signatures_quiet(&app_bin)?;
        if check_sig_requirement(&app_status) {
            println!("  {} keyos/app.bin", "✓".green());
        } else {
            println!(
                "  {} keyos/app.bin ({} of {} signatures)",
                "✗".red(),
                app_status.signature_count(),
                required_sigs
            );
            insufficient_sigs.push("keyos/app.bin".to_string());
            all_valid = false;
        }
    }

    // === Built-in and sideload app bundles ===
    for (relative_dir, required) in [("keyos/apps", true), ("sideload-apps", false)] {
        let apps_path = Path::new(version_folder).join(relative_dir);
        if !apps_path.is_dir() {
            if required {
                println!("  {} {}/ directory is missing", "✗".red(), relative_dir);
                missing_files.push(format!("{}/", relative_dir));
                all_valid = false;
            }
            continue;
        }

        let mut app_count = 0;

        for entry in fs::read_dir(&apps_path).context("Failed to read apps directory")? {
            let entry = entry.context("Failed to read directory entry")?;
            let path = entry.path();

            // Apps are in subdirectories: <root>/{app_name}/{app.elf,manifest.json}
            if path.is_dir() {
                let app_name = path
                    .file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or("unknown");
                let elf_path = path.join("app.elf");
                let manifest_path = path.join("manifest.json");

                if elf_path.exists() || manifest_path.exists() {
                    app_count += 1;

                    for (file_name, file_path) in
                        [("app.elf", &elf_path), ("manifest.json", &manifest_path)]
                    {
                        let relative_path = format!("{}/{}/{}", relative_dir, app_name, file_name);
                        if !file_path.exists() {
                            println!("  {} {} is missing", "✗".red(), relative_path);
                            missing_files.push(relative_path);
                            all_valid = false;
                            continue;
                        }

                        let file_path_str = file_path.to_string_lossy();
                        let status = check_signatures_quiet(&file_path_str)?;
                        if check_sig_requirement(&status) {
                            println!("  {} {}", "✓".green(), relative_path);
                        } else {
                            println!(
                                "  {} {} ({} of {} signatures)",
                                "✗".red(),
                                relative_path,
                                status.signature_count(),
                                required_sigs
                            );
                            insufficient_sigs.push(relative_path);
                            all_valid = false;
                        }
                    }

                    if relative_dir == "sideload-apps" {
                        let archive_path = apps_path.join(format!("{app_name}.{APP_ARCHIVE_EXTENSION}"));
                        let relative_path = format!("{relative_dir}/{app_name}.{APP_ARCHIVE_EXTENSION}");
                        if !archive_path.is_file() {
                            println!("  {} {} is missing", "✗".red(), relative_path);
                            missing_files.push(relative_path);
                            all_valid = false;
                        } else if let Err(error) = validate_app_archive(&path, &archive_path) {
                            println!("  {} {} is invalid: {error:#}", "✗".red(), relative_path);
                            insufficient_sigs.push(relative_path);
                            all_valid = false;
                        } else {
                            println!("  {} {}", "✓".green(), relative_path);
                        }
                    }
                }
            }
        }

        if app_count == 0 {
            println!("  {} No apps found in {}/", "✗".red(), relative_dir);
            all_valid = false;
        }
    }

    // === Artifacts (only checked when not --files-only) ===
    if !files_only {
        println!("\nChecking release artifacts...\n");

        // Check manifest.json
        let manifest_file = format!("{}/manifest.json", version_folder);
        if Path::new(&manifest_file).exists() {
            println!("  {} manifest.json", "✓".green());
        } else {
            println!("  {} manifest.json is missing", "✗".red());
            missing_files.push("manifest.json".to_string());
            all_valid = false;
        }

        // Check Recovery bin: KeyOS-v{version}-Recovery.bin
        // Note: Recovery tars are intentionally unsigned - the signed manifest inside provides integrity
        let recovery_tar = format!(
            "{}/KeyOS-v{}-Recovery.bin",
            version_folder, firmware_version
        );
        if Path::new(&recovery_tar).exists() {
            println!(
                "  {} KeyOS-v{}-Recovery.bin (unsigned, contains signed manifest)",
                "✓".green(),
                firmware_version
            );
        } else {
            println!(
                "  {} KeyOS-v{}-Recovery.bin is missing",
                "⚠".yellow(),
                firmware_version
            );
            // Not a hard failure - might not have been created yet
        }

        // Check Core System Recovery bin: KeyOS-v{version}-CoreSystemRecovery.bin
        // Note: Recovery tars are intentionally unsigned - the signed manifest inside provides integrity
        let core_recovery_tar = format!(
            "{}/KeyOS-v{}-CoreSystemRecovery.bin",
            version_folder, firmware_version
        );
        if Path::new(&core_recovery_tar).exists() {
            println!(
                "  {} KeyOS-v{}-CoreSystemRecovery.bin (unsigned, contains signed manifest)",
                "✓".green(),
                firmware_version
            );
        } else {
            println!(
                "  {} KeyOS-v{}-CoreSystemRecovery.bin is missing",
                "⚠".yellow(),
                firmware_version
            );
            // Not a hard failure - might not have been created yet
        }

        // Check Factory image: KeyOS-v{version}-Factory.img
        let factory_img = format!("{}/KeyOS-v{}-Factory.img", version_folder, firmware_version);
        if Path::new(&factory_img).exists() {
            println!("  {} KeyOS-v{}-Factory.img", "✓".green(), firmware_version);
        } else {
            println!(
                "  {} KeyOS-v{}-Factory.img is missing",
                "⚠".yellow(),
                firmware_version
            );
            // Not a hard failure - might not have been created yet
        }
    }

    // Print summary
    println!("\n{}", "Validation Summary:".bold());

    if !missing_files.is_empty() {
        println!("\n{} Missing required files:", "✗".red());
        for file in &missing_files {
            println!("  - {}", file);
        }
    }

    if !insufficient_sigs.is_empty() {
        println!(
            "\n{} Files with insufficient signatures (need {}):",
            "✗".red(),
            required_sigs
        );
        for file in &insufficient_sigs {
            println!("  - {}", file);
        }
    }

    if all_valid {
        let sig_msg = if dev_mode {
            "All required files exist and have at least one signature."
        } else {
            "All required files exist and have two signatures."
        };
        println!("\n{} {}", "✓".green().bold(), sig_msg.green().bold());
    } else {
        println!(
            "\n{} {}",
            "✗".red().bold(),
            "Validation failed. See issues above.".red().bold()
        );
        return Err(anyhow::anyhow!("Validation failed"));
    }

    Ok(())
}

fn check_signatures(file_path: &str) -> Result<SignatureStatus> {
    check_signatures_impl(file_path, true)
}

fn check_signatures_quiet(file_path: &str) -> Result<SignatureStatus> {
    check_signatures_impl(file_path, false)
}

fn check_signatures_impl(file_path: &str, verbose: bool) -> Result<SignatureStatus> {
    // Run cosign2 dump and capture output
    let output = Command::new("cosign2")
        .args(["dump", "--input", file_path])
        .output()
        .context(format!("Failed to execute cosign2 dump for {}", file_path))?;

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();

    // Check if the file has no header
    if !output.status.success()
        || stderr.contains("no header found")
        || stdout.contains("no header found")
    {
        if verbose {
            println!("  {} {} has no signatures", "✗".red(), file_path);
        }
        return Ok(SignatureStatus {
            has_header: false,
            has_first_signature: false,
            has_second_signature: false,
        });
    }

    // Check for zero signatures in signature2
    let re_sig2 = Regex::new(r"signature2.*0{64}")?;
    if re_sig2.is_match(&stdout) {
        if verbose {
            println!("  {} {} has only one signature", "⚠".yellow(), file_path);
        }
        return Ok(SignatureStatus {
            has_header: true,
            has_first_signature: true,
            has_second_signature: false,
        });
    }

    // Check for zero signatures in signature1
    let re_sig1 = Regex::new(r"signature1.*0{64}")?;
    if re_sig1.is_match(&stdout) {
        if verbose {
            println!(
                "  {} {} has a header but no valid signatures",
                "✗".red(),
                file_path
            );
        }
        return Ok(SignatureStatus {
            has_header: true,
            has_first_signature: false,
            has_second_signature: false,
        });
    }

    // If we get here, the file has two signatures
    if verbose {
        println!("  {} {} has two signatures", "✓".green(), file_path);
    }
    Ok(SignatureStatus {
        has_header: true,
        has_first_signature: true,
        has_second_signature: true,
    })
}

fn generate_manifest(
    version_folder: &str,
    firmware_version: &str,
    is_core_system_recovery: bool,
) -> Result<()> {
    // Manifest file generation is handled by the progress bar in the calling function
    let manifest_file = format!("{}/manifest.json", version_folder);

    // Create manifest structure
    let mut manifest = Manifest {
        version: format!("v{}", firmware_version),
        files: Vec::new(),
    };

    // For core system recovery, include ONLY bootloader and recovery OS
    if is_core_system_recovery {
        // Add signed bootloader - boot-signed.cip has a cosign2 header for verification
        // Prefer boot-signed.cip (secure boot mode), otherwise boot-signed.bin (development)
        let boot_signed_cip = format!("{}/boot-signed.cip", version_folder);
        let boot_signed_bin = format!("{}/boot-signed.bin", version_folder);

        if Path::new(&boot_signed_cip).exists() {
            // boot-signed.cip has a cosign2 header, so use binary hash
            // Note: We name it boot.cip in the manifest (recovery OS expects this name)
            let boot_hash = calculate_binary_hash(&boot_signed_cip)?;
            manifest.files.push(FileEntry {
                name: format!("{}/boot.cip", version_folder),
                hash: boot_hash,
            });
        } else if Path::new(&boot_signed_bin).exists() {
            // boot-signed.bin has a cosign2 header, so use binary hash
            // Note: We name it boot.bin in the manifest (recovery OS expects this name)
            let boot_hash = calculate_binary_hash(&boot_signed_bin)?;
            manifest.files.push(FileEntry {
                name: format!("{}/boot.bin", version_folder),
                hash: boot_hash,
            });
        } else {
            // Fallback error - boot-signed.* should have been created by sign-zip
            return Err(anyhow::anyhow!(
                "boot-signed.cip or boot-signed.bin not found. Run 'signer sign-zip' first to create signed bootloader."
            ));
        }

        // Add recovery.bin (signed file - use binary hash, not full file hash)
        let recovery_bin = format!("{}/recovery.bin", version_folder);
        if Path::new(&recovery_bin).exists() {
            // recovery.bin has a cosign2 header, so we need to hash only the binary content
            let recovery_hash = calculate_binary_hash(&recovery_bin)?;
            manifest.files.push(FileEntry {
                name: format!("{}/recovery.bin", version_folder),
                hash: recovery_hash,
            });
        }

        // Add blassets folder (bootloader assets) recursively - these are NOT signed
        let blassets_dir = format!("{}/blassets", version_folder);
        let blassets_path = Path::new(&blassets_dir);
        if blassets_path.is_dir() {
            let mut blassets_files = Vec::new();
            collect_files_recursive(blassets_path, &mut blassets_files)?;
            for file_path in blassets_files {
                let hash = calculate_full_file_hash(&file_path)?;
                manifest.files.push(FileEntry {
                    name: file_path,
                    hash,
                });
            }
        }

        // Add common-boot folder (common boot assets) recursively - these are NOT signed
        let common_boot_dir = format!("{}/common-boot", version_folder);
        let common_boot_path = Path::new(&common_boot_dir);
        if common_boot_path.is_dir() {
            let mut common_boot_files = Vec::new();
            collect_files_recursive(common_boot_path, &mut common_boot_files)?;
            for file_path in common_boot_files {
                let hash = calculate_full_file_hash(&file_path)?;
                manifest.files.push(FileEntry {
                    name: file_path,
                    hash,
                });
            }
        }
    } else {
        // For regular recovery tar, include app.bin and apps (but NOT recovery.bin or bootloader)
        // Add keyos/app.bin to manifest (signed file - use binary hash)
        let app_bin = format!("{}/keyos/app.bin", version_folder);
        let app_hash = calculate_binary_hash(&app_bin)?;
        manifest.files.push(FileEntry {
            name: format!("{}/keyos/app.bin", version_folder),
            hash: app_hash,
        });

        // Add each app to manifest (both app.elf and manifest.json)
        let apps_dir = format!("{}/keyos/apps", version_folder);
        let apps_path = Path::new(&apps_dir);

        let mut _app_count = 0;
        if apps_path.is_dir() {
            for entry in fs::read_dir(apps_path).context("Failed to read apps directory")? {
                let entry = entry.context("Failed to read directory entry")?;
                let path = entry.path();

                // Apps are in subdirectories: keyos/apps/{app_name}/app.elf and manifest.json
                if path.is_dir() {
                    let app_name = path
                        .file_name()
                        .and_then(|n| n.to_str())
                        .unwrap_or("unknown");
                    let elf_path = path.join("app.elf");
                    let app_manifest_path = path.join("manifest.json");

                    if elf_path.exists() {
                        // app.elf files are signed with cosign2 - use binary hash
                        let app_hash = calculate_binary_hash(elf_path.to_str().unwrap())?;

                        manifest.files.push(FileEntry {
                            name: format!("{}/keyos/apps/{}/app.elf", version_folder, app_name),
                            hash: app_hash,
                        });

                        _app_count += 1;
                    }

                    if app_manifest_path.exists() {
                        // RecoveryOS verifies the complete archived manifest, including its cosign2 header.
                        let manifest_hash =
                            calculate_full_file_hash(app_manifest_path.to_str().unwrap())?;

                        manifest.files.push(FileEntry {
                            name: format!(
                                "{}/keyos/apps/{}/manifest.json",
                                version_folder, app_name
                            ),
                            hash: manifest_hash,
                        });
                    }
                }
            }
            // App count is displayed in the calling function
        }

        // Add keyos/common folder (common assets) recursively - these are NOT signed
        let common_dir = format!("{}/keyos/common", version_folder);
        let common_path = Path::new(&common_dir);
        if common_path.is_dir() {
            let mut common_files = Vec::new();
            collect_files_recursive(common_path, &mut common_files)?;
            for file_path in common_files {
                let hash = calculate_full_file_hash(&file_path)?;
                manifest.files.push(FileEntry {
                    name: file_path,
                    hash,
                });
            }
        }
    }

    // Write manifest to file
    let manifest_json =
        serde_json::to_string_pretty(&manifest).context("Failed to serialize manifest to JSON")?;

    fs::write(&manifest_file, manifest_json)
        .context(format!("Failed to write manifest file: {}", manifest_file))?;
    Ok(())
}

/// Calculate the hash of the binary content only, skipping the cosign2 header.
/// This matches what the recovery OS expects for signed files.
const COSIGN2_HEADER_SIZE: usize = 2048;

fn calculate_binary_hash(file_path: &str) -> Result<String> {
    let mut file =
        File::open(file_path).context(format!("Failed to open file for hashing: {}", file_path))?;

    // Skip the cosign2 header
    let mut header = vec![0u8; COSIGN2_HEADER_SIZE];
    file.read_exact(&mut header)
        .context(format!("Failed to read cosign2 header from: {}", file_path))?;

    // Hash only the binary content after the header
    let mut hasher = Sha256::new();
    io::copy(&mut file, &mut hasher)
        .context(format!("Failed to read binary content for hashing: {}", file_path))?;

    let hash = hasher.finalize();
    Ok(hex::encode(hash))
}

/// Calculate the hash of the entire file, including any cosign2 header.
fn calculate_full_file_hash(file_path: &str) -> Result<String> {
    let mut file =
        File::open(file_path).context(format!("Failed to open file for hashing: {}", file_path))?;

    let mut hasher = Sha256::new();
    io::copy(&mut file, &mut hasher)
        .context(format!("Failed to read file for hashing: {}", file_path))?;

    let hash = hasher.finalize();
    Ok(hex::encode(hash))
}

/// Recursively collect all files from a directory.
fn collect_files_recursive(dir: &Path, files: &mut Vec<String>) -> Result<()> {
    if !dir.is_dir() {
        return Ok(());
    }

    for entry in fs::read_dir(dir).context(format!("Failed to read directory: {}", dir.display()))? {
        let entry = entry.context("Failed to read directory entry")?;
        let path = entry.path();

        if path.is_file() {
            files.push(path.to_string_lossy().to_string());
        } else if path.is_dir() {
            collect_files_recursive(&path, files)?;
        }
    }

    Ok(())
}

fn package_release(version_folder: &str, firmware_version: &str, output_path: &str) -> Result<()> {
    println!(
        "{}",
        format!("Packaging release files from {}", version_folder).bold()
    );

    if !Path::new(version_folder).is_dir() {
        return Err(SignerError::DirectoryNotFound(version_folder.to_string()).into());
    }

    let mut files_to_package: Vec<String> = Vec::new();

    // Add keyos/app.bin
    let app_bin = format!("{}/keyos/app.bin", version_folder);
    if Path::new(&app_bin).exists() {
        files_to_package.push(app_bin.clone());
    } else {
        return Err(SignerError::FileNotFound("keyos/app.bin".to_string()).into());
    }

    // Add recovery.bin
    let recovery_bin = format!("{}/recovery.bin", version_folder);
    if Path::new(&recovery_bin).exists() {
        files_to_package.push(recovery_bin);
    } else {
        return Err(SignerError::FileNotFound("recovery.bin".to_string()).into());
    }

    // Add bootloader (boot.cip or boot.bin) if present
    let boot_cip = format!("{}/boot.cip", version_folder);
    let boot_bin = format!("{}/boot.bin", version_folder);
    if Path::new(&boot_cip).exists() {
        files_to_package.push(boot_cip);
    } else if Path::new(&boot_bin).exists() {
        files_to_package.push(boot_bin);
    }

    // Carry every file named by each app manifest so an offline signer can produce the same
    // final installable archive as a direct signing run.
    for relative_dir in APP_BUNDLE_DIRS {
        let apps_dir = Path::new(version_folder).join(relative_dir);
        if apps_dir.is_dir() {
            for (elf_path, _) in collect_app_bundles(&apps_dir)? {
                let bundle_dir = elf_path.parent().expect("app.elf is inside its bundle");
                for path in app_bundle_files(bundle_dir)? {
                    files_to_package.push(path.to_string_lossy().to_string());
                }
            }
        }
    }
    files_to_package.sort();
    files_to_package.dedup();

    // Check signature status of app.bin to determine naming
    println!("\nChecking current signature status...");
    let sig_status = check_signatures_quiet(&app_bin)?;
    let sig_count = sig_status.signature_count();

    if sig_count >= 2 {
        println!(
            "\n{} {}",
            "✓".green().bold(),
            "All files already have 2 signatures. No more signatures required.".green().bold()
        );
        return Ok(());
    }

    // Determine output filename based on signature count
    let suffix = match sig_count {
        0 => "-unsigned",
        1 => "-partially-signed",
        _ => "-fully-signed",
    };

    let path = Path::new(output_path);
    let stem = path.file_stem().and_then(|s| s.to_str()).unwrap_or("Release");
    let parent = path.parent().map(|p| p.to_string_lossy().to_string()).unwrap_or_default();
    let final_output_path = if parent.is_empty() {
        format!("{}{}.zip", stem, suffix)
    } else {
        format!("{}/{}{}.zip", parent, stem, suffix)
    };

    // Get absolute path for display
    let absolute_path = if Path::new(&final_output_path).is_absolute() {
        final_output_path.clone()
    } else {
        std::env::current_dir()
            .map(|cwd| cwd.join(&final_output_path).to_string_lossy().to_string())
            .unwrap_or_else(|_| final_output_path.clone())
    };

    println!(
        "  {} signature(s) found, creating: {}",
        sig_count,
        Path::new(&final_output_path).file_name().unwrap_or_default().to_string_lossy()
    );

    // Create the zip file
    let zip_file = File::create(&final_output_path)
        .context(format!("Failed to create zip file: {}", final_output_path))?;
    let mut zip = ZipWriter::new(zip_file);
    let options = SimpleFileOptions::default()
        .compression_method(zip::CompressionMethod::Deflated);

    println!("\nAdding files to zip:");
    for file_path in &files_to_package {
        // Get relative path from version folder
        let relative_path = file_path
            .strip_prefix(version_folder)
            .unwrap_or(file_path)
            .trim_start_matches('/');

        print!("  {} {}...", "→".blue(), relative_path);

        zip.start_file(relative_path, options)?;
        let mut file = File::open(file_path)?;
        let mut buffer = Vec::new();
        file.read_to_end(&mut buffer)?;
        zip.write_all(&buffer)?;

        println!(" {}", "✓".green());
    }

    // Add version.json to the zip
    print!("  {} version.json...", "→".blue());
    let version_info = VersionInfo {
        version: firmware_version.to_string(),
    };
    let version_json = serde_json::to_string_pretty(&version_info)
        .context("Failed to serialize version.json")?;
    zip.start_file("version.json", options)?;
    zip.write_all(version_json.as_bytes())?;
    println!(" {}", "✓".green());

    zip.finish()?;

    println!(
        "\n{} {} ({} files)\n",
        "✓".green().bold(),
        format!("Package created: {}", final_output_path).green().bold(),
        files_to_package.len() + 1 // +1 for version.json
    );

    Ok(())
}

fn sign_zip(
    input_path: &str,
    config_path: &str,
    output_path: &str,
    is_developer: bool,
) -> Result<()> {
    println!(
        "{}",
        format!("Signing files from zip: {}", input_path).bold()
    );

    // Expand ~ in config path
    let expanded_config = if config_path.starts_with("~/") {
        let home = std::env::var("HOME").context("HOME environment variable not set")?;
        format!("{}/{}", home, &config_path[2..])
    } else {
        config_path.to_string()
    };

    if !Path::new(&expanded_config).exists() {
        return Err(SignerError::FileNotFound(format!("Config file: {}", config_path)).into());
    }

    // Read version from version.json in the zip
    let zip_file = File::open(input_path)
        .context(format!("Failed to open zip file: {}", input_path))?;
    let mut archive = ZipArchive::new(zip_file)?;

    let version_info: VersionInfo = {
        let mut version_file = archive
            .by_name("version.json")
            .context("version.json not found in zip file. This zip may have been created with an older version of the signer tool.")?;
        let mut contents = String::new();
        version_file
            .read_to_string(&mut contents)
            .context("Failed to read version.json")?;
        serde_json::from_str(&contents).context("Failed to parse version.json")?
    };

    let version = &version_info.version;
    let firmware_version = strip_v_prefix(version);
    println!("  {} Version from zip: {}", "→".blue(), version);

    // Create temp directory
    let temp_dir = TempDir::new().context("Failed to create temp directory")?;
    let temp_path = temp_dir.path();

    println!("Extracting to temporary directory...");

    // Re-open the archive since we consumed it reading version.json
    let zip_file = File::open(input_path)
        .context(format!("Failed to open zip file: {}", input_path))?;
    let mut archive = ZipArchive::new(zip_file)?;

    for i in 0..archive.len() {
        let mut file = archive.by_index(i)?;
        let outpath = temp_path.join(version).join(file.name());

        if file.is_dir() {
            fs::create_dir_all(&outpath)?;
        } else {
            if let Some(parent) = outpath.parent() {
                fs::create_dir_all(parent)?;
            }
            let mut outfile = File::create(&outpath)?;
            io::copy(&mut file, &mut outfile)?;
        }
    }

    println!("{} Extracted {} files", "✓".green(), archive.len());

    // Sign the files using existing sign_files function
    let version_folder = temp_path.join(version);
    let version_folder_str = version_folder.to_string_lossy().to_string();

    sign_files(&version_folder_str, &expanded_config, &firmware_version, is_developer)?;

    // Check signature status after signing to determine output filename
    let app_bin = version_folder.join("keyos/app.bin");
    let sig_status = check_signatures_quiet(&app_bin.to_string_lossy())?;
    let sig_count = sig_status.signature_count();

    let suffix = match sig_count {
        0 => "-unsigned",
        1 => "-partially-signed",
        _ => "-fully-signed",
    };

    // Determine final output path based on signature count
    let final_output_path = if output_path.contains("-signed") || output_path.contains("-unsigned") || output_path.contains("-partially") || output_path.contains("-fully") {
        // User provided explicit name, use it
        output_path.to_string()
    } else {
        // Generate name based on signature count
        let path = Path::new(output_path);
        let stem = path.file_stem().and_then(|s| s.to_str()).unwrap_or("Release");
        // Remove any existing suffix pattern like "-signed"
        let clean_stem = stem.trim_end_matches("-signed");
        format!("{}{}.zip", clean_stem, suffix)
    };

    // Create output zip with signed files
    println!("\nCreating signed zip: {}", final_output_path);

    let output_file = File::create(&final_output_path)
        .context(format!("Failed to create output zip: {}", final_output_path))?;
    let mut zip = ZipWriter::new(output_file);
    let options = SimpleFileOptions::default()
        .compression_method(zip::CompressionMethod::Deflated);
    let mut packaged_names = HashSet::new();

    // Re-package the signed files
    let mut file_count = 0;
    for i in 0..archive.len() {
        let file = archive.by_index(i)?;
        if file.is_dir() {
            continue;
        }

        let file_name = file.name();
        let signed_file_path = temp_path.join(version).join(file_name);

        if signed_file_path.exists() {
            zip.start_file(file_name, options)?;
            let mut signed_file = File::open(&signed_file_path)?;
            let mut buffer = Vec::new();
            signed_file.read_to_end(&mut buffer)?;
            zip.write_all(&buffer)?;
            file_count += 1;
            packaged_names.insert(file_name.to_string());
        }
    }

    // sign_files packs these only when this signer completed the required signatures. They are
    // not present in the incoming signing zip, so append them explicitly to the outgoing zip.
    let sideload_apps_dir = version_folder.join("sideload-apps");
    if sideload_apps_dir.is_dir() {
        let mut app_archives = Vec::new();
        for entry in fs::read_dir(&sideload_apps_dir)? {
            let path = entry?.path();
            if path.extension().is_some_and(|extension| extension == APP_ARCHIVE_EXTENSION) {
                app_archives.push(path);
            }
        }
        app_archives.sort();
        for archive_path in app_archives {
            let relative_path = archive_path
                .strip_prefix(&version_folder)
                .expect("app archive is inside the version folder")
                .to_string_lossy()
                .to_string();
            if packaged_names.insert(relative_path.clone()) {
                zip.start_file(&relative_path, options)?;
                let mut archive_file = File::open(&archive_path)?;
                io::copy(&mut archive_file, &mut zip)?;
                file_count += 1;
                println!("  {} Added {} to zip", "→".blue(), relative_path);
            }
        }
    }

    // sign_files owns bootloader signing. Preserve its output even when the incoming zip only
    // carried boot.cip/boot.bin and therefore had no boot-signed file to replace in the loop.
    for file_name in ["boot-signed.cip", "boot-signed.bin"] {
        let path = version_folder.join(file_name);
        if path.is_file() && packaged_names.insert(file_name.to_string()) {
            zip.start_file(file_name, options)?;
            let mut file = File::open(&path)?;
            io::copy(&mut file, &mut zip)?;
            file_count += 1;
            println!("  {} Added {} to zip", "→".blue(), file_name);
        }
    }

    zip.finish()?;

    // Get absolute path for display
    let absolute_output = if Path::new(&final_output_path).is_absolute() {
        final_output_path.clone()
    } else {
        std::env::current_dir()
            .map(|cwd| cwd.join(&final_output_path).to_string_lossy().to_string())
            .unwrap_or_else(|_| final_output_path.clone())
    };

    println!(
        "\n{} {} ({} files)\n",
        "✓".green().bold(),
        format!("Signed zip created: {}", absolute_output).green().bold(),
        file_count
    );

    Ok(())
}

fn unpack_zip(version_folder: &str, input_path: &str) -> Result<()> {
    println!(
        "{}",
        format!("Unpacking signed files from: {}", input_path).bold()
    );

    if !Path::new(input_path).exists() {
        return Err(SignerError::FileNotFound(input_path.to_string()).into());
    }

    let zip_file = File::open(input_path)
        .context(format!("Failed to open zip file: {}", input_path))?;
    let mut archive = ZipArchive::new(zip_file)?;

    println!("\nExtracting files:");
    let mut file_count = 0;

    for i in 0..archive.len() {
        let mut file = archive.by_index(i)?;
        if file.is_dir() {
            continue;
        }

        let outpath = Path::new(version_folder).join(file.name());

        print!("  {} {}...", "→".blue(), file.name());

        if let Some(parent) = outpath.parent() {
            fs::create_dir_all(parent)?;
        }

        let mut outfile = File::create(&outpath)?;
        io::copy(&mut file, &mut outfile)?;

        println!(" {}", "✓".green());
        file_count += 1;
    }

    println!(
        "\n{} {} ({} files)",
        "✓".green().bold(),
        format!("Unpacked to: {}", version_folder).green().bold(),
        file_count
    );

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_manifest(bundle_dir: &Path, signed: bool) {
        let json = serde_json::json!({
            "appName": { "en": "Example" },
            "appId": "0x00112233445566778899aabbccddeeff",
            "fileHashes": {
                "resources/logo.bin": "00",
                "icon.bin": "00",
                "app.elf": "00"
            }
        });
        let mut bytes = if signed { vec![0; COSIGN2_HEADER_SIZE] } else { Vec::new() };
        bytes.extend(serde_json::to_vec(&json).unwrap());
        fs::write(bundle_dir.join(APP_MANIFEST_FILE), bytes).unwrap();
    }

    fn app_archive_entry_names(archive_path: &Path) -> Vec<String> {
        let archive = File::open(archive_path).unwrap();
        tar::Archive::new(GzDecoder::new(archive))
            .entries()
            .unwrap()
            .map(|entry| entry.unwrap().path().unwrap().display().to_string())
            .collect()
    }

    #[test]
    fn packs_the_sdk_app_archive_layout_reproducibly() {
        let temp = tempfile::tempdir().unwrap();
        let bundle_dir = temp.path().join("example");
        fs::create_dir_all(bundle_dir.join("resources")).unwrap();
        fs::write(bundle_dir.join("app.elf"), b"signed elf").unwrap();
        fs::write(bundle_dir.join("icon.bin"), b"icon").unwrap();
        fs::write(bundle_dir.join("resources/logo.bin"), b"logo").unwrap();
        write_manifest(&bundle_dir, true);

        let first = temp.path().join("first.app");
        let second = temp.path().join("second.app");
        pack_app_bundle(&bundle_dir, &first).unwrap();
        pack_app_bundle(&bundle_dir, &second).unwrap();

        assert_eq!(
            app_archive_entry_names(&first),
            ["manifest.json", "app.elf", "icon.bin", "resources/logo.bin"]
        );
        assert_eq!(fs::read(&first).unwrap(), fs::read(&second).unwrap());
        validate_app_archive(&bundle_dir, &first).unwrap();

        fs::write(bundle_dir.join("icon.bin"), b"changed icon").unwrap();
        assert!(validate_app_archive(&bundle_dir, &first).is_err());
    }

    #[test]
    fn reads_file_hashes_before_and_after_cosign2_signing() {
        let temp = tempfile::tempdir().unwrap();
        write_manifest(temp.path(), false);
        let unsigned = app_manifest_hashed_files(temp.path()).unwrap();
        write_manifest(temp.path(), true);
        let signed = app_manifest_hashed_files(temp.path()).unwrap();

        assert_eq!(unsigned, signed);
        assert_eq!(unsigned, ["app.elf", "icon.bin", "resources/logo.bin"]);
    }
}
