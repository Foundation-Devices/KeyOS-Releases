use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use colored::Colorize;
use regex::Regex;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::{self, File};
use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::str::FromStr;
use thiserror::Error;

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

    #[error("Invalid version format: {0}")]
    InvalidVersion(String),
}

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Sign individual files with the provided key
    SignFiles {
        /// Version number (e.g., 1.0.2 or v1.0.2)
        version: String,

        /// Path to cosign2 configuration file
        #[arg(default_value = "~/cosign2.toml")]
        config_path: String,

        /// Developer mode signing (one signature)
        #[arg(long)]
        developer: bool,

        /// Sign the bootloader (boot.bin or boot.cip), should be done before creating the critical recovery image
        #[arg(long)]
        sign_bootloader: bool,
    },

    /// Create tar file (only when all files have two signatures)
    CreateTar {
        /// Version number (e.g., 1.0.2 or v1.0.2)
        version: String,

        /// Path to cosign2 configuration file. cosign2 is used to sign the recovery tar manifest file
        #[arg(default_value = "~/cosign2.toml")]
        config_path: String,

        /// Supply this argument to produce a tar file for the Firmware Recovery mode.
        #[arg(long)]
        recovery: bool,

        #[arg(long)]
        allow_one_signature: bool,
    },

    /// Sign the tar file with the provided key
    SignTar {
        /// Version number (e.g., 1.0.2 or v1.0.2)
        version: String,

        /// Path to cosign2 configuration file
        #[arg(default_value = "~/cosign2.toml")]
        config_path: String,
    },

    /// Validate that all files for a version are properly signed
    Validate {
        /// Version number (e.g., 1.0.2 or v1.0.2)
        version: String,
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

struct SignatureStatus {
    has_header: bool,
    has_first_signature: bool,
    has_second_signature: bool,
}

fn main() -> Result<()> {
    env_logger::init();

    let cli = Cli::parse();

    match &cli.command {
        Commands::SignFiles {
            version,
            config_path,
            developer,
            sign_bootloader,
        } => {
            let version_folder = version.clone();
            let firmware_version = strip_v_prefix(version);
            sign_files(
                &version_folder,
                config_path,
                &firmware_version,
                *developer,
                *sign_bootloader,
            )?;
        }
        Commands::CreateTar {
            config_path,
            version,
            recovery,
            allow_one_signature,
        } => {
            let version_folder = version.clone();
            let firmware_version = strip_v_prefix(version);
            create_tar(
                config_path,
                &version_folder,
                &firmware_version,
                *recovery,
                *allow_one_signature,
            )?;
        }
        Commands::SignTar {
            version,
            config_path,
        } => {
            let version_folder = version.clone();
            let firmware_version = strip_v_prefix(version);
            sign_tar(&version_folder, config_path, &firmware_version)?;
        }
        Commands::Validate { version } => {
            let version_folder = version.clone();
            let firmware_version = strip_v_prefix(version);
            validate(&version_folder, &firmware_version)?;
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

fn sign_files(
    version_folder: &str,
    config_path: &str,
    firmware_version: &str,
    is_developer: bool,
    sign_bootloader: bool,
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
    if Path::new(&app_bin).exists() {
        // Sign app.bin
        print!(
            "Signing KeyOS image ({})...",
            Path::new(&app_bin).file_name().unwrap().to_string_lossy()
        );

        let output = Command::new("cosign2")
            .args([
                "sign",
                "-i",
                &app_bin,
                "-c",
                config_path,
                "--in-place",
                "--binary-version",
                firmware_version,
                if is_developer { "--developer" } else { "" },
            ])
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
    } else {
        println!("  {} KeyOS image (app.bin) is not found", "⚠".yellow());
    }

    // Sign recovery.bin
    let recovery_bin = format!("{}/recovery.bin", version_folder);
    if Path::new(&recovery_bin).exists() {
        print!(
            "Signing Recovery OS image ({})...",
            Path::new(&recovery_bin)
                .file_name()
                .unwrap()
                .to_string_lossy()
        );

        let output = Command::new("cosign2")
            .args([
                "sign",
                "-i",
                &recovery_bin,
                "-c",
                config_path,
                "--in-place",
                "--binary-version",
                firmware_version,
                if is_developer { "--developer" } else { "" },
            ])
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
    }

    if sign_bootloader {
        let boot_bin = format!("{}/boot.bin", version_folder);
        let boot_cip = format!("{}/boot.cip", version_folder);
        let has_boot_bin = Path::new(&boot_bin).exists();
        let has_boot_cip = Path::new(&boot_cip).exists();
        if has_boot_bin || has_boot_cip {
            let bootloader = format!(
                "{version_folder}/{}",
                if has_boot_cip { "boot.cip" } else { "boot.bin" }
            );

            print!(
                "Signing bootloader ({})...",
                Path::new(&bootloader)
                    .file_name()
                    .unwrap()
                    .to_string_lossy()
            );

            let output = Command::new("cosign2")
                .args([
                    "sign",
                    "-i",
                    &bootloader,
                    "-c",
                    config_path,
                    "--in-place",
                    "--binary-version",
                    firmware_version,
                    if is_developer { "--developer" } else { "" },
                ])
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
        }
    }

    // Sign each dynamically loadable app
    println!(
        "\n{}",
        format!(
            "Looking for dynamically loadable apps in {}/keyos/apps/...",
            version_folder
        )
        .bold()
    );
    let apps_dir = format!("{}/keyos/apps", version_folder);
    let apps_path = Path::new(&apps_dir);

    if apps_path.is_dir() {
        let mut apps = Vec::new();
        for entry in fs::read_dir(apps_path).context("Failed to read apps directory")? {
            let entry = entry.context("Failed to read directory entry")?;
            let path = entry.path();

            // Found an app dir, it should contain an app .elf and a manifest
            if path.is_dir() {
                let elf_path = path.clone().join("app.elf");
                let manifest_path = path.clone().join("manifest.json");
                if elf_path.exists() && manifest_path.exists() {
                    apps.push((elf_path, manifest_path));
                }
            }
        }

        if !apps.is_empty() {
            println!("Found {} dynamically loadable apps", apps.len());

            // Sign each app
            for (elf_path, _manifest_path) in apps {
                print!("Signing app: {}...", elf_path.display());

                let app_path = elf_path.to_str().unwrap();

                let output = Command::new("cosign2")
                    .args([
                        "sign",
                        "-i",
                        app_path,
                        "-c",
                        config_path,
                        "--in-place",
                        "--binary-version",
                        firmware_version,
                        if is_developer { "--developer" } else { "" },
                    ])
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
            }
        } else {
            println!("{}", "No dynamically loadable apps found".yellow());
        }
    } else {
        println!(
            "{}",
            format!("No apps directory found at {}/keyos/apps/", version_folder).yellow()
        );
    }

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
    config_path: &str,
    version_folder: &str,
    firmware_version: &str,
    is_recovery: bool,
    allow_one_signature: bool,
) -> Result<()> {
    println!(
        "{}",
        format!(
            "Creating {}tar file for version {}",
            if is_recovery { "recovery " } else { "" },
            firmware_version
        )
        .bold()
    );

    // Check if version folder exists
    if !Path::new(version_folder).is_dir() {
        return Err(SignerError::DirectoryNotFound(version_folder.to_string()).into());
    }

    println!("Checking signatures on all files...");

    let app_bin = format!("{}/keyos/app.bin", version_folder);
    let recovery_bin = format!("{}/recovery.bin", version_folder);

    let has_app_bin = Path::new(&app_bin).exists();
    let has_recovery_bin = Path::new(&recovery_bin).exists();

    if is_recovery {
        if has_app_bin && has_recovery_bin {
            println!("{} Both app.bin and recovery.bin found. Only one of them is allowed in the recovery archive", "✗".red());
            return Err(SignerError::CommandFailed(
                "Both app.bin and recovery.bin found in recovery mode".to_string(),
            )
            .into());
        }
    } else if !has_app_bin {
        println!("{} No app.bin found", "✗".red());
        if has_recovery_bin {
            println!(
                "  {} recovery OS (recovery.bin) is found but the signer tool is not running in recovery mode",
                "⚠".yellow()
            );
        }
        return Err(SignerError::CommandFailed("No app.bin found".to_string()).into());
    }

    let mut all_signed = true;
    let mut unsigned_files = Vec::new();

    if has_app_bin {
        let app_status = check_signatures(&app_bin, allow_one_signature)?;
        if !app_status.has_second_signature && !allow_one_signature {
            all_signed = false;
            unsigned_files.push("keyos/app.bin".to_string());
        }
    }

    if is_recovery && has_recovery_bin {
        let recovery_status = check_signatures(&recovery_bin, allow_one_signature)?;
        if !recovery_status.has_second_signature && !allow_one_signature {
            all_signed = false;
            unsigned_files.push("recovery.bin".to_string());
        }
    }

    // Check all app files
    let apps_dir = format!("{}/keyos/apps", version_folder);
    let apps_path = Path::new(&apps_dir);

    if apps_path.is_dir() && has_app_bin {
        for entry in fs::read_dir(apps_path).context("Failed to read apps directory")? {
            let entry = entry.context("Failed to read directory entry")?;
            let path = entry.path();

            // Found an app dir, it should contain an app .elf and a manifest
            if path.is_dir() {
                let elf_path = format!("{}/app.elf", path.display());
                let app_status = check_signatures(&elf_path, allow_one_signature)?;
                if allow_one_signature && !app_status.has_second_signature {
                    all_signed = false;
                    unsigned_files.push(elf_path);
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

    // Collect all files to include in the tar
    let mut files_to_include = Vec::new();

    // Add recovery.bin (optional)
    if is_recovery && has_recovery_bin {
        files_to_include.push(recovery_bin);
        println!(
            "  {} recovery OS (recovery.bin) will be included",
            "⚠".yellow()
        );
    }

    // Add bootloader (boot.bin or boot.cip; latter takes precedence)
    let boot_cip = format!("{}/boot.cip", version_folder);
    let has_boot_cip = Path::new(&boot_cip).exists();
    let boot_bin = format!("{}/boot.bin", version_folder);
    let has_boot_bin = Path::new(&boot_bin).exists();
    if has_boot_cip {
        files_to_include.push(boot_cip);
        println!("  {} bootloader (boot.cip) will be included", "⚠".yellow());
        if has_boot_bin {
            println!(
                "  {} boot.bin exists but ignored because boot.cip takes precedence",
                "⚠".yellow()
            );
        }
    } else if has_boot_bin {
        println!("  {} bootloader (boot.bin) will be included", "⚠".yellow());
        files_to_include.push(boot_bin);
    }

    // Create the tar file
    let tar_file = format!("{}/KeyOS-v{}.bin", version_folder, firmware_version);

    // Add app.bin
    if has_app_bin {
        files_to_include.push(app_bin);
    }

    // Add manifest.json
    let manifest_file = format!("{}/manifest.json", version_folder);
    files_to_include.push(manifest_file.clone());

    // Add all .elf files in the apps directory
    let apps_dir = format!("{}/keyos/apps", version_folder);
    let apps_path = Path::new(&apps_dir);
    if apps_path.is_dir() && has_app_bin {
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
    let common_dir = format!("{}/keyos/common", version_folder);
    let num_assets = collect_files_recursively(Path::new(&common_dir), &mut files_to_include)?;

    // Add all recovery OS assets in the common directory
    let mut num_assets_recovery_os = 0;
    let common_boot_dir = format!("{}/common-boot", version_folder);
    if !has_app_bin {
        num_assets_recovery_os =
            collect_files_recursively(Path::new(&common_boot_dir), &mut files_to_include)?;
    }

    // Add all bootloader assets in the blassets
    let mut num_assets_bootloader = 0;
    let blassets = format!("{}/blassets", version_folder);
    let blassets_path = Path::new(&blassets);
    if blassets_path.exists() && blassets_path.is_dir() && (has_boot_cip || has_boot_bin) {
        for entry in fs::read_dir(blassets_path).context("Failed to read blassets directory")? {
            let entry = entry.context("Failed to read directory entry")?;
            let path = entry.path();

            if path.is_file() && path.extension().map_or(false, |ext| ext == "raw") {
                files_to_include.push(path.to_string_lossy().to_string());
                num_assets_bootloader += 1;
            } else {
                println!(
                    "  {} Non-raw file found in blassets: {}",
                    "⚠".yellow(),
                    path.display(),
                );
            }
        }
    }

    println!("{} Included {num_assets} KeyOS assets", "✓".green());
    if num_assets_recovery_os != 0 {
        println!(
            "{} Included {num_assets_recovery_os} Recovery OS assets",
            "✓".green()
        );
    }
    if num_assets_bootloader != 0 {
        println!(
            "{} Included {num_assets_bootloader} bootloader assets",
            "✓".green()
        );
    }

    // Generate manifest file
    println!("Generating manifest file...");

    generate_manifest(
        config_path,
        allow_one_signature,
        version_folder,
        firmware_version,
        &files_to_include,
    )?;

    println!("{} Manifest file generated successfully", "✓".green());

    println!(
        "Creating tar file: {}...",
        Path::new(&tar_file).file_name().unwrap().to_string_lossy()
    );

    // Build the tar command with an explicit file list
    let mut tar_cmd = Command::new("tar");
    tar_cmd.arg("-cf").arg(&tar_file);

    // Add all collected files
    for file in &files_to_include {
        tar_cmd.arg(file);
    }

    // Execute the tar command
    let output = tar_cmd.output().context("Failed to execute tar command")?;

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

    println!("{} Tar file created successfully", "✓".green());

    println!(
        "\n{} {}",
        "✓".green().bold(),
        format!(
            "Tar file creation completed for version {}",
            firmware_version
        )
        .green()
        .bold()
    );
    Ok(())
}

fn collect_files_recursively(dir: &Path, files: &mut Vec<String>) -> Result<usize> {
    let mut count = 0;
    if dir.exists() && dir.is_dir() {
        for entry in fs::read_dir(dir).context("Failed to read directory")? {
            let entry = entry.context("Failed to read directory entry")?;
            let path = entry.path();
            if path.is_file() {
                files.push(path.to_string_lossy().to_string());
                count += 1;
            } else if path.is_dir() {
                count += collect_files_recursively(&path, files)?;
            }
        }
    }
    Ok(count)
}

fn sign_tar(version_folder: &str, config_path: &str, firmware_version: &str) -> Result<()> {
    println!(
        "{}",
        format!("Signing tar file for version {}", firmware_version).bold()
    );

    let tar_file = format!("{}/KeyOS-v{}.bin", version_folder, firmware_version);

    // Check if tar file exists
    if !Path::new(&tar_file).exists() {
        return Err(SignerError::FileNotFound(format!(
            "Tar file not found: {}. Please run create-tar command first.",
            tar_file
        ))
        .into());
    }

    println!("Checking existing signatures on tar file...");

    // Check signature status
    let signature_status = check_signatures(&tar_file, false)?;

    // Sign based on current signature status
    if !signature_status.has_header {
        println!(
            "{} Tar file has no signature header. Adding first signature...",
            "ℹ".blue()
        );
    } else if !signature_status.has_first_signature {
        println!(
            "{} Tar file has a header but no valid signatures. Adding first signature...",
            "ℹ".blue()
        );
    } else if !signature_status.has_second_signature {
        println!(
            "{} Tar file has one signature. Adding second signature...",
            "ℹ".blue()
        );
    } else {
        println!(
            "{} Tar file already has two signatures. No more signatures can be added.",
            "✓".green()
        );
        println!(
            "{} {}",
            "✓".green().bold(),
            "Tar file is already fully signed.".green().bold()
        );
        return Ok(());
    }

    // Sign the tar file
    println!(
        "Signing tar file: {}...",
        Path::new(&tar_file).file_name().unwrap().to_string_lossy()
    );

    let output = Command::new("cosign2")
        .args([
            "sign",
            "-i",
            &tar_file,
            "-c",
            config_path,
            "--in-place",
            "--binary-version",
            firmware_version,
        ])
        .output()
        .context("Failed to execute cosign2 command for tar file")?;

    if !output.status.success() {
        println!("{} Failed to sign tar file", "✗".red());
        return Err(SignerError::CommandFailed(
            String::from_utf8_lossy(&output.stderr).to_string(),
        )
        .into());
    }

    println!("{} Tar file signed successfully", "✓".green());

    println!(
        "\n{} {}",
        "✓".green().bold(),
        format!("Tar file signing complete for version {}", firmware_version)
            .green()
            .bold()
    );
    Ok(())
}

fn validate(version_folder: &str, firmware_version: &str) -> Result<()> {
    println!(
        "{}",
        format!("Validating signatures for version {}", firmware_version).bold()
    );

    // Check if version folder exists
    if !Path::new(version_folder).is_dir() {
        println!("{} Version folder not found: {}", "✗".red(), version_folder);
        return Err(SignerError::DirectoryNotFound(version_folder.to_string()).into());
    }

    println!("Checking required files and signatures...");

    let mut all_valid = true;
    let mut missing_files = Vec::new();
    let mut unsigned_files = Vec::new();

    // Check app.bin
    let app_bin = format!("{}/keyos/app.bin", version_folder);
    if !Path::new(&app_bin).exists() {
        println!("  {} app.bin is missing", "✗".red());
        missing_files.push(app_bin.to_string());
        all_valid = false;
    } else {
        let app_status = check_signatures(&app_bin, false)?;
        if !app_status.has_second_signature {
            unsigned_files.push("keyos/app.bin".to_string());
            all_valid = false;
        }
    }

    // Check manifest.json
    let manifest_file = format!("{}/manifest.json", version_folder);
    if !Path::new(&manifest_file).exists() {
        println!("  {} manifest.json is missing", "✗".red());
        missing_files.push("manifest.json".to_string());
        all_valid = false;
    }

    // Check all app files
    let apps_dir = format!("{}/keyos/apps", version_folder);
    let apps_path = Path::new(&apps_dir);

    if !apps_path.is_dir() {
        println!("  {} apps directory is missing", "✗".red());
        missing_files.push("apps/".to_string());
        all_valid = false;
    } else {
        let mut app_count = 0;

        for entry in fs::read_dir(apps_path).context("Failed to read apps directory")? {
            let entry = entry.context("Failed to read directory entry")?;
            let path = entry.path();

            if path.is_file() && path.extension().map_or(false, |ext| ext == "elf") {
                if let Some(file_name) = path.file_name().and_then(|n| n.to_str()) {
                    if file_name.starts_with("gui-app") {
                        app_count += 1;
                        let app_path = path.to_str().unwrap();
                        let app_status = check_signatures(app_path, false)?;
                        if !app_status.has_second_signature {
                            unsigned_files.push(format!("apps/{}", file_name));
                            all_valid = false;
                        }
                    }
                }
            }
        }

        if app_count == 0 {
            println!("  {} No app files found in apps directory", "⚠".yellow());
        }
    }

    // Check KeyOS tar file
    let tar_file = format!("{}/KeyOS-v{}.bin", version_folder, firmware_version);
    if !Path::new(&tar_file).exists() {
        println!("  {} KeyOS-v{}.bin is missing", "✗".red(), firmware_version);
        missing_files.push(format!("KeyOS-v{}.bin", firmware_version));
        all_valid = false;
    } else {
        let tar_status = check_signatures(&tar_file, false)?;
        if !tar_status.has_second_signature {
            unsigned_files.push(format!("KeyOS-v{}.bin", firmware_version));
            all_valid = false;
        }
    }

    // Print summary
    println!("\nValidation Summary:");

    if !missing_files.is_empty() {
        println!("{} Missing files:", "✗".red());
        for file in missing_files {
            println!("  - {}", file);
        }
    }

    if !unsigned_files.is_empty() {
        println!("{} Files without two signatures:", "✗".red());
        for file in unsigned_files {
            println!("  - {}", file);
        }
    }

    if all_valid {
        println!(
            "\n{} {}",
            "✓".green().bold(),
            "All files exist and have two signatures.".green().bold()
        );
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

fn check_signatures(file_path: &str, is_dev: bool) -> Result<SignatureStatus> {
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
        println!("  {} {} has no signatures", "✗".red(), file_path);
        return Ok(SignatureStatus {
            has_header: false,
            has_first_signature: false,
            has_second_signature: false,
        });
    }

    // Check for zero signatures in signature2
    let re_sig2 = Regex::new(r"signature2.*0{64}")?;
    let sig2_is_empty = re_sig2.is_match(&stdout);
    if sig2_is_empty {
        println!("  {} {} has only one signature", "⚠".yellow(), file_path);
        return Ok(SignatureStatus {
            has_header: true,
            has_first_signature: true,
            has_second_signature: false,
        });
    }

    // Check for zero signatures in signature1
    let re_sig1 = Regex::new(r"signature1.*0{64}")?;
    let sig1_is_empty = re_sig1.is_match(&stdout);
    if is_dev {
        if !sig2_is_empty {
            println!("  {} {} has one signature (dev)", "✓".green(), file_path);

            return Ok(SignatureStatus {
                has_header: true,
                has_first_signature: false,
                has_second_signature: true,
            });
        }
    } else {
        if sig1_is_empty && sig2_is_empty {
            println!(
                "  {} {} has a header but no valid signatures",
                "✗".red(),
                file_path
            );
            return Ok(SignatureStatus {
                has_header: true,
                has_first_signature: false,
                has_second_signature: false,
            });
        }
    }

    // If we get here, the file has two signatures
    println!("  {} {} has two signatures", "✓".green(), file_path);
    Ok(SignatureStatus {
        has_header: true,
        has_first_signature: true,
        has_second_signature: true,
    })
}

fn generate_manifest(
    config_path: &str,
    is_developer: bool,
    version_folder: &str,
    firmware_version: &str,
    files: &[String],
) -> Result<()> {
    let manifest_file = format!("{}/manifest.json", version_folder);

    // Create manifest structure
    let mut manifest = Manifest {
        version: format!("v{}", firmware_version),
        files: Vec::new(),
    };

    // Add OS and app binaries into the manifest
    for file in files {
        // Skip the manifest file itself
        if *file == manifest_file {
            continue;
        }

        let has_cosign2_header = file.ends_with("app.bin")
            || file.ends_with("boot.bin")
            || file.ends_with("boot.cip")
            || file.ends_with("recovery.bin")
            || file.ends_with("app.elf");

        let hash = if has_cosign2_header {
            calculate_hash(&PathBuf::from_str(&file).unwrap())?
        } else {
            calculate_asset_hash(&PathBuf::from_str(&file).unwrap())?
        };

        manifest.files.push(FileEntry {
            name: file.to_string(),
            hash,
        });
    }

    // Add each app to manifest
    let apps_dir = format!("{}/keyos/apps", version_folder);
    let apps_path = Path::new(&apps_dir);

    if apps_path.is_dir() {
        for entry in fs::read_dir(apps_path).context("Failed to read apps directory")? {
            let entry = entry.context("Failed to read directory entry")?;
            let path = entry.path();

            if path.is_file() && path.extension().map_or(false, |ext| ext == "elf") {
                if let Some(file_name) = path.file_name().and_then(|n| n.to_str()) {
                    if file_name.starts_with("gui-app") {
                        let app_hash = calculate_hash(&path)?;

                        manifest.files.push(FileEntry {
                            name: format!("apps/{}", file_name),
                            hash: app_hash,
                        });
                    }
                }
            }
        }
    }

    // Write manifest to file
    let manifest_json =
        serde_json::to_string(&manifest).context("Failed to serialize manifest to JSON")?;

    fs::write(&manifest_file, manifest_json)
        .context(format!("Failed to write manifest file: {}", manifest_file))?;

    // Sign the manifest.json
    print!(
        "Signing manifest ({})...",
        Path::new(&manifest_file)
            .file_name()
            .unwrap()
            .to_string_lossy()
    );

    let output = Command::new("cosign2")
        .args([
            "sign",
            "-i",
            &manifest_file,
            "-c",
            config_path,
            "--in-place",
            "--binary-version",
            firmware_version,
            if is_developer { "--developer" } else { "" },
        ])
        .output()
        .context(format!("{} cosign2 error", "✗".red()))?;

    if !output.status.success() {
        let err = String::from_utf8_lossy(&output.stderr).to_string();
        println!("{} Failed to sign", "✗".red());

        return Err(SignerError::CommandFailed(err).into());
    }

    println!("{}", "✓ Success".green());

    Ok(())
}

fn calculate_cosign2_digest(path: &Path) -> Result<Option<String>> {
    use hex::ToHex;

    const COSIGN2_HEADER_SIZE: usize = 0x800;
    let file_data = fs::read(path).context(format!("Failed to read file: {}", path.display()))?;

    Ok(if file_data.len() > COSIGN2_HEADER_SIZE {
        let digest: String = sha2::Sha256::digest(&file_data[COSIGN2_HEADER_SIZE..]).encode_hex();
        Some(digest)
    } else {
        None
    })
}

fn calculate_asset_hash(asset_path: &Path) -> Result<String> {
    let mut file = File::open(asset_path).context(format!(
        "Failed to open asset file for hashing: {}",
        asset_path.display()
    ))?;

    let mut hasher = Sha256::new();
    io::copy(&mut file, &mut hasher).context(format!(
        "Failed to read file for hashing: {}",
        asset_path.display()
    ))?;

    let hash = hasher.finalize();
    Ok(hex::encode(hash))
}

fn calculate_hash(file_path: &Path) -> Result<String> {
    let Some(cosign2_digest) = calculate_cosign2_digest(file_path)? else {
        anyhow::bail!("File {} isn't signed with cosign2", file_path.display());
    };

    Ok(cosign2_digest.to_string())
}
