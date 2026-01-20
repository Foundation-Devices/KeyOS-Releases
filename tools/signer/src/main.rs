use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use colored::Colorize;
use regex::Regex;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::{self, File};
use std::io;
use std::path::Path;
use std::process::Command;
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

    #[allow(dead_code)]
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
        /// Version number (e.g., 1.0.2)
        version: String,

        /// Path to cosign2 configuration file
        #[arg(default_value = "~/cosign2.toml")]
        config_path: String,

        #[arg(long)]
        developer: bool,
    },

    /// Create recovery tar file (only when all files have two signatures)
    CreateRecoveryTar {
        /// Version number (e.g., 1.0.2)
        version: String,

        /// Supply this argument to produce a Core System Recovery tar file that includes
        /// the bootloader (boot.cip or boot.bin) and recovery OS (recovery.bin) in addition
        /// to the standard KeyOS files.
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

        /// Only check individual binary files (app.bin, recovery.bin, apps);
        /// skip manifest and tar file validation
        #[arg(long)]
        files_only: bool,

        /// Development mode: accept files with only one signature instead of requiring two
        #[arg(long)]
        dev: bool,
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
        Commands::CreateRecoveryTar {
            version,
            core_system_recovery,
            allow_one_signature,
        } => {
            let version_folder = version.clone();
            let firmware_version = strip_v_prefix(version);
            create_tar(
                &version_folder,
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

    // Sign keyos/app.bin
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

    // Sign recovery.bin
    print!(
        "Signing recovery image ({})...",
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

    // Sign each dynamically loadable app
    println!(
        "\n{}",
        format!(
            "Looking for dynamically loadable apps in {}/apps/...",
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

                let mut args = vec![
                    "sign",
                    "-i",
                    app_path,
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
            }
        } else {
            println!("{}", "No dynamically loadable apps found".yellow());
        }
    } else {
        println!(
            "{}",
            format!("No apps directory found at {}/apps/", version_folder).yellow()
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
    version_folder: &str,
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

    let app_bin = format!("{}/keyos/app.bin", version_folder);

    let mut all_signed = true;
    let mut unsigned_files = Vec::new();

    let app_status = check_signatures(&app_bin)?;
    if !app_status.has_second_signature && !allow_one_signature {
        all_signed = false;
        unsigned_files.push("keyos/app.bin".to_string());
    }

    // Check recovery.bin (always check, but only include in core system recovery tar)
    let recovery_bin = format!("{}/recovery.bin", version_folder);
    let recovery_status = check_signatures(&recovery_bin)?;
    if !recovery_status.has_second_signature && !allow_one_signature {
        all_signed = false;
        unsigned_files.push("recovery.bin".to_string());
    }

    // Check all app files
    let apps_dir = format!("{}/keyos/apps", version_folder);
    let apps_path = Path::new(&apps_dir);

    if apps_path.is_dir() {
        for entry in fs::read_dir(apps_path).context("Failed to read apps directory")? {
            let entry = entry.context("Failed to read directory entry")?;
            let path = entry.path();

            // Found an app dir, it should contain an app .elf and a manifest
            if path.is_dir() {
                let elf_path = format!("{}/app.elf", path.display());
                let app_status = check_signatures(&elf_path)?;
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

    // Generate manifest file
    println!("Generating manifest file...");

    generate_manifest(version_folder, firmware_version, is_core_system_recovery)?;

    println!("{} Manifest file generated successfully", "✓".green());

    // Create tar file with appropriate naming (v prefix for customer-facing files)
    let tar_file = if is_core_system_recovery {
        format!(
            "{}/KeyOS-v{}-CoreSystemRecovery.tar",
            version_folder, firmware_version
        )
    } else {
        format!(
            "{}/KeyOS-v{}-Recovery.tar",
            version_folder, firmware_version
        )
    };

    // Collect all files to include in the tar
    let mut files_to_include = Vec::new();

    // For core system recovery, include bootloader and recovery OS
    if is_core_system_recovery {
        // Add bootloader - prefer boot.cip if it exists (secure boot mode), otherwise boot.bin
        // Do NOT rename - the ROM bootloader expects boot.cip in secure boot mode
        let boot_cip = format!("{}/boot.cip", version_folder);
        let boot_bin = format!("{}/boot.bin", version_folder);

        if Path::new(&boot_cip).exists() {
            println!(
                "{} Including bootloader: boot.cip (secure boot mode)",
                "→".blue()
            );
            files_to_include.push(boot_cip);
        } else if Path::new(&boot_bin).exists() {
            println!("{} Including bootloader: boot.bin", "→".blue());
            files_to_include.push(boot_bin);
        } else {
            return Err(SignerError::FileNotFound(
                "Neither boot.cip nor boot.bin found. At least one is required for core system recovery.".to_string()
            ).into());
        }

        // Add recovery.bin
        println!("{} Including recovery OS: recovery.bin", "→".blue());
        files_to_include.push(recovery_bin);
    }

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

    println!(
        "{} Tar file created successfully: {}",
        "✓".green(),
        tar_file
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
    Ok(())
}

fn sign_tar(version_folder: &str, config_path: &str, firmware_version: &str) -> Result<()> {
    println!(
        "{}",
        format!(
            "Signing recovery tar files for version {}",
            firmware_version
        )
        .bold()
    );

    // Sign both recovery tar files
    let recovery_tar = format!(
        "{}/KeyOS-v{}-Recovery.tar",
        version_folder, firmware_version
    );
    let core_recovery_tar = format!(
        "{}/KeyOS-v{}-CoreSystemRecovery.tar",
        version_folder, firmware_version
    );

    let mut signed_count = 0;
    let mut skipped_count = 0;

    // Sign Recovery.tar if it exists
    if Path::new(&recovery_tar).exists() {
        match sign_single_tar(&recovery_tar, config_path, firmware_version)? {
            true => signed_count += 1,
            false => skipped_count += 1,
        }
    } else {
        println!(
            "  {} KeyOS-v{}-Recovery.tar not found, skipping",
            "⚠".yellow(),
            firmware_version
        );
    }

    // Sign CoreSystemRecovery.tar if it exists
    if Path::new(&core_recovery_tar).exists() {
        match sign_single_tar(&core_recovery_tar, config_path, firmware_version)? {
            true => signed_count += 1,
            false => skipped_count += 1,
        }
    } else {
        println!(
            "  {} KeyOS-v{}-CoreSystemRecovery.tar not found, skipping",
            "⚠".yellow(),
            firmware_version
        );
    }

    if signed_count == 0 && skipped_count == 0 {
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
            "Tar file signing complete for version {} ({} signed, {} already complete)",
            firmware_version, signed_count, skipped_count
        )
        .green()
        .bold()
    );
    Ok(())
}

/// Sign a single tar file. Returns true if signed, false if already fully signed.
fn sign_single_tar(tar_file: &str, config_path: &str, firmware_version: &str) -> Result<bool> {
    let file_name = Path::new(tar_file)
        .file_name()
        .unwrap()
        .to_string_lossy()
        .to_string();

    println!("\nChecking signatures on {}...", file_name);

    // Check signature status (quiet - we print our own messages)
    let signature_status = check_signatures_quiet(tar_file)?;

    // Sign based on current signature status
    if !signature_status.has_header {
        println!(
            "  {} {} has no signature header. Adding first signature...",
            "ℹ".blue(),
            file_name
        );
    } else if !signature_status.has_first_signature {
        println!(
            "  {} {} has a header but no valid signatures. Adding first signature...",
            "ℹ".blue(),
            file_name
        );
    } else if !signature_status.has_second_signature {
        println!(
            "  {} {} has one signature. Adding second signature...",
            "ℹ".blue(),
            file_name
        );
    } else {
        println!("  {} {} already has two signatures", "✓".green(), file_name);
        return Ok(false);
    }

    // Sign the tar file
    let output = Command::new("cosign2")
        .args([
            "sign",
            "-i",
            tar_file,
            "-c",
            config_path,
            "--in-place",
            "--binary-version",
            firmware_version,
        ])
        .output()
        .context(format!(
            "Failed to execute cosign2 command for {}",
            file_name
        ))?;

    if !output.status.success() {
        println!("  {} Failed to sign {}", "✗".red(), file_name);
        return Err(SignerError::CommandFailed(
            String::from_utf8_lossy(&output.stderr).to_string(),
        )
        .into());
    }

    println!("  {} {} signed successfully", "✓".green(), file_name);
    Ok(true)
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

    // === Apps (keyos/apps/{app_name}/app.elf) ===
    let apps_dir = format!("{}/keyos/apps", version_folder);
    let apps_path = Path::new(&apps_dir);

    if !apps_path.is_dir() {
        println!("  {} keyos/apps/ directory is missing", "✗".red());
        missing_files.push("keyos/apps/".to_string());
        all_valid = false;
    } else {
        let mut app_count = 0;

        for entry in fs::read_dir(apps_path).context("Failed to read apps directory")? {
            let entry = entry.context("Failed to read directory entry")?;
            let path = entry.path();

            // Apps are in subdirectories: keyos/apps/{app_name}/app.elf
            if path.is_dir() {
                let app_name = path
                    .file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or("unknown");
                let elf_path = path.join("app.elf");
                let manifest_path = path.join("manifest.json");

                if elf_path.exists() {
                    app_count += 1;
                    let elf_path_str = elf_path.to_string_lossy();
                    let app_status = check_signatures_quiet(&elf_path_str)?;

                    let has_manifest = manifest_path.exists();
                    let manifest_status = if has_manifest {
                        ""
                    } else {
                        " (missing manifest.json)"
                    };

                    if check_sig_requirement(&app_status) {
                        println!(
                            "  {} keyos/apps/{}/app.elf{}",
                            "✓".green(),
                            app_name,
                            manifest_status
                        );
                        if !has_manifest {
                            missing_files.push(format!("keyos/apps/{}/manifest.json", app_name));
                            all_valid = false;
                        }
                    } else {
                        println!(
                            "  {} keyos/apps/{}/app.elf ({} of {} signatures){}",
                            "✗".red(),
                            app_name,
                            app_status.signature_count(),
                            required_sigs,
                            manifest_status
                        );
                        insufficient_sigs.push(format!("keyos/apps/{}/app.elf", app_name));
                        all_valid = false;
                        if !has_manifest {
                            missing_files.push(format!("keyos/apps/{}/manifest.json", app_name));
                        }
                    }
                }
            }
        }

        if app_count == 0 {
            println!("  {} No apps found in keyos/apps/", "⚠".yellow());
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

        // Check Recovery tar: KeyOS-v{version}-Recovery.tar
        let recovery_tar = format!(
            "{}/KeyOS-v{}-Recovery.tar",
            version_folder, firmware_version
        );
        if Path::new(&recovery_tar).exists() {
            let tar_status = check_signatures_quiet(&recovery_tar)?;
            if check_sig_requirement(&tar_status) {
                println!("  {} KeyOS-v{}-Recovery.tar", "✓".green(), firmware_version);
            } else {
                println!(
                    "  {} KeyOS-v{}-Recovery.tar ({} of {} signatures)",
                    "✗".red(),
                    firmware_version,
                    tar_status.signature_count(),
                    required_sigs
                );
                insufficient_sigs.push(format!("KeyOS-v{}-Recovery.tar", firmware_version));
                all_valid = false;
            }
        } else {
            println!(
                "  {} KeyOS-v{}-Recovery.tar is missing",
                "⚠".yellow(),
                firmware_version
            );
            // Not a hard failure - might not have been created yet
        }

        // Check Core System Recovery tar: KeyOS-v{version}-CoreSystemRecovery.tar
        let core_recovery_tar = format!(
            "{}/KeyOS-v{}-CoreSystemRecovery.tar",
            version_folder, firmware_version
        );
        if Path::new(&core_recovery_tar).exists() {
            let tar_status = check_signatures_quiet(&core_recovery_tar)?;
            if check_sig_requirement(&tar_status) {
                println!(
                    "  {} KeyOS-v{}-CoreSystemRecovery.tar",
                    "✓".green(),
                    firmware_version
                );
            } else {
                println!(
                    "  {} KeyOS-v{}-CoreSystemRecovery.tar ({} of {} signatures)",
                    "✗".red(),
                    firmware_version,
                    tar_status.signature_count(),
                    required_sigs
                );
                insufficient_sigs.push(format!(
                    "KeyOS-v{}-CoreSystemRecovery.tar",
                    firmware_version
                ));
                all_valid = false;
            }
        } else {
            println!(
                "  {} KeyOS-v{}-CoreSystemRecovery.tar is missing",
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

    // For core system recovery, include bootloader and recovery OS
    if is_core_system_recovery {
        // Add bootloader - prefer boot.cip if it exists (secure boot mode), otherwise boot.bin
        let boot_cip = format!("{}/boot.cip", version_folder);
        let boot_bin = format!("{}/boot.bin", version_folder);

        if Path::new(&boot_cip).exists() {
            let boot_hash = calculate_hash(&boot_cip)?;
            manifest.files.push(FileEntry {
                name: "boot.cip".to_string(),
                hash: format!("0x{}", boot_hash),
            });
        } else if Path::new(&boot_bin).exists() {
            let boot_hash = calculate_hash(&boot_bin)?;
            manifest.files.push(FileEntry {
                name: "boot.bin".to_string(),
                hash: format!("0x{}", boot_hash),
            });
        }

        // Add recovery.bin
        let recovery_bin = format!("{}/recovery.bin", version_folder);
        if Path::new(&recovery_bin).exists() {
            let recovery_hash = calculate_hash(&recovery_bin)?;
            manifest.files.push(FileEntry {
                name: "recovery.bin".to_string(),
                hash: format!("0x{}", recovery_hash),
            });
        }
    }

    // Add keyos/app.bin to manifest
    let app_bin = format!("{}/keyos/app.bin", version_folder);
    let app_hash = calculate_hash(&app_bin)?;
    manifest.files.push(FileEntry {
        name: "keyos/app.bin".to_string(),
        hash: format!("0x{}", app_hash),
    });

    // Add each app to manifest
    let apps_dir = format!("{}/keyos/apps", version_folder);
    let apps_path = Path::new(&apps_dir);

    let mut _app_count = 0;
    if apps_path.is_dir() {
        for entry in fs::read_dir(apps_path).context("Failed to read apps directory")? {
            let entry = entry.context("Failed to read directory entry")?;
            let path = entry.path();

            // Apps are in subdirectories: keyos/apps/{app_name}/app.elf
            if path.is_dir() {
                let app_name = path
                    .file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or("unknown");
                let elf_path = path.join("app.elf");

                if elf_path.exists() {
                    let app_hash = calculate_hash(elf_path.to_str().unwrap())?;

                    manifest.files.push(FileEntry {
                        name: format!("apps/{}/app.elf", app_name),
                        hash: format!("0x{}", app_hash),
                    });

                    _app_count += 1;
                }
            }
        }
        // App count is displayed in the calling function
    }

    // Write manifest to file
    let manifest_json =
        serde_json::to_string_pretty(&manifest).context("Failed to serialize manifest to JSON")?;

    fs::write(&manifest_file, manifest_json)
        .context(format!("Failed to write manifest file: {}", manifest_file))?;
    Ok(())
}

fn calculate_hash(file_path: &str) -> Result<String> {
    let mut file =
        File::open(file_path).context(format!("Failed to open file for hashing: {}", file_path))?;

    let mut hasher = Sha256::new();
    io::copy(&mut file, &mut hasher)
        .context(format!("Failed to read file for hashing: {}", file_path))?;

    let hash = hasher.finalize();
    Ok(hex::encode(hash))
}
