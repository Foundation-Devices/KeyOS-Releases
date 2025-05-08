use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use colored::Colorize;
use log::debug;
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
    },

    /// Create tar file (only when all files have two signatures)
    CreateTar {
        /// Version number (e.g., 1.0.2 or v1.0.2)
        version: String,
    },

    /// Sign the tar file with the provided key
    SignTar {
        /// Version number (e.g., 1.0.2 or v1.0.2)
        version: String,

        /// Path to cosign2 configuration file
        #[arg(default_value = "~/cosign2.toml")]
        config_path: String,
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
        } => {
            let version_folder = normalize_version(version)?;
            let firmware_version = strip_v_prefix(version);
            sign_files(&version_folder, config_path, &firmware_version)?;
        }
        Commands::CreateTar { version } => {
            let version_folder = normalize_version(version)?;
            let firmware_version = strip_v_prefix(version);
            create_tar(&version_folder, &firmware_version)?;
        }
        Commands::SignTar {
            version,
            config_path,
        } => {
            let version_folder = normalize_version(version)?;
            let firmware_version = strip_v_prefix(version);
            sign_tar(&version_folder, config_path, &firmware_version)?;
        }
    }

    Ok(())
}

fn normalize_version(version: &str) -> Result<String> {
    // Ensure version has a 'v' prefix
    if version.starts_with('v') {
        Ok(version.to_string())
    } else {
        Ok(format!("v{}", version))
    }
}

fn strip_v_prefix(version: &str) -> String {
    // Remove 'v' prefix if present for cosign2 --firmware-version parameter
    if version.starts_with('v') {
        version[1..].to_string()
    } else {
        version.to_string()
    }
}

fn sign_files(version_folder: &str, config_path: &str, firmware_version: &str) -> Result<()> {
    println!(
        "{}",
        format!("Signing files for version {}", firmware_version).bold()
    );

    // Check if version folder exists
    if !Path::new(version_folder).is_dir() {
        return Err(SignerError::DirectoryNotFound(version_folder.to_string()).into());
    }

    // Check for required files
    let recovery_bin = format!("{}/recovery.bin", version_folder);
    let app_bin = format!("{}/app.bin", version_folder);

    if !Path::new(&recovery_bin).exists() {
        return Err(SignerError::FileNotFound(recovery_bin).into());
    }

    if !Path::new(&app_bin).exists() {
        return Err(SignerError::FileNotFound(app_bin).into());
    }

    // Sign recovery.bin
    print!(
        "Signing recovery image ({})...",
        Path::new(&recovery_bin)
            .file_name()
            .unwrap()
            .to_string_lossy()
    );

    debug!("  File: {}", recovery_bin);
    debug!("  Config path: {}", config_path);
    debug!("  Firmware version: {}", firmware_version);

    let output = Command::new("cosign2")
        .args([
            "sign",
            "-i",
            &recovery_bin,
            "-c",
            config_path,
            "--in-place",
            "--firmware-version",
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

    // Sign app.bin
    print!(
        "Signing main firmware image ({})...",
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
            "--firmware-version",
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
    let apps_dir = format!("{}/apps", version_folder);
    let apps_path = Path::new(&apps_dir);

    let mut app_count = 0;

    if apps_path.is_dir() {
        let mut app_files = Vec::new();

        // Collect all app files first
        for entry in fs::read_dir(apps_path).context("Failed to read apps directory")? {
            let entry = entry.context("Failed to read directory entry")?;
            let path = entry.path();

            if path.is_file() && path.extension().map_or(false, |ext| ext == "elf") {
                if let Some(file_name) = path.file_name().and_then(|n| n.to_str()) {
                    if file_name.starts_with("gui-app") {
                        app_files.push((file_name.to_string(), path));
                        app_count += 1;
                    }
                }
            }
        }

        if app_count > 0 {
            println!("Found {} dynamically loadable apps", app_count);

            // Sign each app
            for (file_name, path) in app_files {
                print!("Signing app: {}...", file_name);

                let app_path = path.to_str().unwrap();

                let output = Command::new("cosign2")
                    .args([
                        "sign",
                        "-i",
                        app_path,
                        "-c",
                        config_path,
                        "--in-place",
                        "--firmware-version",
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

fn create_tar(version_folder: &str, firmware_version: &str) -> Result<()> {
    println!(
        "{}",
        format!("Creating tar file for version {}", firmware_version).bold()
    );

    // Check if version folder exists
    if !Path::new(version_folder).is_dir() {
        return Err(SignerError::DirectoryNotFound(version_folder.to_string()).into());
    }

    println!("Checking signatures on all files...");

    // Check recovery.bin and app.bin
    let recovery_bin = format!("{}/recovery.bin", version_folder);
    let app_bin = format!("{}/app.bin", version_folder);

    let mut all_signed = true;
    let mut unsigned_files = Vec::new();

    let recovery_status = check_signatures(&recovery_bin)?;
    if !recovery_status.has_second_signature {
        all_signed = false;
        unsigned_files.push("recovery.bin".to_string());
    }

    let app_status = check_signatures(&app_bin)?;
    if !app_status.has_second_signature {
        all_signed = false;
        unsigned_files.push("app.bin".to_string());
    }

    // Check all app files
    let apps_dir = format!("{}/apps", version_folder);
    let apps_path = Path::new(&apps_dir);

    if apps_path.is_dir() {
        for entry in fs::read_dir(apps_path).context("Failed to read apps directory")? {
            let entry = entry.context("Failed to read directory entry")?;
            let path = entry.path();

            if path.is_file() && path.extension().map_or(false, |ext| ext == "elf") {
                if let Some(file_name) = path.file_name().and_then(|n| n.to_str()) {
                    if file_name.starts_with("gui-app") {
                        let app_path = path.to_str().unwrap();
                        let app_status = check_signatures(app_path)?;
                        if !app_status.has_second_signature {
                            all_signed = false;
                            // Convert to owned String
                            unsigned_files.push(file_name.to_string());
                        }
                    }
                }
            }
        }
    }

    // Only proceed with tar file creation if all files are properly signed
    if !all_signed {
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

    println!("{} All files have two signatures", "✓".green());

    // Generate manifest file
    println!("Generating manifest file...");

    generate_manifest(version_folder, firmware_version)?;

    println!("{} Manifest file generated successfully", "✓".green());

    // Create tar file
    let tar_file = format!("{}/KeyOS-v{}.bin", version_folder, firmware_version);

    println!(
        "Creating tar file: {}...",
        Path::new(&tar_file).file_name().unwrap().to_string_lossy()
    );

    // Collect all files to include in the tar
    let mut files_to_include = Vec::new();

    // Add recovery.bin and app.bin
    let recovery_bin = format!("{}/recovery.bin", version_folder);
    let app_bin = format!("{}/app.bin", version_folder);
    files_to_include.push(recovery_bin);
    files_to_include.push(app_bin);

    // Add manifest.json
    let manifest_file = format!("{}/manifest.json", version_folder);
    files_to_include.push(manifest_file.clone());

    // Add all .elf files in the apps directory
    let apps_dir = format!("{}/apps", version_folder);
    let apps_path = Path::new(&apps_dir);
    if apps_path.is_dir() {
        for entry in fs::read_dir(apps_path).context("Failed to read apps directory")? {
            let entry = entry.context("Failed to read directory entry")?;
            let path = entry.path();

            if path.is_file() && path.extension().map_or(false, |ext| ext == "elf") {
                if let Some(file_name) = path.file_name().and_then(|n| n.to_str()) {
                    if file_name.starts_with("gui-app") {
                        files_to_include.push(path.to_string_lossy().to_string());
                    }
                }
            }
        }
    }

    // Build the tar command with explicit file list
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
            "Tar file creation complete for version {}",
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
    let signature_status = check_signatures(&tar_file)?;

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
            "--firmware-version",
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

fn check_signatures(file_path: &str) -> Result<SignatureStatus> {
    let file_name = Path::new(file_path)
        .file_name()
        .unwrap_or_default()
        .to_string_lossy();

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
        println!("  {} {} has no signatures", "✗".red(), file_name);
        return Ok(SignatureStatus {
            has_header: false,
            has_first_signature: false,
            has_second_signature: false,
        });
    }

    // Check for zero signatures in signature2
    let re_sig2 = Regex::new(r"signature2.*0{64}").unwrap();
    if re_sig2.is_match(&stdout) {
        println!("  {} {} has only one signature", "⚠".yellow(), file_name);
        return Ok(SignatureStatus {
            has_header: true,
            has_first_signature: true,
            has_second_signature: false,
        });
    }

    // Check for zero signatures in signature1
    let re_sig1 = Regex::new(r"signature1.*0{64}").unwrap();
    if re_sig1.is_match(&stdout) {
        println!(
            "  {} {} has a header but no valid signatures",
            "✗".red(),
            file_name
        );
        return Ok(SignatureStatus {
            has_header: true,
            has_first_signature: false,
            has_second_signature: false,
        });
    }

    // If we get here, the file has two signatures
    println!("  {} {} has two signatures", "✓".green(), file_name);
    Ok(SignatureStatus {
        has_header: true,
        has_first_signature: true,
        has_second_signature: true,
    })
}

fn generate_manifest(version_folder: &str, firmware_version: &str) -> Result<()> {
    // Manifest file generation is handled by the progress bar in the calling function
    let manifest_file = format!("{}/manifest.json", version_folder);

    // Create manifest structure
    let mut manifest = Manifest {
        version: format!("v{}", firmware_version),
        files: Vec::new(),
    };

    // Add recovery.bin to manifest
    let recovery_bin = format!("{}/recovery.bin", version_folder);
    let recovery_hash = calculate_hash(&recovery_bin)?;
    manifest.files.push(FileEntry {
        name: "recovery.bin".to_string(),
        hash: format!("0x{}", recovery_hash),
    });

    // Add app.bin to manifest
    let app_bin = format!("{}/app.bin", version_folder);
    let app_hash = calculate_hash(&app_bin)?;
    manifest.files.push(FileEntry {
        name: "app.bin".to_string(),
        hash: format!("0x{}", app_hash),
    });

    // Add each app to manifest
    let apps_dir = format!("{}/apps", version_folder);
    let apps_path = Path::new(&apps_dir);

    let mut app_count = 0;
    if apps_path.is_dir() {
        for entry in fs::read_dir(apps_path).context("Failed to read apps directory")? {
            let entry = entry.context("Failed to read directory entry")?;
            let path = entry.path();

            if path.is_file() && path.extension().map_or(false, |ext| ext == "elf") {
                if let Some(file_name) = path.file_name().and_then(|n| n.to_str()) {
                    if file_name.starts_with("gui-app") {
                        let app_path = path.to_str().unwrap();
                        let app_hash = calculate_hash(app_path)?;

                        manifest.files.push(FileEntry {
                            name: format!("apps/{}", file_name),
                            hash: format!("0x{}", app_hash),
                        });

                        app_count += 1;
                    }
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
