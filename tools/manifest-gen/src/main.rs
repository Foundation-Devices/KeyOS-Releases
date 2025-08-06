use anyhow::{Context, Result};
use clap::Parser;
use colored::Colorize;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::{self, File};
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;
use thiserror::Error;

#[derive(Error, Debug)]
enum ManifestError {
    #[error("File not found: {0}")]
    FileNotFound(String),

    #[error("Release config not found: {0}")]
    ConfigNotFound(String),
}

#[derive(Parser)]
#[command(author, version, about = "Generate firmware manifest.json", long_about = None)]
struct Cli {
    /// Version number (e.g., 1.0.0) - will read from {version}/release-config.toml
    firmware_version: String,

    /// Description for the update
    #[arg(long, default_value = "")]
    description: String,

    /// Release date (YYYY-MM-DD format, defaults to today)
    #[arg(long)]
    release_date: Option<String>,

    /// Output path for manifest.json (defaults to {version}/manifest.json)
    #[arg(long)]
    output: Option<String>,
}

#[derive(Serialize, Deserialize)]
struct ReleaseConfig {
    release: ReleaseInfo,
}

#[derive(Serialize, Deserialize)]
struct ReleaseInfo {
    #[serde(rename = "base-version")]
    base_version: String,
    version: String,
}

#[derive(Serialize, Deserialize)]
struct Manifest {
    #[serde(rename = "baseVersion")]
    base_version: String,
    version: String,
    #[serde(rename = "signedSha256")]
    signed_sha256: String,
    #[serde(rename = "unsignedSha256")]
    unsigned_sha256: String,
    #[serde(rename = "updateFilename")]
    update_filename: String,
    #[serde(rename = "signatureFilename")]
    signature_filename: String,
    description: String,
    #[serde(rename = "releaseDate")]
    release_date: String,
}

fn calculate_signed_sha256(file_path: &str) -> Result<String> {
    let mut file =
        File::open(file_path).with_context(|| format!("Failed to open file: {}", file_path))?;

    let mut hasher = Sha256::new();
    let mut buffer = [0; 8192];

    loop {
        let bytes_read = file
            .read(&mut buffer)
            .with_context(|| "Failed to read file")?;
        if bytes_read == 0 {
            break;
        }
        hasher.update(&buffer[..bytes_read]);
    }

    Ok(hex::encode(hasher.finalize()))
}

fn calculate_unsigned_sha256(file_path: &str) -> Result<String> {
    let mut file =
        File::open(file_path).with_context(|| format!("Failed to open file: {}", file_path))?;

    // Skip the first 2048 bytes (cosign2 signature header)
    file.seek(SeekFrom::Start(2048))
        .with_context(|| "Failed to seek in file")?;

    let mut hasher = Sha256::new();
    let mut buffer = [0; 8192];

    loop {
        let bytes_read = file
            .read(&mut buffer)
            .with_context(|| "Failed to read file")?;
        if bytes_read == 0 {
            break;
        }
        hasher.update(&buffer[..bytes_read]);
    }

    Ok(hex::encode(hasher.finalize()))
}

fn generate_default_release_date() -> String {
    chrono::Utc::now().format("%Y-%m-%d").to_string()
}

fn read_release_config(version: &str) -> Result<ReleaseConfig> {
    let config_path = format!("{}/release-config.toml", version);

    if !Path::new(&config_path).exists() {
        return Err(ManifestError::ConfigNotFound(config_path).into());
    }

    let config_content = fs::read_to_string(&config_path)
        .with_context(|| format!("Failed to read config file: {}", config_path))?;

    let config: ReleaseConfig = toml::from_str(&config_content)
        .with_context(|| format!("Failed to parse config file: {}", config_path))?;

    Ok(config)
}

fn generate_description(base_version: &str, version: &str, custom_description: &str) -> String {
    if custom_description.is_empty() {
        format!(
            "KeyOS firmware update from v{} to v{}",
            base_version, version
        )
    } else {
        custom_description.to_string()
    }
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    println!("{} Generating firmware manifest...", "✓".green());

    // Read release config
    println!(
        "  {} Reading release config from {}/release-config.toml...",
        "→".blue(),
        cli.firmware_version
    );
    let config = read_release_config(&cli.firmware_version)?;
    let base_version = &config.release.base_version;
    let version = &config.release.version;

    // Generate update filename
    let update_filename = format!("KeyOS-v{}.bin", version);
    let update_file_path = format!("{}/{}", cli.firmware_version, update_filename);

    // Validate that the update file exists
    if !Path::new(&update_file_path).exists() {
        return Err(ManifestError::FileNotFound(update_file_path.clone()).into());
    }

    // Calculate hashes
    println!("  {} Calculating signed SHA256...", "→".blue());
    let signed_sha256 = calculate_signed_sha256(&update_file_path)?;
    println!("    Signed SHA256: {}", signed_sha256);

    println!(
        "  {} Calculating unsigned SHA256 (skipping first 2048 bytes)...",
        "→".blue()
    );
    let unsigned_sha256 = calculate_unsigned_sha256(&update_file_path)?;
    println!("    Unsigned SHA256: {}", unsigned_sha256);

    // Generate signature filename
    let signature_filename = format!("{}.sig", update_filename);

    // Generate metadata
    let release_date = cli
        .release_date
        .unwrap_or_else(generate_default_release_date);
    let description = generate_description(base_version, version, &cli.description);

    // Generate output path
    let output_path = cli
        .output
        .unwrap_or_else(|| format!("{}/manifest.json", cli.firmware_version));

    // Create manifest
    let manifest = Manifest {
        base_version: base_version.clone(),
        version: version.clone(),
        signed_sha256,
        unsigned_sha256,
        update_filename,
        signature_filename,
        description,
        release_date,
    };

    // Write manifest to file
    let manifest_json = serde_json::to_string_pretty(&manifest)
        .with_context(|| "Failed to serialize manifest to JSON")?;

    fs::write(&output_path, manifest_json)
        .with_context(|| format!("Failed to write manifest to {}", output_path))?;

    println!();
    println!(
        "{}",
        format!("✓ Manifest generated successfully: {}", output_path).green()
    );
    println!();

    Ok(())
}
