use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use colored::Colorize;
use fatfs::{Dir, FatType, FileSystem};
use fscommon::StreamSlice;
use hex::ToHex;
use mbrs::{AddrScheme, Mbr, PartInfo, PartType};
use sha2::Digest;
use std::fs::{self, File};
use std::io::{Seek, Write};
use std::path::{Path, PathBuf};
use thiserror::Error;

#[derive(Error, Debug)]
enum ImageBuilderError {
    #[error("File not found: {0}")]
    FileNotFound(String),

    #[error("Directory not found: {0}")]
    DirectoryNotFound(String),

    #[error("Failed to create image: {0}")]
    ImageCreationFailed(String),
}

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Create a bootable disk image from firmware components
    CreateImage {
        /// Version number (e.g., 1.0.2 or v1.0.2)
        version: String,

        /// Output image file name (default: boot.img)
        #[arg(short, long, default_value = "boot.img")]
        output: String,
    },

    /// Print SHA256 hashes of firmware components
    PrintHashes {
        /// Version number (e.g., 1.0.2 or v1.0.2)
        version: String,
    },
}

// Constants from the original code
const KIB: u64 = 1024;
const MIB: u64 = 1024 * KIB;
const GIB: u64 = 1024 * MIB;

const BOOT_VOLUME_NAME: &[u8] = b"KEYOSBOOT  ";
const SYSTEM_VOLUME_NAME: &[u8] = b"PRIME      ";

const SECTOR_SIZE: u64 = 512;
const BOOT_PARTITION_START_SECTOR: u32 = 1;
const BOOT_PARTITION_SIZE_BYTES: u64 = 32 * MIB - SECTOR_SIZE;
const BOOT_PARTITION_SIZE_SECTORS: u32 = (BOOT_PARTITION_SIZE_BYTES / SECTOR_SIZE) as u32;

const SYSTEM_PARTITION_START_SECTOR: u32 =
    BOOT_PARTITION_START_SECTOR + BOOT_PARTITION_SIZE_SECTORS;
const SYSTEM_PARTITION_SIZE_BYTES: u64 = 10 * GIB - 0xd90000;
const SYSTEM_PARTITION_SIZE_SECTORS: u32 = (SYSTEM_PARTITION_SIZE_BYTES / SECTOR_SIZE) as u32;

// Simplified for our use case - we'll focus on the essential partitions
const TOTAL_FLASH_BLOCKS: u64 = 64 * GIB / SECTOR_SIZE; // Assume 64GB device
const USER_PARTITION_SIZE_BYTES: u64 = 45 * GIB - 0x500000;
const USER_PARTITION_SIZE_SECTORS: u32 = (USER_PARTITION_SIZE_BYTES / SECTOR_SIZE) as u32;
const USER_PARTITION_START_SECTOR: u32 =
    TOTAL_FLASH_BLOCKS as u32 - (USER_PARTITION_SIZE_BYTES / SECTOR_SIZE) as u32;

fn main() -> Result<()> {
    env_logger::init();

    let cli = Cli::parse();

    match &cli.command {
        Commands::CreateImage { version, output } => {
            let version_folder = version.clone();
            create_boot_image(&version_folder, output)?;
        }
        Commands::PrintHashes { version } => {
            let version_folder = version.clone();
            print_hashes(&version_folder)?;
        }
    }

    Ok(())
}

fn strip_v_prefix(version: &str) -> String {
    if version.starts_with('v') {
        version[1..].to_string()
    } else {
        version.to_string()
    }
}

fn check_images_exist(version_folder: &str) -> Result<()> {
    let boot_bin = format!("{}/boot.bin", version_folder);
    let app_bin = format!("{}/app.bin", version_folder);
    let recovery_bin = format!("{}/recovery.bin", version_folder);

    if !Path::new(&boot_bin).exists() {
        return Err(ImageBuilderError::FileNotFound(format!(
            "boot.bin not found in {}. This file is required for the bootloader.",
            version_folder
        ))
        .into());
    }

    if !Path::new(&app_bin).exists() {
        return Err(ImageBuilderError::FileNotFound(format!(
            "app.bin not found in {}. This file should be signed first.",
            version_folder
        ))
        .into());
    }

    if !Path::new(&recovery_bin).exists() {
        return Err(ImageBuilderError::FileNotFound(format!(
            "recovery.bin not found in {}. This file is required for recovery mode.",
            version_folder
        ))
        .into());
    }

    Ok(())
}

fn init_mbr(file: &mut File) -> Result<()> {
    file.seek(std::io::SeekFrom::Start(0))?;

    let buf = <[u8; 512]>::try_from(&Mbr::default())?;
    file.write_all(&buf)?;
    file.seek(std::io::SeekFrom::Start(0))?;

    Ok(())
}

fn update_mbr(
    file: &mut File,
    is_bootable: bool,
    partition_idx: usize,
    start_sector: u32,
    last_sector: u32,
) -> Result<Mbr> {
    file.seek(std::io::SeekFrom::Start(0))?;
    let mut mbr = Mbr::try_from_reader(&*file).context("MBR must be already initialized")?;
    file.seek(std::io::SeekFrom::Start(0))?;

    mbr.partition_table.entries[partition_idx] = Some(PartInfo::try_from_lba_bounds(
        is_bootable,
        start_sector,
        last_sector,
        PartType::Fat32 {
            visible: true,
            scheme: AddrScheme::Lba,
        },
    )?);

    Ok(mbr)
}

fn format_partition<'a>(
    file: &'a mut File,
    is_bootable: bool,
    partition_idx: usize,
    volume_label: &[u8],
    start_sector: u32,
    sectors: u32,
) -> Result<FileSystem<StreamSlice<&'a mut File>>> {
    let last_sector = start_sector + sectors - 1;
    let mbr = update_mbr(file, is_bootable, partition_idx, start_sector, last_sector)?;

    let start_offset = start_sector as u64 * SECTOR_SIZE;
    let end_offset = ((start_sector + sectors) as u64 * SECTOR_SIZE) + 1;
    let partition_slice = StreamSlice::new(&*file, start_offset, end_offset)?;

    println!(
        "Formatting partition #{}, bootable: {is_bootable}, start_sector: {start_sector}, last_sector: {last_sector}",
        partition_idx
    );
    fatfs::format_volume(
        partition_slice,
        fatfs::FormatVolumeOptions::new()
            .fat_type(FatType::Fat32)
            .total_sectors(sectors)
            .bytes_per_cluster(64 * SECTOR_SIZE as u32)
            .volume_label(volume_label.try_into()?),
    )
    .context("format volume")?;

    // Overwrite the modified MBR
    file.seek(std::io::SeekFrom::Start(0))?;
    let buf = <[u8; 512]>::try_from(&mbr)?;
    file.write_all(&buf)?;

    // Open the newly formatted partition
    file.seek(std::io::SeekFrom::Start(0))?;
    let mut boot_partition = StreamSlice::new(file, start_offset, end_offset)?;
    boot_partition.seek(std::io::SeekFrom::Start(0))?;
    FileSystem::new(boot_partition, fatfs::FsOptions::new()).context("open filesystem")
}

fn create_boot_partition(file: &mut File, version_folder: &str) -> Result<()> {
    println!("{}", "Creating boot partition...".bold());

    let fs = format_partition(
        file,
        true,
        0,
        BOOT_VOLUME_NAME,
        BOOT_PARTITION_START_SECTOR,
        BOOT_PARTITION_SIZE_SECTORS,
    )
    .context("formatting boot partition")?;

    // Copy boot.bin (bootloader)
    let boot_bin_path = format!("{}/boot.bin", version_folder);
    println!("  {} Copying boot.bin to boot partition", "→".blue());
    fs.root_dir()
        .create_file("boot.bin")?
        .write_all(&fs::read(&boot_bin_path)?)?;

    // Copy recovery.bin
    let recovery_bin_path = format!("{}/recovery.bin", version_folder);
    println!("  {} Copying recovery.bin to boot partition", "→".blue());
    fs.root_dir()
        .create_file("recovery.bin")?
        .write_all(&fs::read(&recovery_bin_path)?)?;

    println!("{} Boot partition created successfully", "✓".green());
    Ok(())
}

fn create_system_partition(file: &mut File, version_folder: &str) -> Result<()> {
    println!("{}", "Creating system partition...".bold());

    let fs = format_partition(
        file,
        false,
        1,
        SYSTEM_VOLUME_NAME,
        SYSTEM_PARTITION_START_SECTOR,
        SYSTEM_PARTITION_SIZE_SECTORS,
    )?;

    // Copy app.bin (main firmware)
    let app_bin_path = format!("{}/app.bin", version_folder);
    println!("  {} Copying app.bin to system partition", "→".blue());
    fs.root_dir()
        .create_file("app.bin")?
        .write_all(&fs::read(&app_bin_path)?)?;

    // Copy apps directory if it exists
    let apps_dir_path = format!("{}/apps", version_folder);
    if Path::new(&apps_dir_path).exists() {
        println!("  {} Copying apps directory", "→".blue());
        let apps_dir_disk = fs.root_dir().create_dir("apps")?;

        for entry in fs::read_dir(&apps_dir_path)? {
            let app_dir = entry?;
            if app_dir.path().is_dir() {
                let app_name = app_dir.file_name().into_string().unwrap();
                println!("    - Bundling `{}` app", app_name);
                let app_dir_disk = apps_dir_disk.create_dir(&app_name)?;

                // Copy app.elf and manifest.json
                for app_file in &["app.elf", "manifest.json"] {
                    let app_file_path = app_dir.path().join(app_file);
                    if app_file_path.exists() {
                        println!("      - Copying: {}", app_file);
                        app_dir_disk
                            .create_file(app_file)?
                            .write_all(&fs::read(&app_file_path)?)?;
                    }
                }
            }
        }
    } else {
        println!("  {} No apps directory found", "⚠".yellow());
    }

    println!("{} System partition created successfully", "✓".green());
    Ok(())
}

fn create_user_partition(file: &mut File) -> Result<()> {
    println!("{}", "Creating user partition...".bold());

    let first_sector = USER_PARTITION_START_SECTOR;
    let last_sector = first_sector + USER_PARTITION_SIZE_SECTORS - 1;
    let mbr = update_mbr(file, false, 2, first_sector, last_sector)?;

    // Overwrite the modified MBR
    file.seek(std::io::SeekFrom::Start(0))?;
    let buf = <[u8; 512]>::try_from(&mbr)?;
    file.write_all(&buf)?;

    println!("{} User partition created successfully", "✓".green());
    Ok(())
}

fn create_boot_image(version_folder: &str, output_file: &str) -> Result<()> {
    println!(
        "{}",
        format!(
            "Creating disk image for version {}",
            strip_v_prefix(version_folder)
        )
        .bold()
    );

    // Check that all required files exist
    check_images_exist(version_folder)?;

    println!("Creating {}", output_file);
    let mut boot_image = fs::OpenOptions::new()
        .write(true)
        .read(true)
        .truncate(true)
        .create(true)
        .open(output_file)
        .context("Failed to create output image file")?;

    init_mbr(&mut boot_image).context("Failed to initialize MBR")?;
    create_boot_partition(&mut boot_image, version_folder)
        .context("Failed to create boot partition")?;
    create_system_partition(&mut boot_image, version_folder)
        .context("Failed to create system partition")?;
    create_user_partition(&mut boot_image).context("Failed to create user partition")?;

    println!(
        "\n{} {}",
        "✓".green().bold(),
        format!("{} created successfully", output_file)
            .green()
            .bold()
    );
    Ok(())
}

fn print_digest_of_cosigned_file(name: &str, path: &Path) -> Result<()> {
    const COSIGN2_HEADER_SIZE: usize = 0x800;
    let file_data = fs::read(path).context(format!("Failed to read file: {}", path.display()))?;

    if file_data.len() > COSIGN2_HEADER_SIZE {
        let digest: String = sha2::Sha256::digest(&file_data[COSIGN2_HEADER_SIZE..]).encode_hex();
        println!("{name:<30} - {digest}");
    } else {
        let digest: String = sha2::Sha256::digest(&file_data).encode_hex();
        println!("{name:<30} - {digest} (no cosign2 header)");
    }
    Ok(())
}

fn print_hashes(version_folder: &str) -> Result<()> {
    println!(
        "{}",
        format!(
            "SHA256 hashes for version {}",
            strip_v_prefix(version_folder)
        )
        .bold()
    );
    println!("The SHA256 hashes of all binaries (without the cosign2 header where applicable)");

    // Check that files exist first
    check_images_exist(version_folder)?;

    // Print bootloader hash (no cosign2 header expected)
    let boot_bin_path = format!("{}/boot.bin", version_folder);
    let bootloader_digest: String = sha2::Sha256::digest(fs::read(&boot_bin_path)?).encode_hex();
    println!("bootloader                     - {bootloader_digest}");

    // Print app image hash (with cosign2 header)
    let app_bin_path = format!("{}/app.bin", version_folder);
    print_digest_of_cosigned_file("app image", Path::new(&app_bin_path))?;

    // Print recovery image hash (may have cosign2 header)
    let recovery_bin_path = format!("{}/recovery.bin", version_folder);
    print_digest_of_cosigned_file("recovery image", Path::new(&recovery_bin_path))?;

    // Print app hashes if apps directory exists
    let apps_dir_path = format!("{}/apps", version_folder);
    if Path::new(&apps_dir_path).exists() {
        for entry in fs::read_dir(&apps_dir_path)? {
            let app_dir = entry?;
            if app_dir.path().is_dir() {
                let app_name = app_dir.file_name().into_string().unwrap();
                let app_elf_path = app_dir.path().join("app.elf");
                if app_elf_path.exists() {
                    print_digest_of_cosigned_file(&app_name, &app_elf_path)?;
                }
            }
        }
    }

    Ok(())
}
