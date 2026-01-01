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
use std::path::Path;
use thiserror::Error;

#[derive(Error, Debug)]
enum ImageBuilderError {
    #[error("File not found: {0}")]
    FileNotFound(String),
}

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    /// Whether this is a production build (default: false)
    #[arg(short, long, default_value = "false")]
    production: bool,
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
const BOOT_PARTITION_SIZE_BYTES: u64 = 256 * MIB - SECTOR_SIZE;
const BOOT_PARTITION_SIZE_SECTORS: u32 = (BOOT_PARTITION_SIZE_BYTES / SECTOR_SIZE) as u32;

const SYSTEM_PARTITION_START_SECTOR: u32 =
    BOOT_PARTITION_START_SECTOR + BOOT_PARTITION_SIZE_SECTORS;
const SYSTEM_PARTITION_SIZE_BYTES: u64 = 8 * GIB - 0x1000000;
const SYSTEM_PARTITION_SIZE_SECTORS: u32 = (SYSTEM_PARTITION_SIZE_BYTES / SECTOR_SIZE) as u32;

const USER_PARTITION_START_SECTOR: u32 =
    SYSTEM_PARTITION_START_SECTOR + SYSTEM_PARTITION_SIZE_SECTORS;
const USER_PARTITION_SIZE_BYTES: u64 = 50 * GIB - 0x400000;
const USER_PARTITION_SIZE_SECTORS: u32 = (USER_PARTITION_SIZE_BYTES / SECTOR_SIZE) as u32;

fn main() -> Result<()> {
    env_logger::init();

    let cli = Cli::parse();

    match &cli.command {
        Commands::CreateImage { version, output } => {
            let version_folder = version.clone();
            create_boot_image(&version_folder, cli.production, output)?;
        }
        Commands::PrintHashes { version } => {
            let version_folder = version.clone();
            print_hashes(&version_folder, cli.production)?;
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

fn check_images_exist(version_folder: &str, _is_production: bool) -> Result<()> {
    // Check for bootloader: prefer boot.cip if it exists, otherwise boot.bin
    let boot_cip = format!("{version_folder}/boot.cip");
    let boot_bin = format!("{version_folder}/boot.bin");
    let blassets = format!("{version_folder}/blassets");
    let common = format!("{version_folder}/keyos/common");
    let common_boot = format!("{version_folder}/common-boot");

    let app_bin = format!("{version_folder}/keyos/app.bin");
    let recovery_bin = format!("{version_folder}/recovery.bin");

    // Check for bootloader file (prefer boot.cip, fallback to boot.bin)
    if !Path::new(&boot_cip).exists() && !Path::new(&boot_bin).exists() {
        return Err(ImageBuilderError::FileNotFound(format!(
            "Neither boot.cip nor boot.bin found in {version_folder}. At least one is required to boot KeyOS.",
        ))
        .into());
    }
    if !Path::new(&blassets).exists() {
        return Err(ImageBuilderError::FileNotFound(format!(
            "blassets not found in {version_folder}. This folder is required to boot KeyOS.",
        ))
        .into());
    }

    if !Path::new(&common).exists() {
        return Err(ImageBuilderError::FileNotFound(format!(
            "`keyos/common` not found in {version_folder}. This folder is required to boot KeyOS.",
        ))
        .into());
    }

    if !Path::new(&common_boot).exists() {
        return Err(ImageBuilderError::FileNotFound(format!(
            "`common-boot` not found in {version_folder}. This folder is required to boot KeyOS.",
        ))
        .into());
    }

    if !Path::new(&app_bin).exists() {
        return Err(ImageBuilderError::FileNotFound(format!(
            "keyos/app.bin not found in {version_folder}. This file should be signed first.",
        ))
        .into());
    }

    if !Path::new(&recovery_bin).exists() {
        return Err(ImageBuilderError::FileNotFound(format!(
            "recovery.bin not found in {version_folder}. This file is required for recovery mode.",
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

fn create_boot_partition(
    file: &mut File,
    version_folder: &str,
    _is_production: bool,
) -> Result<()> {
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

    // Copy bootloader - prefer boot.cip if it exists, otherwise boot.bin
    // Do NOT rename - the ROM bootloader expects boot.cip in secure boot mode
    let boot_cip_path = format!("{}/boot.cip", version_folder);
    let boot_bin_path = format!("{}/boot.bin", version_folder);

    let (bootloader_src, bootloader_dst) = if Path::new(&boot_cip_path).exists() {
        (boot_cip_path, "boot.cip")
    } else {
        (boot_bin_path, "boot.bin")
    };

    println!(
        "  {} Copying {} to boot partition",
        "→".blue(),
        bootloader_dst
    );
    fs.root_dir()
        .create_file(bootloader_dst)?
        .write_all(&std::fs::read(&bootloader_src)?)?;

    // Copy recovery.bin
    let recovery_bin_path = format!("{}/recovery.bin", version_folder);
    println!("  {} Copying recovery.bin to boot partition", "→".blue());
    fs.root_dir()
        .create_file("recovery.bin")?
        .write_all(&fs::read(&recovery_bin_path)?)?;

    copy_directory_to_disk(
        &mut fs.root_dir(),
        version_folder,
        "bootloader assets",
        "blassets",
        "blassets",
    )?;
    copy_directory_to_disk(
        &mut fs.root_dir(),
        version_folder,
        "recovery OS common assets",
        "common-boot",
        "common",
    )?;

    println!("{} Boot partition created successfully", "✓".green());
    Ok(())
}

fn copy_directory_to_disk(
    root_dir: &mut Dir<StreamSlice<&mut File>>,
    version_folder: &str,
    kind: &str,
    src_dir: &str,
    dst_dir: &str,
) -> Result<()> {
    let fs_dst_dir = root_dir.create_dir(dst_dir)?;
    let fs_src_dir = Path::new(&version_folder).join(src_dir).read_dir()?;

    for asset_file in fs_src_dir {
        let file = asset_file?;
        let file_name = file.file_name();
        let file_name = file_name.to_str().unwrap();

        if file.file_type()?.is_dir() {
            copy_directory_to_disk(
                root_dir,
                version_folder,
                &kind,
                format!("{}/{}", src_dir, file_name).as_str(),
                format!("{}/{}", dst_dir, file_name).as_str(),
            )?;
            continue;
        }

        println!(
            "  {} Copying {kind} {} -> {}/{}",
            "→".blue(),
            file.path().as_os_str().to_str().unwrap(),
            dst_dir,
            file_name
        );

        fs_dst_dir
            .create_file(file_name)?
            .write_all(&fs::read(file.path())?)?;
    }

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

    // Create keyos directory and copy app.bin (main firmware)
    println!("  {} Creating keyos directory", "→".blue());
    let mut keyos_dir = fs.root_dir().create_dir("keyos")?;

    let app_bin_path = format!("{}/keyos/app.bin", version_folder);
    println!("  {} Copying keyos/app.bin to system partition", "→".blue());
    keyos_dir
        .create_file("app.bin")?
        .write_all(&fs::read(&app_bin_path)?)?;

    // Copy apps directory if it exists (from keyos/apps to keyos/apps on disk)
    let apps_dir_path = format!("{}/keyos/apps", version_folder);
    if Path::new(&apps_dir_path).exists() {
        println!("  {} Copying apps directory", "→".blue());
        let apps_dir_disk = keyos_dir.create_dir("apps")?;

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

    // Copy common assets (from keyos/common to keyos/common on disk)
    copy_directory_to_disk(
        &mut keyos_dir,
        version_folder,
        "common assets",
        "keyos/common",
        "common",
    )?;

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

fn log_all_partitions(file: &mut File) -> Result<()> {
    println!("\n{}", "Partition Table Summary:".bold());

    file.seek(std::io::SeekFrom::Start(0))?;
    let mbr = Mbr::try_from_reader(&*file).context("Failed to read MBR")?;

    for (idx, entry) in mbr.partition_table.entries.iter().enumerate() {
        if let Some(part) = entry {
            let start_sector = part.start_sector_lba();
            let end_sector = part.end_sector_lba();
            let size_sectors = end_sector - start_sector + 1;
            let size_mb = (size_sectors as u64 * SECTOR_SIZE) / MIB;
            let bootable = if part.bootable() {
                "bootable"
            } else {
                "non-bootable"
            };

            println!(
                "  {} Partition #{}: {} sectors ({} MB), start: {}, end: {}, {}",
                "→".blue(),
                idx,
                size_sectors,
                size_mb,
                start_sector,
                end_sector,
                bootable
            );
        }
    }

    Ok(())
}

fn list_directory_contents(
    dir: &Dir<StreamSlice<&mut File>>,
    _descend_into_folders: bool,
) -> Result<()> {
    list_directory_contents_recursive(dir, 1)
}

fn list_directory_contents_recursive(
    dir: &Dir<StreamSlice<&mut File>>,
    depth: usize,
) -> Result<()> {
    let indent = "  ".repeat(depth + 1);

    for entry in dir.iter() {
        let entry = entry?;
        let name = entry.file_name();

        // Skip . and .. entries
        if name == "." || name == ".." {
            continue;
        }

        if entry.is_dir() {
            println!("{}📁 {}/", indent, name);

            // Recursively list subdirectory contents
            let subdir = entry.to_dir();
            list_directory_contents_recursive(&subdir, depth + 1)?;
        } else {
            let size = entry.len();
            println!("{}📄 {} ({} bytes)", indent, name, size);
        }
    }

    Ok(())
}

fn verify_boot_partition_contents(file: &mut File, _is_production: bool) -> Result<()> {
    println!("\n{}", "Verifying boot partition contents...".bold());

    file.seek(std::io::SeekFrom::Start(0))?;
    let mbr = Mbr::try_from_reader(&*file).context("Failed to read MBR")?;

    let boot_partition_entry = mbr.partition_table.entries[0]
        .ok_or_else(|| anyhow::anyhow!("Boot partition not found"))?;
    let start_offset = boot_partition_entry.start_sector_lba() as u64 * SECTOR_SIZE;
    let end_offset = (boot_partition_entry.end_sector_lba() as u64 + 1) * SECTOR_SIZE;

    let boot_partition_slice = StreamSlice::new(file, start_offset, end_offset)?;
    let fs = FileSystem::new(boot_partition_slice, fatfs::FsOptions::new())
        .context("Failed to open boot partition filesystem")?;

    println!("  {} Root contents of boot partition:", "→".blue());
    let mut found_bootloader = false;

    list_directory_contents(&fs.root_dir(), false)?;

    // Check for bootloader file (boot.cip in secure boot mode, boot.bin otherwise)
    for entry in fs.root_dir().iter() {
        let entry = entry?;
        let name = entry.file_name();
        if name.eq_ignore_ascii_case("boot.cip") || name.eq_ignore_ascii_case("boot.bin") {
            found_bootloader = true;
            break;
        }
    }

    if !found_bootloader {
        return Err(anyhow::anyhow!(
            "Expected bootloader file (boot.cip or boot.bin) not found in boot partition!"
        ));
    }

    println!("{} Boot partition verification successful", "✓".green());
    Ok(())
}

fn verify_system_partition_contents(file: &mut File) -> Result<()> {
    println!("\n{}", "Verifying system partition contents...".bold());

    file.seek(std::io::SeekFrom::Start(0))?;
    let mbr = Mbr::try_from_reader(&*file).context("Failed to read MBR")?;

    let system_partition_entry = mbr.partition_table.entries[1]
        .ok_or_else(|| anyhow::anyhow!("System partition not found"))?;
    let start_offset = system_partition_entry.start_sector_lba() as u64 * SECTOR_SIZE;
    let end_offset = (system_partition_entry.end_sector_lba() as u64 + 1) * SECTOR_SIZE;

    let system_partition_slice = StreamSlice::new(file, start_offset, end_offset)?;
    let fs = FileSystem::new(system_partition_slice, fatfs::FsOptions::new())
        .context("Failed to open system partition filesystem")?;

    println!("  {} Root contents of system partition:", "→".blue());
    list_directory_contents(&fs.root_dir(), true)?;

    println!("{} System partition verification successful", "✓".green());
    Ok(())
}

fn create_boot_image(version_folder: &str, is_production: bool, output_file: &str) -> Result<()> {
    println!(
        "{}",
        format!(
            "Creating {} disk image for version {}",
            if is_production {
                "production".underline()
            } else {
                "development".underline()
            },
            strip_v_prefix(version_folder)
        )
        .bold()
    );

    // Check that all required files exist
    check_images_exist(version_folder, is_production)?;

    println!("Creating {}", output_file);
    let mut boot_image = fs::OpenOptions::new()
        .write(true)
        .read(true)
        .truncate(true)
        .create(true)
        .open(output_file)
        .context("Failed to create output image file")?;

    init_mbr(&mut boot_image).context("Failed to initialize MBR")?;
    create_boot_partition(&mut boot_image, version_folder, is_production)
        .context("Failed to create boot partition")?;
    create_system_partition(&mut boot_image, version_folder)
        .context("Failed to create system partition")?;
    create_user_partition(&mut boot_image).context("Failed to create user partition")?;

    // Log all partitions
    log_all_partitions(&mut boot_image).context("Failed to log partitions")?;

    // Verify the boot partition contents
    verify_boot_partition_contents(&mut boot_image, is_production)
        .context("Boot partition verification failed")?;

    // Verify the system partition contents
    verify_system_partition_contents(&mut boot_image)
        .context("System partition verification failed")?;

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

fn print_hashes(version_folder: &str, is_production: bool) -> Result<()> {
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
    check_images_exist(version_folder, is_production)?;

    // Print bootloader hash (no cosign2 header expected)
    // Prefer boot.cip if it exists, otherwise boot.bin
    let boot_cip_path = format!("{}/boot.cip", version_folder);
    let boot_bin_path = format!("{}/boot.bin", version_folder);
    let bootloader_path = if Path::new(&boot_cip_path).exists() {
        &boot_cip_path
    } else {
        &boot_bin_path
    };
    let bootloader_digest: String = sha2::Sha256::digest(fs::read(bootloader_path)?).encode_hex();
    println!("bootloader                     - {bootloader_digest}");

    // Print app image hash (with cosign2 header)
    let app_bin_path = format!("{}/keyos/app.bin", version_folder);
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
