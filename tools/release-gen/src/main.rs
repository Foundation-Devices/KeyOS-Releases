#[cfg(not(test))]
use {
    aho_corasick::AhoCorasick,
    std::{ffi, io::Seek},
};
use {
    anyhow::Context,
    clap::Parser,
    release_manifest::{Action, ReleaseManifest, Transaction},
    std::{
        fmt::Display,
        fs::{self, File, ReadDir},
        io::{self, Read, Write},
        path::{Path, PathBuf},
        process::Command,
    },
};

mod release_manifest;
#[cfg(test)]
mod test;

#[cfg(not(test))]
const APP_IMAGE: &str = "app.bin";
#[cfg(not(test))]
const COSIGN2_DEFAULT_HEADER_SIZE: usize = 2048;
const PATH_TO_STR_ERROR: &str = "Path should be a valid string";

/// `release-gen` traverses the two directories and crates a `release.tar` file
/// that contains the manifest describing what actions to perform to reach the
/// destination directory state starting from the source one.
///
/// Uses the `updiff` tool. See: https://github.com/Foundation-Devices/updiff
#[derive(Parser, Debug)]
pub struct Args {
    /// Version before the update.
    pub base_version: String,
    /// Path to the base directory.
    pub base: PathBuf,
    /// Version after the update.
    pub new_version: String,
    /// Path to the new directory.
    pub new: PathBuf,
    /// Release label.
    #[arg(long, default_value = "KeyOS Release")]
    pub label: String,
    /// Flag indicating whether this release is mandatory.
    #[arg(long)]
    pub mandatory: bool,
    /// Flag indicating whether a reboot is required after this release.
    #[arg(long)]
    pub reboot_required: bool,
    /// Path where the release tar (output of `release-gen`) should be created.
    /// The directory does not need to exist, it will be created if missing.
    ///
    /// Example: ./out/release.tar
    #[arg(short, long, default_value = "release.tar")]
    pub out: PathBuf,
    /// Path to the `updiff` tool binary. If not specified, it is assumed that
    /// `updiff` is accessible from CWD.
    #[arg(long, default_value = "updiff")]
    pub updiff_path: PathBuf,
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    run(args)
}

pub fn run(args: Args) -> anyhow::Result<()> {
    println!("[INFO] verifying `updiff` tool access");

    if let Err(err) = Command::new(args.updiff_path.as_os_str()).output() {
        if err.to_string().contains("No such file or directory") {
            anyhow::bail!(
                r"updiff tool not found at {}
Please make sure it's in your PATH or specify the path where it is installed. See `--help` for more information.",
                abs_path(args.updiff_path)
            );
        } else {
            anyhow::bail!("could not run updiff tool: {}", err.to_string());
        }
    }

    println!("[INFO] setting up output directory");

    if fs::exists(&args.out).context("Checking if output file exists")? {
        anyhow::bail!(
            "Output file {} already exists. Please remove it or specify a different output path.",
            abs_path(args.out)
        );
    }
    let out_dir = if let Some(parent_dir) = args.out.parent() {
        fs::create_dir_all(parent_dir)
            .with_context(|| format!("Creating output dir: {}", abs_path(parent_dir)))?;
        parent_dir.to_path_buf()
    } else {
        std::env::current_dir().context("Reading current directory")?
    };

    let base_src_root = fs::read_dir(&args.base)
        .with_context(|| format!("Reading base dir: {}", abs_path(&args.base)))?;
    let new_src_root = fs::read_dir(&args.new)
        .with_context(|| format!("Reading new dir: {}", abs_path(&args.new)))?;

    let out_patch_dir = out_dir.join("patch");
    let manifest_file_path = out_dir.clone().join("manifest.json");

    fs::create_dir(&out_patch_dir)
        .with_context(|| format!("Creating patch dir: {}", abs_path(&out_patch_dir)))?;
    let mut manifest_file =
        File::create_new(&manifest_file_path).expect("Manifest file should not exist");

    let _guard = FileCleanupGuard {
        files: vec![&manifest_file_path],
        dirs: vec![&out_patch_dir],
    };

    let base_src_files: Vec<_> = rec_get_all_files_in_tree(base_src_root)
        .context("Getting all files in base dir")?
        .into_iter()
        .map(|file| {
            file.strip_prefix(&args.base)
                .expect("Prefix should be valid")
                .to_path_buf()
        })
        .collect();
    let new_src_files: Vec<_> = rec_get_all_files_in_tree(new_src_root)
        .context("Getting all files in new dir")?
        .into_iter()
        .map(|file| {
            file.strip_prefix(&args.new)
                .expect("Prefix should be valid")
                .to_path_buf()
        })
        .collect();

    println!("[INFO] collecting actions for release");

    let mut actions = vec![];

    for base_file in &base_src_files {
        if !new_src_files.contains(base_file) {
            let path = base_file.to_str().expect(PATH_TO_STR_ERROR).to_string();
            actions.push(Action::Delete { path });
            println!("[INFO] action/delete: {}", base_file.display());
        } else {
            let base_file_full = args.base.clone().join(base_file);
            let new_file_full = args.new.clone().join(base_file);

            #[cfg(not(test))]
            let is_app_image = base_file_full.file_name().expect("file should have a name")
                == ffi::OsStr::new(APP_IMAGE);
            #[cfg(not(test))]
            if is_app_image
                && should_demand_reboot(&base_file_full, &new_file_full)?
                && !args.reboot_required
            {
                println!(
                    "[WARN] this release will likely require a reboot to be applied correctly, \
                     but the `--reboot-required` flag was not set. Please consider setting it and \
                     regenerating the release."
                );
            }

            if !files_have_same_content(&base_file_full, &new_file_full)? {
                let patch_file = out_patch_dir.clone().join(base_file);
                let patch_file_parent = patch_file
                    .parent()
                    .expect("Patch file should have a parent");
                fs::create_dir_all(patch_file_parent)
                    .with_context(|| format!("Creating dir: {}", abs_path(patch_file_parent)))?;
                let _ = File::create_new(&patch_file)
                    .with_context(|| format!("Creating patch file: {}", abs_path(&patch_file)))?;

                let output = Command::new(args.updiff_path.as_os_str())
                    .arg(&args.base_version)
                    .arg(base_file_full)
                    .arg(&args.new_version)
                    .arg(new_file_full)
                    .arg(&patch_file)
                    .output()
                    .context("Running updiff command")?;

                anyhow::ensure!(
                    output.status.success(),
                    "updiff command failed: {}",
                    String::from_utf8_lossy(&output.stderr)
                );

                let file = base_file.to_str().expect(PATH_TO_STR_ERROR).to_string();

                actions.push(Action::Patch {
                    patch_file: file.clone(),
                    patch_source: file,
                    base_version: args.base_version.clone(),
                    new_version: args.new_version.clone(),
                });
                println!("[INFO] action/patch: {}", base_file.display());
            }
        }
    }
    for new_file in &new_src_files {
        if !base_src_files.contains(new_file) {
            let source_file_path = args.new.clone().join(new_file);
            let mut source_file = File::open(&source_file_path).expect("Source should file exist");
            let patch_file_path = out_patch_dir.clone().join(new_file);
            let patch_file_parent = patch_file_path
                .parent()
                .expect("Patch file should have parent");
            fs::create_dir_all(patch_file_parent)
                .with_context(|| format!("Creating dir: {}", abs_path(patch_file_parent)))?;

            let mut out_file = fs::File::create_new(&patch_file_path)
                .with_context(|| format!("Creating patch file: {}", abs_path(&patch_file_path)))?;

            let file_path = new_file.to_str().expect(PATH_TO_STR_ERROR).to_string();
            io::copy(&mut source_file, &mut out_file).with_context(|| {
                format!(
                    "Copying file from {} to {}",
                    abs_path(source_file_path),
                    abs_path(patch_file_path)
                )
            })?;
            actions.push(Action::Add {
                source: file_path.clone(),
                dest: file_path,
            });
            println!("[INFO] action/add: {}", new_file.display());
        }
    }

    println!("[INFO] creating release manifest");

    let manifest = ReleaseManifest {
        label: args.label.clone(),
        mandatory: args.mandatory,
        reboot_required: args.reboot_required,
        date: chrono::Utc::now().date_naive().to_string(),
        transactions: vec![Transaction::new(actions)],
    };

    manifest_file
        .write_all(
            serde_json::to_string(&manifest)
                .expect("Serialization should not fail")
                .as_bytes(),
        )
        .context("Writing to manifest.json")?;

    manifest_file.sync_all()?;

    println!("[INFO] creating release tar");

    let tar_cmd = std::process::Command::new("tar")
        .args([
            "-cf",
            args.out.to_str().unwrap(),
            "-C",
            out_dir.to_str().unwrap(),
            "patch",
            "manifest.json",
        ])
        .output()
        .context("Failed to execute tar command")?;

    if !tar_cmd.status.success() {
        return Err(anyhow::anyhow!(
            "tar command failed: {}",
            String::from_utf8_lossy(&tar_cmd.stderr)
        ));
    }

    println!("[INFO] done");

    Ok(())
}

#[cfg(not(test))]
fn should_demand_reboot(base_image_path: &Path, new_image_path: &Path) -> anyhow::Result<bool> {
    let base_update_server_hash = program_elf_hash(base_image_path, "update")?
        .expect("Update server should exist in base image");
    let new_update_server_hash = program_elf_hash(new_image_path, "update")?
        .expect("Update server should exist in new image");

    Ok(base_update_server_hash != new_update_server_hash)
}

#[cfg(not(test))]
fn program_elf_hash(
    image_path: &Path,
    target_program_name: &str,
) -> anyhow::Result<Option<blake3::Hash>> {
    let mut image = File::open(image_path)
        .with_context(|| format!("Opening file: {}", abs_path(image_path)))?;

    // Find the start positions of all binary elf tags in the image. These tags have
    // the following format:
    //
    // +------------+-----------+----------------+---------------------------+
    // | Magic      | CRC16     | Size (words)   |     BinaryElfTag          |
    // +------------+-----------+----------------+---------------------------+
    // | b"BElf"    | digest    | len/4 (u16)    | BinaryElfTag::TOTAL_SIZE  |
    // | (4 bytes)  | (2 bytes) | (2 bytes)      | (variable size)           |
    // +------------+-----------+----------------+---------------------------+
    let mut belf_tag_start_positions = Vec::new();
    let ac = AhoCorasick::new([b"BElf"]).context("Creating Aho-Corasick automaton")?;
    for ac_match in ac.stream_find_iter(&image) {
        let ac_match = ac_match.context("Aho-Corasick match error")?;
        belf_tag_start_positions.push(ac_match.start());
    }

    // Search for the binary ELF that has the required program name.
    for start_pos in belf_tag_start_positions {
        image.seek(io::SeekFrom::Start(start_pos as u64))?;
        let magic = {
            let mut buf = [0u8; 4];
            image.read_exact(&mut buf).context("Reading BElf magic")?;
            buf
        };
        assert_eq!(&magic, b"BElf", "Invalid BElf magic");
        let _crc = {
            let mut buf = [0u8; 2];
            image.read_exact(&mut buf).context("Reading BElf CRC16")?;
            u16::from_le_bytes(buf)
        };
        let belf_size = {
            let mut buf = [0u8; 2];
            image.read_exact(&mut buf).context("Reading BElf size")?;
            u16::from_le_bytes(buf) as usize * 4
        };
        let belf_bytes = {
            let mut buf = vec![0u8; belf_size];
            image.read_exact(&mut buf).context("Reading BElf bytes")?;
            buf
        };
        let belf = BinaryElfTag::from_bytes(&belf_bytes).context("Parsing BinaryElf from bytes")?;

        let belf_name = belf
            .program_name
            .iter()
            .cloned()
            .take_while(|&b| b != 0)
            .chain(std::iter::once(0))
            .collect::<Vec<u8>>();
        let Ok(prog_name) = ffi::CStr::from_bytes_with_nul(&belf_name)
            .context("Creating program name CStr")?
            .to_str()
        else {
            // Probably a false positive, skip.
            continue;
        };
        if prog_name == target_program_name {
            // All ELF files should have a cosign2 header at the start.
            let elf_start = belf.load_offset + COSIGN2_DEFAULT_HEADER_SIZE as u32;
            image
                .seek(io::SeekFrom::Start(elf_start as u64))
                .context("Seeking to BElf data")?;

            let mut buf = vec![0u8; belf.data_len as usize - COSIGN2_DEFAULT_HEADER_SIZE];
            image.read_exact(&mut buf).context("Reading BElf data")?;
            let hash = blake3::hash(&buf);

            return Ok(Some(hash));
        }
    }

    Ok(None)
}

#[cfg(not(test))]
struct BinaryElfTag {
    load_offset: u32,
    data_len: u32,
    _app_id: [u8; Self::APP_ID_SIZE],
    program_name: [u8; Self::PROGRAM_NAME_SIZE],
}

#[cfg(not(test))]
impl BinaryElfTag {
    const APP_ID_SIZE: usize = 16;
    const PROGRAM_NAME_SIZE: usize = 32;
    const TOTAL_SIZE: usize = 4 + 4 + Self::APP_ID_SIZE + Self::PROGRAM_NAME_SIZE;

    fn from_bytes(bytes: &[u8]) -> anyhow::Result<Self> {
        if bytes.len() != Self::TOTAL_SIZE {
            anyhow::bail!(
                "BinaryElfTag bytes length incorrect: expected {}, got {}",
                Self::TOTAL_SIZE,
                bytes.len()
            );
        }

        let load_offset = u32::from_le_bytes(bytes[..4].try_into().unwrap());
        let data_len = u32::from_le_bytes(bytes[4..8].try_into().unwrap());

        let mut app_id = [0u8; Self::APP_ID_SIZE];
        app_id.copy_from_slice(&bytes[8..8 + Self::APP_ID_SIZE]);

        let mut program_name = [0u8; Self::PROGRAM_NAME_SIZE];
        program_name.copy_from_slice(
            &bytes[8 + Self::APP_ID_SIZE..8 + Self::APP_ID_SIZE + Self::PROGRAM_NAME_SIZE],
        );

        Ok(Self {
            load_offset,
            data_len,
            _app_id: app_id,
            program_name,
        })
    }
}

struct FileCleanupGuard<'a> {
    files: Vec<&'a Path>,
    dirs: Vec<&'a Path>,
}

impl Drop for FileCleanupGuard<'_> {
    fn drop(&mut self) {
        for file in &self.files {
            if let Err(err) = fs::remove_file(file) {
                eprintln!("Error removing file {}: {}", file.display(), err);
            }
        }
        for dir in &self.dirs {
            if let Err(err) = fs::remove_dir_all(dir) {
                eprintln!("Error removing directory {}: {}", dir.display(), err);
            }
        }
    }
}

fn rec_get_all_files_in_tree(dir: ReadDir) -> anyhow::Result<Vec<PathBuf>> {
    let mut file_paths = vec![];

    for entry in dir {
        let entry = entry?;
        let metadata = entry.metadata()?;

        if metadata.is_symlink() {
            continue;
        } else if metadata.is_file() {
            file_paths.push(entry.path());
        } else if metadata.is_dir() {
            let subdir = fs::read_dir(entry.path())
                .with_context(|| format!("Reading subdirectory: {}", abs_path(entry.path())))?;
            file_paths.extend(rec_get_all_files_in_tree(subdir)?);
        }
    }

    Ok(file_paths)
}

fn files_have_same_content(file_path1: &Path, file_path2: &Path) -> anyhow::Result<bool> {
    let metadata1 = fs::metadata(file_path1)
        .with_context(|| format!("Reading metadata from: {}", abs_path(file_path1)))?;
    let metadata2 = fs::metadata(file_path2)
        .with_context(|| format!("Reading metadata from: {}", abs_path(file_path2)))?;

    if metadata1.len() != metadata2.len() {
        return Ok(false);
    }

    let mut file1 = File::open(file_path1)
        .with_context(|| format!("Opening file: {}", abs_path(file_path1)))?;
    let mut file2 = File::open(file_path2)
        .with_context(|| format!("Opening file: {}", abs_path(file_path2)))?;

    let mut buffer1 = [0; 1024];
    let mut buffer2 = [0; 1024];

    loop {
        let bytes_read1 = file1
            .read(&mut buffer1)
            .with_context(|| format!("Reading chunk from: {}", abs_path(file_path1)))?;
        let bytes_read2 = file2
            .read(&mut buffer2)
            .with_context(|| format!("Reading chunk from: {}", abs_path(file_path2)))?;

        if bytes_read1 == 0 {
            debug_assert_eq!(bytes_read2, 0);
            break;
        }

        if buffer1[..bytes_read1] != buffer2[..bytes_read2] {
            return Ok(false);
        }
    }

    Ok(true)
}

fn abs_path<P: AsRef<Path>>(path: P) -> impl Display {
    std::path::absolute(path)
        .expect("failed to get absolute path")
        .to_string_lossy()
        .to_string()
}
