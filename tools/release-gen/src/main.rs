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
    /// Overwrite existing output files without prompting.
    #[arg(long)]
    pub force: bool,
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

    let out_dir = if let Some(parent_dir) = args.out.parent() {
        fs::create_dir_all(parent_dir)
            .with_context(|| format!("Creating output dir: {}", abs_path(parent_dir)))?;
        parent_dir.to_path_buf()
    } else {
        std::env::current_dir().context("Reading current directory")?
    };

    let out_patch_dir = out_dir.join("patch");
    let manifest_file_path = out_dir.clone().join("manifest.json");

    // Check if output file or intermediate files exist
    let out_exists = fs::exists(&args.out).context("Checking if output file exists")?;
    let patch_exists = fs::exists(&out_patch_dir).context("Checking if patch dir exists")?;
    let manifest_exists =
        fs::exists(&manifest_file_path).context("Checking if manifest file exists")?;

    if out_exists || patch_exists || manifest_exists {
        if !args.force {
            anyhow::bail!(
                "Output file {} already exists. Use --force to overwrite.",
                abs_path(&args.out)
            );
        }
        // Clean up all existing output files
        if out_exists {
            fs::remove_file(&args.out).with_context(|| {
                format!("Removing existing output file: {}", abs_path(&args.out))
            })?;
        }
        if patch_exists {
            fs::remove_dir_all(&out_patch_dir).with_context(|| {
                format!("Removing existing patch dir: {}", abs_path(&out_patch_dir))
            })?;
        }
        if manifest_exists {
            fs::remove_file(&manifest_file_path).with_context(|| {
                format!(
                    "Removing existing manifest: {}",
                    abs_path(&manifest_file_path)
                )
            })?;
        }
    }

    // Only consider files in the `keyos` folder for updates
    let base_keyos_dir = args.base.join("keyos");
    let new_keyos_dir = args.new.join("keyos");

    let base_src_root = fs::read_dir(&base_keyos_dir)
        .with_context(|| format!("Reading base keyos dir: {}", abs_path(&base_keyos_dir)))?;
    let new_src_root = fs::read_dir(&new_keyos_dir)
        .with_context(|| format!("Reading new keyos dir: {}", abs_path(&new_keyos_dir)))?;

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

            if !files_have_same_content(&base_file_full, &new_file_full)? {
                let patch_file = out_patch_dir.clone().join(base_file);
                let patch_file_parent = patch_file
                    .parent()
                    .expect("Patch file should have a parent");
                fs::create_dir_all(patch_file_parent)
                    .with_context(|| format!("Creating dir: {}", abs_path(patch_file_parent)))?;

                let output = Command::new(args.updiff_path.as_os_str())
                    .arg(&args.base_version)
                    .arg(base_file_full)
                    .arg(&args.new_version)
                    .arg(new_file_full)
                    .arg(&patch_file)
                    .arg("--force")
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
