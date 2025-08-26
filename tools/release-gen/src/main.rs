use {
    anyhow::Context,
    clap::Parser,
    release_manifest::{Action, ReleaseManifest, Transaction},
    std::{
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
    /// Path to the new directory.
    #[arg(long, default_value = "KeyOS Release")]
    pub label: String,
    /// Path to the new directory.
    #[arg(long)]
    pub mandatory: bool,
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
                absolute_path(args.updiff_path)
            );
        } else {
            anyhow::bail!("could not run updiff tool: {}", err.to_string());
        }
    }

    println!("[INFO] setting up output directory");

    if fs::exists(&args.out).context("Checking if output file exists")? {
        anyhow::bail!(
            "Output file {} already exists. Please remove it or specify a different output path.",
            absolute_path(args.out)
        );
    }
    let out_dir = if let Some(parent_dir) = args.out.parent() {
        fs::create_dir_all(parent_dir)
            .with_context(|| format!("Creating output dir: {}", absolute_path(parent_dir)))?;
        parent_dir.to_path_buf()
    } else {
        std::env::current_dir().context("Reading current directory")?
    };

    let base_src_root = fs::read_dir(&args.base)
        .with_context(|| format!("Reading base dir: {}", absolute_path(&args.base)))?;
    let new_src_root = fs::read_dir(&args.new)
        .with_context(|| format!("Reading new dir: {}", absolute_path(&args.new)))?;

    let out_patch_dir = out_dir.join("patch");
    let manifest_file_path = out_dir.clone().join("manifest.json");

    fs::create_dir(&out_patch_dir)
        .with_context(|| format!("Creating patch dir: {}", absolute_path(&out_patch_dir)))?;
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

    let mut actions = vec![];

    for base_file in &base_src_files {
        if !new_src_files.contains(base_file) {
            let path = base_file.to_str().expect(PATH_TO_STR_ERROR).to_string();
            actions.push(Action::Delete { path });
            println!("[INFO] action/delete: {}", base_file.display());
        } else {
            let base_file_full = args.base.clone().join(base_file);
            let new_file_full = args.new.clone().join(base_file);

            if !files_are_same(&base_file_full, &new_file_full)? {
                let patch_file = out_patch_dir.clone().join(base_file);
                let patch_file_parent = patch_file
                    .parent()
                    .expect("Patch file should have a parent");
                fs::create_dir_all(patch_file_parent).with_context(|| {
                    format!("Creating dir: {}", absolute_path(patch_file_parent))
                })?;
                let _ = File::create_new(&patch_file).with_context(|| {
                    format!("Creating patch file: {}", absolute_path(&patch_file))
                })?;

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
                .with_context(|| format!("Creating dir: {}", absolute_path(patch_file_parent)))?;

            let mut out_file = fs::File::create_new(&patch_file_path).with_context(|| {
                format!("Creating patch file: {}", absolute_path(&patch_file_path))
            })?;

            let file_path = new_file.to_str().expect(PATH_TO_STR_ERROR).to_string();
            io::copy(&mut source_file, &mut out_file).with_context(|| {
                format!(
                    "Copying file from {} to {}",
                    absolute_path(source_file_path),
                    absolute_path(patch_file_path)
                )
            })?;
            actions.push(Action::Add {
                source: file_path.clone(),
                dest: file_path,
            });
            println!("[INFO] action/add: {}", new_file.display());
        }
    }

    let manifest = ReleaseManifest {
        label: args.label.clone(),
        mandatory: args.mandatory,
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

    let out_file = File::create(&args.out).context("Creating output file")?;
    let mut tar = tar::Builder::new(out_file);
    tar.append_dir_all("patch", &out_patch_dir)?;
    tar.append_file("manifest.json", &mut manifest_file)?;

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
            let subdir = fs::read_dir(entry.path()).with_context(|| {
                format!("Reading subdirectory: {}", absolute_path(entry.path()))
            })?;
            file_paths.extend(rec_get_all_files_in_tree(subdir)?);
        }
    }

    Ok(file_paths)
}

fn files_are_same(file_path1: &Path, file_path2: &Path) -> anyhow::Result<bool> {
    let metadata1 = fs::metadata(file_path1)
        .with_context(|| format!("Reading metadata from: {}", absolute_path(file_path1)))?;
    let metadata2 = fs::metadata(file_path2)
        .with_context(|| format!("Reading metadata from: {}", absolute_path(file_path2)))?;

    if metadata1.len() != metadata2.len() {
        return Ok(false);
    }

    let mut file1 = File::open(file_path1)
        .with_context(|| format!("Opening file: {}", absolute_path(file_path1)))?;
    let mut file2 = File::open(file_path2)
        .with_context(|| format!("Opening file: {}", absolute_path(file_path2)))?;

    let mut buffer1 = [0; 1024];
    let mut buffer2 = [0; 1024];

    loop {
        let bytes_read1 = file1
            .read(&mut buffer1)
            .with_context(|| format!("Reading chunk from: {}", absolute_path(file_path1)))?;
        let bytes_read2 = file2
            .read(&mut buffer2)
            .with_context(|| format!("Reading chunk from: {}", absolute_path(file_path2)))?;

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

fn absolute_path<P: AsRef<Path>>(path: P) -> String {
    fs::canonicalize(path)
        .unwrap()
        .to_string_lossy()
        .to_string()
}
