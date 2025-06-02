use {
    anyhow::Context,
    clap::Parser,
    release_manifest::{Action, ReleaseManifest, SignedData},
    std::{
        fs::{File, ReadDir},
        io::{Read, Write},
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
    if let Err(err) = Command::new(args.updiff_path.as_os_str()).output() {
        if err.to_string().contains("No such file or directory") {
            anyhow::bail!(
                r"updiff tool not found at {}
Please make sure it's in your PATH or specify the path where it is installed. See `--help` for more information.",
                args.updiff_path.display()
            );
        }
    }

    let mut out_path = args.out.clone();
    // Remove the file name.
    out_path.pop();
    std::fs::create_dir_all(&out_path)
        .with_context(|| format!("Creating output dir: {}", out_path.display()))?;
    let Ok(tar_file) = File::create_new(&args.out) else {
        anyhow::bail!(
            "Tar file ({}) already exists. Please delete it before generating a new release.",
            args.out.display()
        );
    };

    let base_src_root = std::fs::read_dir(&args.base)
        .with_context(|| format!("Reading base dir: {}", args.base.display()))?;
    let new_src_root = std::fs::read_dir(&args.new)
        .with_context(|| format!("Reading new dir: {}", args.new.display()))?;

    let out_patch_dir = out_path.join("patch");
    let manifest_file_path = out_path.clone().join("manifest.json");

    std::fs::create_dir(&out_patch_dir)
        .with_context(|| format!("Creating patch dir: {}", out_patch_dir.display()))?;
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
        } else {
            let base_file_full = args.base.clone().join(base_file);
            let new_file_full = args.new.clone().join(base_file);

            if !files_are_same(&base_file_full, &new_file_full)? {
                let patch_file = out_patch_dir.clone().join(base_file);
                let patch_file_parent = patch_file
                    .parent()
                    .expect("Patch file should have a parent");
                std::fs::create_dir_all(patch_file_parent)
                    .with_context(|| format!("Creating dir: {}", patch_file_parent.display()))?;
                let _ = File::create_new(&patch_file)
                    .with_context(|| format!("Creating patch file: {}", patch_file.display()))?;

                let output = Command::new(args.updiff_path.as_os_str())
                    .arg(&args.base_version)
                    .arg(base_file_full)
                    .arg(&args.new_version)
                    .arg(new_file_full)
                    .arg(&patch_file)
                    .output()
                    .context("Running updiff command")?;

                if !output.status.success() {
                    eprintln!("Error: {}", String::from_utf8_lossy(&output.stderr));
                    std::process::exit(1);
                }

                let file = base_file.to_str().expect(PATH_TO_STR_ERROR).to_string();

                actions.push(Action::Patch {
                    patch_file: file.clone(),
                    patch_source: file,
                    base_version: args.base_version.clone(),
                    new_version: args.new_version.clone(),
                });
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
            std::fs::create_dir_all(patch_file_parent)
                .with_context(|| format!("Creating dir: {}", patch_file_parent.display()))?;

            let mut out_file = std::fs::File::create_new(&patch_file_path)
                .with_context(|| format!("Creating patch file: {}", patch_file_path.display()))?;

            let file_path = new_file.to_str().expect(PATH_TO_STR_ERROR).to_string();
            std::io::copy(&mut source_file, &mut out_file).with_context(|| {
                format!(
                    "Copying file from {} to {}",
                    source_file_path.display(),
                    patch_file_path.display()
                )
            })?;
            actions.push(Action::Add {
                source: file_path.clone(),
                dest: file_path,
            });
        }
    }

    let actions = vec![Action::Transaction { actions }];

    let manifest = ReleaseManifest {
        signature: String::from("deadbeef"),
        signed_data: SignedData {
            label: args.label.clone(),
            mandatory: args.mandatory,
            date: chrono::Utc::now().date_naive().to_string(),
            actions,
        },
    };

    manifest_file
        .write_all(
            serde_json::to_string(&manifest)
                .expect("Serialization should not fail")
                .as_bytes(),
        )
        .context("Writing to manifest.json")?;

    let mut tar = tar::Builder::new(tar_file);
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
            if let Err(err) = std::fs::remove_file(file) {
                eprintln!("Error removing file {}: {}", file.display(), err);
            }
        }
        for dir in &self.dirs {
            if let Err(err) = std::fs::remove_dir_all(dir) {
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
            let subdir = std::fs::read_dir(entry.path())
                .with_context(|| format!("Reading subdirectory: {}", entry.path().display()))?;
            file_paths.extend(rec_get_all_files_in_tree(subdir)?);
        }
    }

    Ok(file_paths)
}

fn files_are_same(file_path1: &Path, file_path2: &Path) -> anyhow::Result<bool> {
    let metadata1 = std::fs::metadata(file_path1)
        .with_context(|| format!("Reading metadata from: {}", file_path1.display()))?;
    let metadata2 = std::fs::metadata(file_path2)
        .with_context(|| format!("Reading metadata from: {}", file_path2.display()))?;

    if metadata1.len() != metadata2.len() {
        return Ok(false);
    }

    let mut file1 = File::open(file_path1)
        .with_context(|| format!("Opening file: {}", file_path1.display()))?;
    let mut file2 = File::open(file_path2)
        .with_context(|| format!("Opening file: {}", file_path2.display()))?;

    let mut buffer1 = [0; 1024];
    let mut buffer2 = [0; 1024];

    loop {
        let bytes_read1 = file1
            .read(&mut buffer1)
            .with_context(|| format!("Reading chunk from: {}", file_path1.display()))?;
        let bytes_read2 = file2
            .read(&mut buffer2)
            .with_context(|| format!("Reading chunk from: {}", file_path1.display()))?;

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
