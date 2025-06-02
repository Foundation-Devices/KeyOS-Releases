use {
    crate::{
        Args,
        release_manifest::{Action, ReleaseManifest},
        run,
    },
    std::{
        fs::File,
        io::{self, BufReader, Read, Seek},
        path::PathBuf,
    },
};

#[test]
fn release_roundtrip() {
    let updiff_path: PathBuf = std::env::var("UPDIFF_PATH")
        .expect("updiff path should exist")
        .into();
    let base_ver = String::from("v0.0.1");
    let base_dir = PathBuf::from("src/test/fixtures/base/");
    let new_ver = String::from("v0.0.2");
    let new_dir = PathBuf::from("src/test/fixtures/new/");
    let out_dir = PathBuf::from("src/test/fixtures/out");
    let tar_path = out_dir.join("release.tar");

    let args = Args {
        base_version: base_ver.clone(),
        base: base_dir.clone(),
        new_version: new_ver.clone(),
        new: new_dir.clone(),
        label: String::from("test label"),
        mandatory: true,
        out: tar_path.clone(),
        updiff_path,
    };

    run(args).unwrap();

    let tar_file = File::open(tar_path).unwrap();
    let mut tar = tar::Archive::new(tar_file);
    tar.unpack(&out_dir).unwrap();

    let manifest_file = File::open(out_dir.join("manifest.json")).unwrap();
    let reader = BufReader::new(manifest_file);
    let manifest: ReleaseManifest = serde_json::from_reader(reader).unwrap();

    assert_eq!(manifest.signature, "deadbeef");
    assert_eq!(manifest.signed_data.label, "test label");
    assert!(manifest.signed_data.mandatory);
    assert_eq!(
        manifest.signed_data.date,
        chrono::Utc::now().date_naive().to_string(),
    );

    assert_eq!(manifest.signed_data.actions.len(), 1);

    let Action::Transaction { ref actions } = manifest.signed_data.actions[0] else {
        panic!("Expected a single transaction action");
    };

    for action in actions {
        match action {
            Action::Patch {
                patch_file,
                patch_source,
                base_version,
                new_version,
            } => {
                assert_eq!(base_version, &base_ver);
                assert_eq!(new_version, &new_ver);

                let base_file_full = base_dir.join(patch_source);
                let new_file_full = new_dir.join(patch_source);
                let patch_file_full = out_dir.join("patch").join(patch_file);
                let base_file_buf = {
                    let mut base_file = File::open(base_file_full).unwrap();
                    let mut buf = vec![];
                    File::read_to_end(&mut base_file, &mut buf).unwrap();
                    buf
                };
                let patch_file_buf = {
                    let mut patch_file = File::open(&patch_file_full).unwrap();
                    // Skip the `updiff` header.
                    patch_file.seek(io::SeekFrom::Start(216)).unwrap();
                    let mut buf = vec![];
                    File::read_to_end(&mut patch_file, &mut buf).unwrap();
                    buf
                };
                let mut patched_file_buf = Vec::with_capacity(base_file_buf.len());

                bsdiff::patch(
                    &base_file_buf,
                    &mut patch_file_buf.as_slice(),
                    &mut patched_file_buf,
                )
                .unwrap();

                let new_file_buf = {
                    let mut new_file = File::open(new_file_full).unwrap();
                    let mut buf = vec![];
                    File::read_to_end(&mut new_file, &mut buf).unwrap();
                    buf
                };

                assert_eq!(patched_file_buf, new_file_buf);
            }
            Action::Add { source, dest } => {
                let source_file_path = base_dir.join(source);
                let new_file_path = new_dir.join(dest);
                assert!(!source_file_path.exists());
                assert!(new_file_path.exists());
            }
            Action::Delete { path } => {
                let base_file_path = base_dir.join(path);
                let new_file_path = new_dir.join(path);
                assert!(base_file_path.exists());
                assert!(!new_file_path.exists());
            }
            _ => {
                unreachable!("Unexpected action: {:?}", action);
            }
        }
    }

    std::fs::remove_dir_all("src/test/fixtures/out").unwrap();
}
