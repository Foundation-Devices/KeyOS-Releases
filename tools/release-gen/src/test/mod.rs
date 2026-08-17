use {
    crate::{
        Args, base_ota_patch_version, manifest_patch_versions, ota_patch_version,
        release_manifest::{Action, ReleaseManifest},
        run, updater_supports_canonical_prereleases,
    },
    std::{
        fs::File,
        io::{self, BufReader, Read, Seek},
        path::PathBuf,
    },
};

struct CleanupGuard;

impl Drop for CleanupGuard {
    fn drop(&mut self) {
        if let Err(e) = std::fs::remove_dir_all("src/test/fixtures/out") {
            eprintln!("Failed to clean up test output directory: {}", e);
        }
    }
}

#[test]
fn release_roundtrip() {
    let updiff_path: PathBuf = std::env::var("UPDIFF_PATH")
        .unwrap_or_else(|_| String::from("updiff"))
        .into();
    let base_ver = String::from("0.0.1");
    let base_dir = PathBuf::from("src/test/fixtures/base/");
    let new_ver = String::from("0.0.2-beta.1");
    let new_dir = PathBuf::from("src/test/fixtures/new/");
    let out_dir = PathBuf::from("src/test/fixtures/out");
    let out_path = out_dir.join("release.tar");

    let args = Args {
        base_version: base_ver.clone(),
        base: base_dir.clone(),
        new_version: new_ver.clone(),
        new: new_dir.clone(),
        label: String::from("test label"),
        mandatory: true,
        reboot_required: false,
        out: out_path.clone(),
        updiff_path,
        force: true,
    };

    let _cleanup_guard = CleanupGuard;

    run(args).unwrap();

    let out_file = File::open(out_path).unwrap();
    let mut tar = tar::Archive::new(out_file);
    tar.unpack(&out_dir).unwrap();

    let manifest_file = File::open(out_dir.join("manifest.json")).unwrap();
    let reader = BufReader::new(manifest_file);
    let manifest: ReleaseManifest = serde_json::from_reader(reader).unwrap();

    assert_eq!(manifest.label, "test label");
    assert!(manifest.mandatory);
    assert_eq!(manifest.date, chrono::Utc::now().date_naive().to_string());

    assert_eq!(manifest.transactions.len(), 1);

    let actions = manifest.transactions[0].actions();
    for action in actions {
        match action {
            Action::Patch {
                patch_file,
                patch_source,
                base_version,
                new_version,
            } => {
                assert_eq!(
                    base_version,
                    &format!("v{}", ota_patch_version(&base_ver).unwrap())
                );
                assert_eq!(
                    new_version,
                    &format!("v{}", ota_patch_version(&new_ver).unwrap())
                );

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
                    let mut decoder = bzip2::read::BzDecoder::new(patch_file);
                    let mut buf = vec![];
                    decoder.read_to_end(&mut buf).unwrap();
                    buf
                };
                // Assuming the size did not change drastically.
                let mut patched_file_buf = Vec::with_capacity(base_file_buf.len());

                let patch = qbsdiff::Bspatch::new(&patch_file_buf).unwrap();
                patch.apply(&base_file_buf, &mut patched_file_buf).unwrap();

                let new_file_buf = {
                    let mut new_file = File::open(new_file_full).unwrap();
                    let mut buf = Vec::with_capacity(patched_file_buf.len());
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
}

#[test]
fn ota_patch_version_keeps_stable_versions() {
    assert_eq!(ota_patch_version("1.4.0").unwrap(), "1.4.0");
    assert_eq!(ota_patch_version("v1.4.0").unwrap(), "1.4.0");
}

#[test]
fn ota_patch_version_maps_beta_versions() {
    assert_eq!(ota_patch_version("1.4.0-beta.1").unwrap(), "1.4.0b1");
    assert_eq!(ota_patch_version("v1.4.0-beta.127").unwrap(), "1.4.0b127");
}

#[test]
fn ota_patch_version_maps_alpha_versions_to_a_distinct_wire_range() {
    assert_eq!(ota_patch_version("1.4.0-alpha.1").unwrap(), "1.4.0b129");
    assert_eq!(ota_patch_version("1.4.0-alpha.126").unwrap(), "1.4.0b254");
}

#[test]
fn ota_patch_version_uses_the_top_bit_as_the_alpha_flag() {
    let beta: u8 = ota_patch_version("1.4.0-beta.1")
        .unwrap()
        .rsplit_once('b')
        .unwrap()
        .1
        .parse()
        .unwrap();
    let alpha: u8 = ota_patch_version("1.4.0-alpha.1")
        .unwrap()
        .rsplit_once('b')
        .unwrap()
        .1
        .parse()
        .unwrap();

    assert_eq!(beta & 0x80, 0);
    assert_eq!(alpha & 0x80, 0x80);
    assert_eq!(alpha & 0x7f, 1);
}

#[test]
fn base_ota_patch_version_accepts_published_beta1() {
    assert_eq!(base_ota_patch_version("1.4.0-beta1").unwrap(), "1.4.0b1");
    assert_eq!(base_ota_patch_version("v1.4.0-beta1").unwrap(), "1.4.0b1");
}

#[test]
fn canonical_manifest_prereleases_start_with_the_1_4_0_updater() {
    assert!(!updater_supports_canonical_prereleases("1.3.1"));
    assert!(!updater_supports_canonical_prereleases("1.4.0-beta1"));
    assert!(updater_supports_canonical_prereleases("1.4.0"));
    assert!(updater_supports_canonical_prereleases("v1.4.1-alpha.1"));

    assert_eq!(
        manifest_patch_versions("1.4.0", "1.4.1-alpha.1", "1.4.0", "1.4.1b129"),
        ("1.4.0".to_string(), "1.4.1-alpha.1".to_string())
    );
    assert_eq!(
        manifest_patch_versions("1.4.0-beta1", "1.4.0", "1.4.0b1", "1.4.0"),
        ("1.4.0b1".to_string(), "1.4.0".to_string())
    );
}

#[test]
fn ota_patch_version_rejects_unsupported_prereleases() {
    assert!(ota_patch_version("1.4.0-alpha1").is_err());
    assert!(ota_patch_version("1.4.0-beta1").is_err());
    assert!(ota_patch_version("1.4.0-beta.0").is_err());
    assert!(ota_patch_version("1.4.0-beta.128").is_err());
    assert!(ota_patch_version("1.4.0-alpha.127").is_err());
    assert!(ota_patch_version("1.4.0-rc.1").is_err());
    assert!(ota_patch_version("255.255.255-alpha.126").is_err());
}
