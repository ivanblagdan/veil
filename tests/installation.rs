use serde_json::{Value, json};
use std::{
    fs,
    path::{Path, PathBuf},
    process::{Command, Output},
};

// Copying private executables while another test spawns can leave an inherited writer
// open until exec on Linux (ETXTBSY). Serialize this suite's copy/spawn lifetimes.
static EXECUTABLE_TEST: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn fixture(root: &Path) -> PathBuf {
    fs::create_dir_all(root.join("bin")).unwrap();
    let binary = root.join("bin/veil");
    fs::copy(env!("CARGO_BIN_EXE_veil"), &binary).unwrap();
    let lock: Value = serde_json::from_str(include_str!("../assets.lock.json")).unwrap();
    let platform = format!("{}-{}", std::env::consts::OS, std::env::consts::ARCH);
    fs::write(
        root.join("manifest.json"),
        serde_json::to_vec(&json!({
            "schema":1,"veil_version":env!("CARGO_PKG_VERSION"),
            "asset_set":lock["asset_set"],"platform":platform,
        }))
        .unwrap(),
    )
    .unwrap();
    for asset in lock["files"]
        .as_array()
        .unwrap()
        .iter()
        .chain(lock["platforms"][&platform]["files"].as_array().unwrap())
    {
        let path = root.join(asset["path"].as_str().unwrap());
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, b"not executable native code").unwrap();
    }
    fs::write(root.join("LICENSE"), include_str!("../LICENSE")).unwrap();
    binary
}
fn verify(binary: &Path, cwd: &Path) -> Output {
    Command::new(binary)
        .arg("verify-artifacts")
        .current_dir(cwd)
        .output()
        .unwrap()
}

#[test]
fn installed_verification_checks_all_assets_without_loading_native_code() {
    let _guard = EXECUTABLE_TEST.lock().unwrap();
    let temp = tempfile::tempdir().unwrap();
    let binary = fixture(&temp.path().join("prefix"));
    let output = verify(&binary, temp.path());
    assert_eq!(output.status.code(), Some(1));
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["source"], "installation");
    assert_eq!(report["passed"], false);
    assert_eq!(report["files"].as_array().unwrap().len(), 5);
    assert!(String::from_utf8_lossy(&output.stderr).contains("installed asset checksum mismatch"));
}
#[test]
fn license_verification_uses_the_expected_text() {
    let _guard = EXECUTABLE_TEST.lock().unwrap();
    let temp = tempfile::tempdir().unwrap();
    let prefix = temp.path().join("prefix");
    let binary = fixture(&prefix);
    let license_verified = |output: Output| {
        let report: Value = serde_json::from_slice(&output.stdout).unwrap();
        report["files"]
            .as_array()
            .unwrap()
            .iter()
            .find(|file| file["path"] == "LICENSE")
            .unwrap()["verified"]
            .as_bool()
            .unwrap()
    };
    assert!(license_verified(verify(&binary, temp.path())));
    fs::write(prefix.join("LICENSE"), b"changed").unwrap();
    assert!(!license_verified(verify(&binary, temp.path())));
}
#[test]
fn installed_paths_survive_relocation_and_path_symlinks() {
    let _guard = EXECUTABLE_TEST.lock().unwrap();
    let temp = tempfile::tempdir().unwrap();
    fixture(&temp.path().join("old"));
    let relocated = temp.path().join("new");
    fs::rename(temp.path().join("old"), &relocated).unwrap();
    let link = temp.path().join("veil-link");
    #[cfg(unix)]
    std::os::unix::fs::symlink(relocated.join("bin/veil"), &link).unwrap();
    let output = verify(&link, temp.path());
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(
        Path::new(report["root"].as_str().unwrap()),
        relocated.canonicalize().unwrap()
    );
}
#[test]
fn invalid_manifest_never_falls_back_to_current_directory() {
    let _guard = EXECUTABLE_TEST.lock().unwrap();
    let temp = tempfile::tempdir().unwrap();
    let prefix = temp.path().join("prefix");
    let binary = fixture(&prefix);
    let original: Value =
        serde_json::from_slice(&fs::read(prefix.join("manifest.json")).unwrap()).unwrap();
    for (field, value, message) in [
        (
            "schema",
            json!(2),
            "unsupported installation manifest schema",
        ),
        (
            "veil_version",
            json!("wrong"),
            "installation/executable version mismatch",
        ),
        (
            "asset_set",
            json!("wrong"),
            "installation asset set mismatch",
        ),
        ("platform", json!("wrong"), "installation platform mismatch"),
    ] {
        let mut manifest = original.clone();
        manifest[field] = value;
        fs::write(
            prefix.join("manifest.json"),
            serde_json::to_vec(&manifest).unwrap(),
        )
        .unwrap();
        let output = verify(&binary, temp.path());
        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
        assert!(String::from_utf8_lossy(&output.stderr).contains(message));
    }
    fs::write(prefix.join("manifest.json"), b"not JSON").unwrap();
    assert!(
        String::from_utf8_lossy(&verify(&binary, temp.path()).stderr)
            .contains("invalid installation manifest")
    );
}
#[test]
fn explicit_paths_bypass_a_broken_installation() {
    let _guard = EXECUTABLE_TEST.lock().unwrap();
    let temp = tempfile::tempdir().unwrap();
    let prefix = temp.path().join("prefix");
    let binary = fixture(&prefix);
    fs::remove_file(prefix.join("manifest.json")).unwrap();
    let runtime = prefix.join("fake-runtime");
    fs::write(&runtime, b"abc").unwrap();
    let output = Command::new(binary)
        .args([
            "--artifacts",
            prefix.join("model").to_str().unwrap(),
            "--runtime",
            runtime.to_str().unwrap(),
            "verify-artifacts",
        ])
        .output()
        .unwrap();
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["model_verified"], false);
    assert_eq!(
        report["runtime_verification"],
        "fingerprint only; no approved runtime hash checked"
    );
}
#[test]
fn uncloak_does_not_read_installation_or_native_assets() {
    let _guard = EXECUTABLE_TEST.lock().unwrap();
    let temp = tempfile::tempdir().unwrap();
    let binary = fixture(&temp.path().join("prefix"));
    fs::remove_file(temp.path().join("prefix/manifest.json")).unwrap();
    fs::remove_dir_all(temp.path().join("prefix/model")).unwrap();
    fs::remove_dir_all(temp.path().join("prefix/lib")).unwrap();
    let vault = temp.path().join("test.vault");
    veil_cli::privacy::tokenize(
        "hello".as_bytes(),
        &mut Vec::new(),
        &vault,
        veil_cli::privacy::Format::Text,
        |_| Ok(vec![]),
    )
    .unwrap();
    let output = Command::new(binary)
        .args(["uncloak", "--vault", vault.to_str().unwrap()])
        .stdin(std::process::Stdio::null())
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}
#[test]
fn partial_cli_override_is_rejected_before_loading_runtime() {
    let _guard = EXECUTABLE_TEST.lock().unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_veil"))
        .args(["--runtime", "/does/not/exist", "verify-artifacts"])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("must be supplied together"));
}
