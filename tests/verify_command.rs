use std::{fs, process::Command};

#[test]
fn verification_hashes_files_without_loading_native_runtime() {
    let root = tempfile::tempdir().unwrap();
    fs::create_dir(root.path().join("onnx")).unwrap();
    fs::write(root.path().join("onnx/model_q4.onnx"), b"abc").unwrap();
    let runtime = root.path().join("not-a-library");
    fs::write(&runtime, b"abc").unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_veil"))
        .arg("--artifacts")
        .arg(root.path())
        .arg("--runtime")
        .arg(runtime)
        .arg("verify-artifacts")
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    let record: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(record["model_verified"], false);
    assert_eq!(
        record["model_sha256"],
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
    assert_eq!(record["runtime_sha256"], record["model_sha256"]);
    assert!(
        String::from_utf8(output.stderr)
            .unwrap()
            .contains("unrecognized model SHA256")
    );
}
