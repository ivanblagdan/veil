#![cfg(unix)]
use std::{
    io::Write,
    process::{Command, Stdio},
};
use tempfile::tempdir;
use veil_cli::{
    detect::{Detection, Label, Source},
    privacy::{self, Format},
};

#[test]
fn uncloak_needs_neither_model_paths_nor_native_runtime() {
    let d = tempdir().unwrap();
    let vault = d.path().join("local.vault");
    let mut protected = Vec::new();
    privacy::tokenize(&b"private"[..], &mut protected, &vault, Format::Text, |s| {
        Ok(vec![Detection::new(
            s,
            0,
            s.len(),
            Label::GivenName,
            1.,
            Source::Model,
        )?])
    })
    .unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_veil"))
        .args(["uncloak", "--vault"])
        .arg(&vault)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(&protected).unwrap();
    let result = child.wait_with_output().unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert_eq!(result.stdout, b"private");
}
#[test]
fn uncloak_accepts_new_formats_without_model_flags() {
    let d = tempdir().unwrap();
    for (name, format, input) in [
        ("lines", Format::Lines, "private\r\n\nprivate"),
        ("json", Format::Json, "{\n\"name\":\"private\",\"n\":7\n}"),
    ] {
        let vault = d.path().join(format!("{name}.vault"));
        let mut protected = Vec::new();
        privacy::tokenize(input.as_bytes(), &mut protected, &vault, format, |s| {
            if s == "private" {
                Ok(vec![Detection::new(
                    s,
                    0,
                    s.len(),
                    Label::GivenName,
                    1.,
                    Source::Model,
                )?])
            } else {
                Ok(Vec::new())
            }
        })
        .unwrap();
        let mut child = Command::new(env!("CARGO_BIN_EXE_veil"))
            .args(["uncloak", "--input", name, "--vault"])
            .arg(&vault)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child.stdin.take().unwrap().write_all(&protected).unwrap();
        let result = child.wait_with_output().unwrap();
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        if format == Format::Lines {
            assert_eq!(result.stdout, b"private\n\nprivate\n");
        } else {
            assert_eq!(
                serde_json::from_slice::<serde_json::Value>(&result.stdout).unwrap(),
                serde_json::json!({"name":"private","n":7})
            );
        }
    }
}
#[test]
fn expanded_formats_are_not_advertised_as_redact_support() {
    let help = Command::new(env!("CARGO_BIN_EXE_veil"))
        .args(["cloak", "--help"])
        .output()
        .unwrap();
    assert!(help.status.success());
    let text = String::from_utf8(help.stdout).unwrap();
    assert!(text.contains("text, lines, json, jsonl"));
    let result = Command::new(env!("CARGO_BIN_EXE_veil"))
        .args(["redact", "--input", "lines"])
        .output()
        .unwrap();
    assert_eq!(result.status.code(), Some(2));
    assert!(result.stdout.is_empty());
}
#[test]
fn model_commands_require_explicit_artifact_paths_without_creating_a_vault() {
    let d = tempdir().unwrap();
    let vault = d.path().join("local.vault");
    let result = Command::new(env!("CARGO_BIN_EXE_veil"))
        .args(["cloak", "--vault"])
        .arg(&vault)
        .output()
        .unwrap();
    assert!(!result.status.success());
    assert!(result.stdout.is_empty());
    assert!(!vault.exists());
    assert!(String::from_utf8_lossy(&result.stderr).contains("--artifacts is required"));
}
