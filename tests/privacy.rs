#![cfg(unix)]
use anyhow::Result;
use serde_json::{Value, json};
use std::{
    fs,
    io::{self, Write},
    os::unix::fs::PermissionsExt,
    path::Path,
};
use tempfile::tempdir;
use veil_cli::{
    detect::{Detection, Label, Source},
    privacy::{self, Format},
};

fn detect(text: &str) -> Result<Vec<Detection>> {
    let regex = regex::Regex::new(r"[A-Za-z0-9._+-]+@[A-Za-z0-9.-]+|Alice|alice|José")?;
    regex
        .find_iter(text)
        .map(|m| {
            Detection::new(
                text,
                m.start(),
                m.end(),
                if m.as_str().contains('@') {
                    Label::Email
                } else {
                    Label::GivenName
                },
                1.,
                Source::Heuristic,
            )
        })
        .collect()
}
fn tokenize(text: &str, path: &Path, format: Format) -> Vec<u8> {
    let mut out = Vec::new();
    privacy::tokenize(text.as_bytes(), &mut out, path, format, detect).unwrap();
    out
}
fn restore(bytes: &[u8], path: &Path, format: Format) -> Vec<u8> {
    let mut out = Vec::new();
    privacy::restore(bytes, &mut out, path, format).unwrap();
    out
}
fn vault_lines(path: &Path) -> Vec<Value> {
    fs::read_to_string(path)
        .unwrap()
        .lines()
        .map(|s| serde_json::from_str(s).unwrap())
        .collect()
}

#[test]
fn text_round_trip_preserves_unicode_crlf_and_no_final_newline() {
    let d = tempdir().unwrap();
    let p = d.path().join("run.vault");
    let text = "🙂 José\r\nAlice: a@example.com; repeat a@example.com.";
    let protected = tokenize(text, &p, Format::Text);
    assert!(!String::from_utf8_lossy(&protected).contains("José"));
    assert_eq!(restore(&protected, &p, Format::Text), text.as_bytes());
    assert_eq!(
        fs::metadata(&p).unwrap().permissions().mode() & 0o777,
        0o600
    );
}
#[test]
fn nested_json_only_changes_string_values_and_keeps_large_numbers_exact() {
    let d = tempdir().unwrap();
    let p = d.path().join("run.vault");
    let text = r#"{"Alice":"a@example.com","nested":[true,null,123456789012345678901234567890,{"x":"José"}],"n":0.123456789012345678901234567890}"#;
    let protected = tokenize(text, &p, Format::Jsonl);
    let value: Value = serde_json::from_slice(&protected).unwrap();
    assert!(value.get("Alice").is_some());
    assert_eq!(value["nested"][0], true);
    assert_eq!(
        value["nested"][2].to_string(),
        "123456789012345678901234567890"
    );
    let original: Value = serde_json::from_str(text).unwrap();
    assert_eq!(
        serde_json::from_slice::<Value>(&restore(&protected, &p, Format::Jsonl)).unwrap(),
        original
    );
}
#[test]
fn json_implementation_marker_keys_round_trip_as_ordinary_keys() {
    let d = tempdir().unwrap();
    let p = d.path().join("run.vault");
    let text = r#"{"$serde_json::private::Number":"Alice"}"#;
    let protected = tokenize(text, &p, Format::Jsonl);
    let protected_text = String::from_utf8(protected.clone()).unwrap();
    assert!(protected_text.contains("$serde_json::private::Number"));
    assert!(protected_text.contains("[[VEIL:"));
    assert_eq!(
        restore(&protected, &p, Format::Jsonl),
        format!("{text}\n").as_bytes()
    );
}
#[test]
fn repeated_exact_values_reuse_slots_across_fields_and_records_but_not_case() {
    let d = tempdir().unwrap();
    let p = d.path().join("run.vault");
    let text = "{\"a\":\"Alice\",\"b\":\"Alice\"}\n{\"a\":\"Alice\",\"b\":\"alice\"}\n";
    let protected = tokenize(text, &p, Format::Jsonl);
    let output: Vec<Value> = String::from_utf8(protected.clone())
        .unwrap()
        .lines()
        .map(|s| serde_json::from_str(s).unwrap())
        .collect();
    assert_eq!(output[0]["a"], output[0]["b"]);
    assert_eq!(output[0]["a"], output[1]["a"]);
    assert_ne!(output[1]["a"], output[1]["b"]);
    let vault = vault_lines(&p);
    assert_eq!(vault[1]["bindings"].as_array().unwrap().len(), 1);
    assert_eq!(vault[2]["bindings"].as_array().unwrap().len(), 1);
    assert_eq!(vault[1]["bindings"][0]["path"], json!(["a"]));
    assert_eq!(restore(&protected, &p, Format::Jsonl), text.as_bytes());
}
#[test]
fn plain_values_and_empty_streams_still_have_valid_vaults() {
    let d = tempdir().unwrap();
    for (i, (text, format)) in [
        ("", Format::Text),
        ("", Format::Jsonl),
        ("ordinary", Format::Text),
    ]
    .into_iter()
    .enumerate()
    {
        let p = d.path().join(format!("{i}.vault"));
        let protected = tokenize(text, &p, format);
        assert_eq!(restore(&protected, &p, format), text.as_bytes());
    }
}
#[test]
fn nesting_limit_leaves_room_for_a_readable_vault_envelope() {
    let d = tempdir().unwrap();
    let text = format!("{}\"Alice\"{}", "[".repeat(64), "]".repeat(64));
    let p = d.path().join("deep.vault");
    let protected = tokenize(&text, &p, Format::Jsonl);
    assert_eq!(
        restore(&protected, &p, Format::Jsonl),
        format!("{text}\n").as_bytes()
    );
    let p = d.path().join("too-deep.vault");
    let text = format!("[{text}]");
    let mut output = Vec::new();
    assert!(
        privacy::tokenize(text.as_bytes(), &mut output, &p, Format::Jsonl, |_| panic!(
            "must reject before detection"
        ))
        .is_err()
    );
    assert!(output.is_empty());
}
#[test]
fn input_with_reserved_prefix_fails_before_record_output_even_in_keys() {
    let d = tempdir().unwrap();
    for (i, (text, format)) in [
        ("[[VEIL:literal]]", Format::Text),
        (r#"{"[[VEIL:key]]":"Alice"}"#, Format::Jsonl),
        (r#"{"x":["[[VEIL:literal]]"]}"#, Format::Jsonl),
    ]
    .into_iter()
    .enumerate()
    {
        let p = d.path().join(format!("{i}.vault"));
        let mut out = Vec::new();
        let mut called = false;
        assert!(
            privacy::tokenize(text.as_bytes(), &mut out, &p, format, |_| {
                called = true;
                Ok(Vec::new())
            })
            .is_err()
        );
        assert!(!called);
        assert!(out.is_empty());
        assert_eq!(vault_lines(&p).len(), 1);
    }
}
#[test]
fn existing_files_and_symlinks_are_never_overwritten() {
    let d = tempdir().unwrap();
    let p = d.path().join("existing.vault");
    fs::write(&p, b"original").unwrap();
    let mut out = Vec::new();
    assert!(privacy::tokenize("Alice".as_bytes(), &mut out, &p, Format::Text, detect).is_err());
    assert_eq!(fs::read(&p).unwrap(), b"original");
    assert!(out.is_empty());
    let link = d.path().join("link.vault");
    std::os::unix::fs::symlink(&p, &link).unwrap();
    assert!(privacy::tokenize("Alice".as_bytes(), &mut out, &link, Format::Text, detect).is_err());
    assert_eq!(fs::read(&p).unwrap(), b"original");
}
#[test]
fn duplicate_keys_or_invalid_second_record_keep_first_record_restorable() {
    let d = tempdir().unwrap();
    for (i, bad) in [r#"{"x":"secret","x":"other"}"#, "", "42", "not JSON"]
        .into_iter()
        .enumerate()
    {
        let p = d.path().join(format!("{i}.vault"));
        let input = format!("\"Alice\"\n{bad}\n");
        let mut out = Vec::new();
        assert!(privacy::tokenize(input.as_bytes(), &mut out, &p, Format::Jsonl, detect).is_err());
        assert_eq!(restore(&out, &p, Format::Jsonl), b"\"Alice\"\n");
        assert_eq!(vault_lines(&p).len(), 2);
    }
}
#[test]
fn foreign_unknown_malformed_or_edited_tokens_fail_without_output() {
    let d = tempdir().unwrap();
    let p = d.path().join("run.vault");
    let token = String::from_utf8(tokenize("Alice", &p, Format::Text)).unwrap();
    let foreign = format!("[[VEIL:{}:1]]", "f".repeat(32));
    for bad in [
        foreign,
        token.replace(":1]]", ":2]]"),
        token.replace(":1]]", ":01]]"),
        token.trim_end_matches("]]").to_string(),
        "[[VEIL:broken]]".into(),
    ] {
        let mut out = Vec::new();
        assert!(privacy::restore(bad.as_bytes(), &mut out, &p, Format::Text).is_err());
        assert!(out.is_empty());
    }
}
#[test]
fn modified_vault_structure_offsets_duplicate_keys_and_truncated_tail_fail() {
    let d = tempdir().unwrap();
    let p = d.path().join("run.vault");
    let protected = tokenize("🙂 José", &p, Format::Text);
    let lines = vault_lines(&p);
    let serialize = |values: &[Value]| values.iter().map(|v| format!("{v}\n")).collect::<String>();
    let mut bad_cases = Vec::new();
    let mut v = lines.clone();
    v[0]["version"] = json!(2);
    bad_cases.push(serialize(&v));
    let mut v = lines.clone();
    v[1]["bindings"][0]["start"] = json!(1);
    bad_cases.push(serialize(&v));
    let mut v = lines.clone();
    v[1]["index"] = json!(1);
    bad_cases.push(serialize(&v));
    let mut v = lines.clone();
    v[1]["bindings"][0]["slot"] = json!(2);
    bad_cases.push(serialize(&v));
    let mut v = lines.clone();
    v[1]["bindings"][0]["path"] = json!(["missing"]);
    bad_cases.push(serialize(&v));
    let mut v = lines.clone();
    v[0]["extra"] = json!(true);
    bad_cases.push(serialize(&v));
    bad_cases.push(serialize(&lines).trim_end().to_string());
    bad_cases.push("{\"type\":\"header\",\"version\":1,\"version\":1}\n".into());
    for (i, bad) in bad_cases.into_iter().enumerate() {
        let broken = d.path().join(format!("bad-{i}.vault"));
        fs::write(&broken, bad).unwrap();
        let mut out = Vec::new();
        assert!(
            privacy::restore(&protected[..], &mut out, &broken, Format::Text).is_err(),
            "case {i}"
        );
        assert!(out.is_empty());
    }
}
struct ObserveCommit<'a> {
    path: &'a Path,
    original: &'a str,
    bytes: Vec<u8>,
}
impl Write for ObserveCommit<'_> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let mut restored = Vec::new();
        privacy::restore(bytes, &mut restored, self.path, Format::Text)
            .map_err(|_| io::Error::other("restoration data missing before output"))?;
        assert_eq!(restored, self.original.as_bytes());
        self.bytes.extend(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
#[test]
fn restoration_state_exists_before_the_first_output_write() {
    let d = tempdir().unwrap();
    let p = d.path().join("run.vault");
    let text = "Alice";
    let mut observed = ObserveCommit {
        path: &p,
        original: text,
        bytes: Vec::new(),
    };
    privacy::tokenize(text.as_bytes(), &mut observed, &p, Format::Text, detect).unwrap();
    assert!(!observed.bytes.is_empty());
}
#[test]
fn detector_errors_do_not_echo_sensitive_error_payloads() {
    let d = tempdir().unwrap();
    let p = d.path().join("run.vault");
    let mut out = Vec::new();
    let error = privacy::tokenize("secret".as_bytes(), &mut out, &p, Format::Text, |_| {
        anyhow::bail!("secret payload")
    })
    .unwrap_err();
    assert!(!format!("{error:#}").contains("secret"));
    assert!(out.is_empty());
}
#[test]
fn invalid_overlapping_detector_ranges_never_emit_a_partial_record() {
    let d = tempdir().unwrap();
    let p = d.path().join("run.vault");
    let mut out = Vec::new();
    assert!(
        privacy::tokenize(
            "Alice Alice".as_bytes(),
            &mut out,
            &p,
            Format::Text,
            |s| Ok(vec![
                Detection::new(s, 0, 5, Label::GivenName, 1., Source::Model)?,
                Detection::new(s, 3, 7, Label::Surname, 1., Source::Model)?
            ])
        )
        .is_err()
    );
    assert!(out.is_empty());
    assert_eq!(vault_lines(&p).len(), 1);
}
