#![cfg(unix)]
use anyhow::Result;
use serde_json::{Value, json};
use std::{
    cell::Cell,
    fs,
    io::{self, BufRead, Read, Write},
    path::Path,
    rc::Rc,
};
use tempfile::tempdir;
use veil_cli::{
    detect::{Detection, Label, Source},
    privacy::{self, Format},
};

fn detect(text: &str) -> Result<Vec<Detection>> {
    regex::Regex::new(r"Alice|Bob|José")?
        .find_iter(text)
        .map(|m| {
            Detection::new(
                text,
                m.start(),
                m.end(),
                Label::GivenName,
                1.,
                Source::Model,
            )
        })
        .collect()
}
fn protect(input: &[u8], path: &Path, format: Format) -> Vec<u8> {
    let mut out = Vec::new();
    privacy::tokenize(input, &mut out, path, format, detect).unwrap();
    out
}
fn restore(input: &[u8], path: &Path, format: Format) -> Vec<u8> {
    let mut out = Vec::new();
    privacy::restore(input, &mut out, path, format).unwrap();
    out
}
fn entries(path: &Path) -> Vec<Value> {
    fs::read_to_string(path)
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect()
}

#[test]
fn lines_strip_crlf_preserve_empty_records_and_terminate_final_record() {
    let d = tempdir().unwrap();
    let path = d.path().join("lines.vault");
    let mut seen = Vec::new();
    let mut protected = Vec::new();
    privacy::tokenize(
        &b"Alice\r\n\r\nBob\nlast"[..],
        &mut protected,
        &path,
        Format::Lines,
        |s| {
            seen.push(s.to_owned());
            detect(s)
        },
    )
    .unwrap();
    assert_eq!(seen, ["Alice", "", "Bob", "last"]);
    assert_eq!(
        restore(&protected, &path, Format::Lines),
        b"Alice\n\nBob\nlast\n"
    );
    let saved = entries(&path);
    assert_eq!(saved[0]["input"], "lines");
    assert_eq!(saved.len(), 5);
    assert_eq!(saved[2]["original"], "");
    assert_eq!(saved[4]["original"], "last");
}
#[test]
fn empty_line_streams_have_exact_record_counts() {
    let d = tempdir().unwrap();
    for (i, (input, expected, count)) in [
        ("", "", 0),
        ("\n", "\n", 1),
        ("\r\n", "\n", 1),
        ("\n\n", "\n\n", 2),
        ("Alice", "Alice\n", 1),
        ("Alice\n", "Alice\n", 1),
        ("Alice\n\n", "Alice\n\n", 2),
    ]
    .into_iter()
    .enumerate()
    {
        let path = d.path().join(format!("{i}.vault"));
        let out = protect(input.as_bytes(), &path, Format::Lines);
        assert_eq!(restore(&out, &path, Format::Lines), expected.as_bytes());
        assert_eq!(entries(&path).len(), count + 1);
    }
}
#[test]
fn embedded_bare_cr_is_preserved_but_ambiguous_trailing_cr_is_rejected() {
    let d = tempdir().unwrap();
    let path = d.path().join("embedded.vault");
    let out = protect(b"left\rright\n", &path, Format::Lines);
    assert_eq!(restore(&out, &path, Format::Lines), b"left\rright\n");
    for (i, bad) in [b"last\r".as_slice(), b"last\r\r\n"]
        .into_iter()
        .enumerate()
    {
        let path = d.path().join(format!("{i}.vault"));
        let mut out = Vec::new();
        assert!(
            privacy::tokenize(bad, &mut out, &path, Format::Lines, |_| panic!(
                "reject before detection"
            ))
            .is_err()
        );
        assert!(out.is_empty());
        assert_eq!(entries(&path).len(), 1);
    }
}
#[test]
fn line_failure_keeps_prior_completed_records_restorable() {
    let d = tempdir().unwrap();
    let path = d.path().join("partial.vault");
    let mut out = Vec::new();
    assert!(
        privacy::tokenize(
            &b"Alice\n[[VEIL:literal]]\n"[..],
            &mut out,
            &path,
            Format::Lines,
            detect
        )
        .is_err()
    );
    assert_eq!(restore(&out, &path, Format::Lines), b"Alice\n");
    assert_eq!(entries(&path).len(), 2);
}
#[test]
fn pretty_json_is_one_record_with_nested_values_and_exact_numbers() {
    let d = tempdir().unwrap();
    let path = d.path().join("json.vault");
    let input=b"{\n  \"name\": \"Alice\",\n  \"items\": [\"Jos\xc3\xa9\", true, null],\n  \"number\": 123456789012345678901234567890\n}\n";
    let out = protect(input, &path, Format::Json);
    assert_eq!(out.iter().filter(|&&b| b == b'\n').count(), 1);
    assert!(!String::from_utf8_lossy(&out).contains("Alice"));
    let restored = restore(&out, &path, Format::Json);
    assert_eq!(
        serde_json::from_slice::<Value>(&restored).unwrap(),
        serde_json::from_slice::<Value>(input).unwrap()
    );
    let saved = entries(&path);
    assert_eq!(saved.len(), 2);
    assert_eq!(saved[0]["input"], "json");
    assert_eq!(saved[1]["bindings"][0]["path"], json!(["items", 0]));
}
#[test]
fn json_accepts_every_root_type_without_losing_scalar_precision() {
    let d = tempdir().unwrap();
    for (i, input) in [
        "null",
        "true",
        "false",
        "123456789012345678901234567890",
        "0.123456789012345678901234567890",
        "\"Alice\"",
        "[\"Alice\",42]",
        "{}",
    ]
    .into_iter()
    .enumerate()
    {
        let path = d.path().join(format!("{i}.vault"));
        let out = protect(input.as_bytes(), &path, Format::Json);
        assert_eq!(
            restore(&out, &path, Format::Json),
            format!("{input}\n").as_bytes()
        );
    }
}
#[test]
fn json_rejects_duplicates_trailing_documents_and_empty_input_before_detection() {
    let d = tempdir().unwrap();
    for (i, input) in [
        "",
        " \n",
        "{}\n{}",
        r#"{"secret":"Alice","secret":"Bob"}"#,
        r#"{"nested":[{"a":1,"\u0061":2}]}"#,
    ]
    .into_iter()
    .enumerate()
    {
        let path = d.path().join(format!("{i}.vault"));
        let mut out = Vec::new();
        let error = privacy::tokenize(input.as_bytes(), &mut out, &path, Format::Json, |_| {
            panic!("reject before detection")
        })
        .unwrap_err();
        assert!(out.is_empty());
        assert_eq!(entries(&path).len(), 1);
        assert!(!format!("{error:#}").contains("Alice"));
    }
}
#[test]
fn json_marker_keys_are_not_reinterpreted_as_number_metadata() {
    let d = tempdir().unwrap();
    let path = d.path().join("marker.vault");
    let input = br#"{"$serde_json::private::Number":"Alice"}"#;
    let out = protect(input, &path, Format::Json);
    assert_eq!(
        restore(&out, &path, Format::Json),
        [input.as_slice(), b"\n"].concat()
    );
}
#[test]
fn single_document_vaults_reject_extra_records_and_line_vaults_validate_strings() {
    let d = tempdir().unwrap();
    let path = d.path().join("original.vault");
    let out = protect(b"Alice\nBob\n", &path, Format::Lines);
    let original = entries(&path);
    for (i, format) in ["text", "json"].into_iter().enumerate() {
        let path = d.path().join(format!("{i}.vault"));
        let mut bad = original.clone();
        bad[0]["input"] = json!(format);
        fs::write(
            &path,
            bad.iter().map(|v| format!("{v}\n")).collect::<String>(),
        )
        .unwrap();
        let mut restored = Vec::new();
        assert!(privacy::restore(&out[..], &mut restored, &path, Format::Lines).is_err());
        assert!(restored.is_empty());
    }
    let path = d.path().join("bad-line.vault");
    let mut bad = original;
    bad[1]["original"] = json!(true);
    fs::write(
        &path,
        bad.iter().map(|v| format!("{v}\n")).collect::<String>(),
    )
    .unwrap();
    let mut restored = Vec::new();
    assert!(privacy::restore(&out[..], &mut restored, &path, Format::Lines).is_err());
    assert!(restored.is_empty());
}
#[test]
fn cross_format_restore_refuses_values_that_would_split_line_records() {
    let d = tempdir().unwrap();
    for (i, original) in ["Alice\nBob", "Alice\r"].into_iter().enumerate() {
        let path = d.path().join(format!("{i}.vault"));
        let mut token = Vec::new();
        privacy::tokenize(original.as_bytes(), &mut token, &path, Format::Text, |s| {
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
        let mut out = Vec::new();
        assert!(privacy::restore(&token[..], &mut out, &path, Format::Lines).is_err());
        assert!(out.is_empty());
        assert_eq!(restore(&token, &path, Format::Text), original.as_bytes());
        let quoted = serde_json::to_vec(&String::from_utf8(token).unwrap()).unwrap();
        assert_eq!(
            serde_json::from_slice::<Value>(&restore(&quoted, &path, Format::Json)).unwrap(),
            original
        );
    }
}
#[test]
fn lines_tokens_can_be_restored_inside_a_json_document() {
    let d = tempdir().unwrap();
    let path = d.path().join("lines.vault");
    let out = protect(b"Alice\nAlice\n", &path, Format::Lines);
    let tokens = String::from_utf8(out).unwrap();
    let tokens: Vec<_> = tokens.lines().collect();
    assert_eq!(tokens[0], tokens[1]);
    let document =
        serde_json::to_vec(&json!({"input":tokens[0],"result":{"explanation":tokens[1]}})).unwrap();
    assert_eq!(
        serde_json::from_slice::<Value>(&restore(&document, &path, Format::Json)).unwrap(),
        json!({"input":"Alice","result":{"explanation":"Alice"}})
    );
}

struct GatedInput<'a> {
    first: &'a [u8],
    second: &'a [u8],
    position: usize,
    flushed: Rc<Cell<bool>>,
}
impl BufRead for GatedInput<'_> {
    fn fill_buf(&mut self) -> io::Result<&[u8]> {
        if self.position < self.first.len() {
            return Ok(&self.first[self.position..]);
        }
        if !self.flushed.get() {
            return Err(io::Error::other(
                "next record requested before prior output flush",
            ));
        }
        Ok(&self.second[self.position - self.first.len()..])
    }
    fn consume(&mut self, n: usize) {
        self.position += n;
    }
}
impl Read for GatedInput<'_> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        let bytes = self.fill_buf()?;
        let n = bytes.len().min(out.len());
        out[..n].copy_from_slice(&bytes[..n]);
        self.consume(n);
        Ok(n)
    }
}
struct GatedOutput {
    bytes: Vec<u8>,
    flushed: Rc<Cell<bool>>,
}
impl Write for GatedOutput {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        self.flushed.set(true);
        Ok(())
    }
}
#[test]
fn streaming_formats_emit_and_flush_before_reading_the_next_record() {
    let d = tempdir().unwrap();
    for (i, (format, first, second)) in [
        (Format::Lines, b"one\n".as_slice(), b"two\n".as_slice()),
        (Format::Jsonl, b"\"one\"\n", b"\"two\"\n"),
    ]
    .into_iter()
    .enumerate()
    {
        let path = d.path().join(format!("{i}.vault"));
        let flushed = Rc::new(Cell::new(false));
        let input = GatedInput {
            first,
            second,
            position: 0,
            flushed: flushed.clone(),
        };
        let mut output = GatedOutput {
            bytes: Vec::new(),
            flushed,
        };
        privacy::tokenize(input, &mut output, &path, format, |_| Ok(Vec::new())).unwrap();
        assert_eq!(output.bytes, [first, second].concat());
    }
}
