//! Reversible local placeholders. The vault is PLAINTEXT and contains originals.
//! Detection rules stay in detect::Pipeline; this module owns framing and state.
mod json;
mod vault;
use crate::detect::{Detection, SourceRange};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    collections::HashMap,
    io::{BufRead, Write},
    path::Path,
};
use vault::{Binding, Part};

const PREFIX: &str = "[[VEIL:";
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Format {
    Text,
    Lines,
    Json,
    Jsonl,
}
impl Format {
    fn is_streaming(self) -> bool {
        matches!(self, Self::Lines | Self::Jsonl)
    }
    fn validate_record(self, value: &Value) -> Result<()> {
        match self {
            Self::Text | Self::Lines => {
                let text = value.as_str().context("text record must be a string")?;
                if self == Self::Lines {
                    ensure!(
                        !text.contains('\n') && !text.ends_with('\r'),
                        "value cannot be represented as one LF-delimited line; use text or JSON framing"
                    );
                }
            }
            Self::Json => (), // Every JSON root type is valid, including scalars.
            Self::Jsonl => ensure!(
                matches!(value, Value::String(_) | Value::Array(_) | Value::Object(_)),
                "JSONL record must be a string, object, or array"
            ),
        }
        Ok(())
    }
}

fn check_key(key: &str) -> Result<()> {
    ensure!(
        !key.contains(PREFIX),
        "JSON keys cannot contain the reserved Veil placeholder prefix"
    );
    Ok(())
}
fn validate_original(value: &Value) -> Result<()> {
    validate_source(value, 0)
}
fn validate_source(value: &Value, depth: usize) -> Result<()> {
    // Leave room for the vault envelope inside serde_json's recursion limit.
    // Reject before committing/output rather than creating an unreadable vault.
    ensure!(
        depth <= 64,
        "JSON input nesting exceeds the supported depth of 64"
    );
    match value {
        Value::String(text) => ensure!(
            !text.contains(PREFIX),
            "input contains the reserved Veil placeholder prefix"
        ),
        Value::Array(values) => {
            for v in values {
                validate_source(v, depth + 1)?;
            }
        }
        Value::Object(values) => {
            for (k, v) in values {
                check_key(k)?;
                validate_source(v, depth + 1)?;
            }
        }
        _ => (),
    }
    Ok(())
}
fn map_strings<F: FnMut(&str, &[Part]) -> Result<String>>(
    value: &Value,
    path: &mut Vec<Part>,
    f: &mut F,
) -> Result<Value> {
    Ok(match value {
        Value::String(s) => Value::String(f(s, path)?),
        Value::Array(values) => {
            let mut out = Vec::with_capacity(values.len());
            for (i, v) in values.iter().enumerate() {
                path.push(Part::Index(i));
                out.push(map_strings(v, path, f)?);
                path.pop();
            }
            Value::Array(out)
        }
        Value::Object(values) => {
            let mut out = serde_json::Map::new();
            for (k, v) in values {
                check_key(k)?;
                path.push(Part::Key(k.clone()));
                out.insert(k.clone(), map_strings(v, path, f)?);
                path.pop();
            }
            Value::Object(out)
        }
        other => other.clone(),
    })
}
fn records<R: BufRead, F: FnMut(Value) -> Result<()>>(
    mut input: R,
    format: Format,
    mut f: F,
) -> Result<()> {
    if !format.is_streaming() {
        let mut text = String::new();
        input
            .read_to_string(&mut text)
            .context("read UTF-8 stdin")?;
        let value = match format {
            Format::Text => Value::String(text),
            Format::Json => json::parse(&text).context("invalid JSON document")?,
            Format::Lines | Format::Jsonl => unreachable!("streaming modes handled below"),
        };
        format.validate_record(&value)?;
        return f(value);
    }
    let mut line = String::new();
    let mut index = 0u64;
    loop {
        line.clear();
        if input
            .read_line(&mut line)
            .context("read UTF-8 stdin record")?
            == 0
        {
            break;
        }
        let value = match format {
            Format::Lines => {
                if line.ends_with('\n') {
                    line.pop();
                    if line.ends_with('\r') {
                        line.pop();
                    }
                }
                Value::String(std::mem::take(&mut line))
            }
            Format::Jsonl => json::parse(&line)
                .with_context(|| format!("invalid JSONL at record {}", index + 1))?,
            Format::Text | Format::Json => unreachable!("single-document modes handled above"),
        };
        format
            .validate_record(&value)
            .with_context(|| format!("input record {}", index + 1))?;
        f(value).with_context(|| format!("input record {}", index + 1))?;
        index = index
            .checked_add(1)
            .context("input record index overflow")?;
    }
    Ok(())
}
fn output_bytes(value: &Value, format: Format) -> Result<Vec<u8>> {
    format.validate_record(value)?;
    let mut out = match format {
        Format::Text | Format::Lines => value
            .as_str()
            .context("text output must be a string")?
            .as_bytes()
            .to_vec(),
        Format::Json | Format::Jsonl => serde_json::to_vec(value)?,
    };
    if format != Format::Text {
        out.push(b'\n');
    }
    Ok(out)
}
fn emit<W: Write>(output: &mut W, bytes: &[u8]) -> Result<()> {
    output.write_all(bytes).context("write output")?;
    output.flush().context("flush output")
}

/// One exact-value pool per invocation. Only new bindings are written per record;
/// they reference original source ranges, not a second stored copy of the value.
struct Pool {
    slots: HashMap<String, u64>,
}
impl Pool {
    fn protect<D: FnMut(&str) -> Result<Vec<Detection>>>(
        &mut self,
        text: &str,
        path: &[Part],
        run: &str,
        bindings: &mut Vec<Binding>,
        detect: &mut D,
    ) -> Result<String> {
        let mut spans = detect(text).map_err(|_| {
            anyhow::anyhow!("local detector failed while processing a string value")
        })?;
        spans.sort_by_key(|s| s.range.start());
        let mut out = String::with_capacity(text.len());
        let mut cursor = 0;
        for span in spans {
            let range = SourceRange::new(text, span.range.start(), span.range.end())?;
            ensure!(
                !span.label.kept(),
                "detector returned an intentionally kept label for replacement"
            );
            ensure!(
                range.start() >= cursor,
                "detector returned overlapping replacement ranges"
            );
            out.push_str(&text[cursor..range.start()]);
            let original = range.text(text)?;
            let slot = if let Some(slot) = self.slots.get(original) {
                *slot
            } else {
                let slot = u64::try_from(self.slots.len())?
                    .checked_add(1)
                    .context("placeholder slot overflow")?;
                self.slots.insert(original.to_owned(), slot);
                bindings.push(Binding {
                    slot,
                    path: path.to_vec(),
                    start: range.start(),
                    end: range.end(),
                });
                slot
            };
            out.push_str(&vault::token(run, slot));
            cursor = range.end();
        }
        out.push_str(&text[cursor..]);
        Ok(out)
    }
}

/// Save each original + new mappings and sync the file BEFORE emitting the
/// corresponding protected record. A failed later record does not erase earlier
/// committed mappings. Memory grows with unique detected values, not all records.
pub fn tokenize<R: BufRead, W: Write, D: FnMut(&str) -> Result<Vec<Detection>>>(
    input: R,
    output: &mut W,
    path: &Path,
    format: Format,
    mut detect: D,
) -> Result<()> {
    let mut writer = vault::Writer::create(path, format)?;
    let mut pool = Pool {
        slots: HashMap::new(),
    };
    records(input, format, |original| {
        validate_original(&original)?;
        let mut bindings = Vec::new();
        let protected = map_strings(&original, &mut Vec::new(), &mut |text, path| {
            pool.protect(text, path, &writer.run, &mut bindings, &mut detect)
        })?;
        let bytes = output_bytes(&protected, format)?;
        writer.record(original, bindings)?;
        emit(output, &bytes)
    })
}

/// Restore exact known placeholders once, without regex/fuzzy matching or model
/// loading. The entire vault is validated before any output is written.
pub fn restore<R: BufRead, W: Write>(
    input: R,
    output: &mut W,
    path: &Path,
    format: Format,
) -> Result<()> {
    let vault = vault::Loaded::read(path)?;
    records(input, format, |value| {
        let restored = map_strings(&value, &mut Vec::new(), &mut |text, _| vault.restore(text))?;
        emit(output, &output_bytes(&restored, format)?)
    })
}
