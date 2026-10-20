use super::{Format, PREFIX, json, validate_original};
use crate::detect::SourceRange;
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    collections::{HashMap, HashSet},
    fs::{File, OpenOptions},
    io::{BufRead, BufReader, Write},
    path::Path,
};

#[derive(Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub(super) enum Part {
    Key(String),
    Index(usize),
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Binding {
    pub slot: u64,
    pub path: Vec<Part>,
    pub start: usize,
    pub end: usize,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Header {
    version: u32,
    run: String,
    input: Format,
}
#[derive(Serialize)]
struct Record {
    index: u64,
    original: Value,
    bindings: Vec<Binding>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RecordFields {
    index: u64,
    bindings: Vec<Binding>,
}
#[derive(Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum Entry {
    Header(Header),
    Record(Record),
}
impl Entry {
    fn parse(mut value: Value) -> Result<Self> {
        // Dispatch explicitly, without serde's internally tagged Content buffer:
        // that buffer cannot round-trip arbitrary-precision JSON numbers.
        let tag = value.as_object_mut().and_then(|v| v.remove("type"));
        match tag.as_ref().and_then(Value::as_str) {
            Some("header") => serde_json::from_value(value)
                .map(Self::Header)
                .map_err(|_| anyhow::anyhow!("invalid vault header fields")),
            Some("record") => {
                // Keep already parsed user JSON intact, including marker-like
                // keys, instead of deserializing it through Value a second time.
                let original = value
                    .as_object_mut()
                    .and_then(|v| v.remove("original"))
                    .context("vault record has no original")?;
                let fields: RecordFields = serde_json::from_value(value)
                    .map_err(|_| anyhow::anyhow!("invalid vault record fields"))?;
                Ok(Self::Record(Record {
                    index: fields.index,
                    original,
                    bindings: fields.bindings,
                }))
            }
            _ => anyhow::bail!("invalid vault entry type"),
        }
    }
}
fn valid_run(run: &str) -> bool {
    run.len() == 32
        && run
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}
pub(super) fn token(run: &str, slot: u64) -> String {
    format!("{PREFIX}{run}:{slot}]]")
}
fn source<'a>(value: &'a Value, path: &[Part]) -> Result<&'a str> {
    let mut v = value;
    for part in path {
        v = match part {
            Part::Key(k) => v.as_object().and_then(|v| v.get(k)),
            Part::Index(i) => v.as_array().and_then(|v| v.get(*i)),
        }
        .context("vault binding addresses a missing source value")?;
    }
    v.as_str().context("vault binding must address a string")
}

pub(super) struct Writer {
    file: File,
    pub run: String,
    next_record: u64,
}
impl Writer {
    pub fn create(path: &Path, format: Format) -> Result<Self> {
        let mut bytes = [0u8; 16];
        getrandom::fill(&mut bytes)
            .map_err(|_| anyhow::anyhow!("cannot generate placeholder run ID"))?;
        let run = bytes.iter().map(|b| format!("{b:02x}")).collect::<String>();
        #[cfg(unix)]
        let file = {
            use std::os::unix::fs::OpenOptionsExt;
            OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(path)
                .context("create new plaintext vault (existing files are never overwritten)")?
        };
        #[cfg(not(unix))]
        let file: File = {
            anyhow::bail!(
                "plaintext vault creation requires Unix owner-only file permissions; this platform is not supported yet"
            );
        };
        let mut writer = Self {
            file,
            run: run.clone(),
            next_record: 0,
        };
        writer.persist(&Entry::Header(Header {
            version: 1,
            run,
            input: format,
        }))?;
        // Persist the new directory entry as well as the file before output.
        #[cfg(unix)]
        File::open(
            path.parent()
                .filter(|p| !p.as_os_str().is_empty())
                .unwrap_or(Path::new(".")),
        )?
        .sync_all()
        .context("sync vault directory")?;
        Ok(writer)
    }
    fn persist(&mut self, entry: &Entry) -> Result<()> {
        let mut bytes = serde_json::to_vec(entry)?;
        bytes.push(b'\n');
        self.file
            .write_all(&bytes)
            .context("write plaintext vault")?;
        self.file
            .sync_all()
            .context("sync plaintext vault before output")
    }
    pub fn record(&mut self, original: Value, bindings: Vec<Binding>) -> Result<()> {
        self.persist(&Entry::Record(Record {
            index: self.next_record,
            original,
            bindings,
        }))?;
        self.next_record = self
            .next_record
            .checked_add(1)
            .context("vault record index overflow")?;
        Ok(())
    }
}

pub(super) struct Loaded {
    run: String,
    values: HashMap<u64, String>,
}
impl Loaded {
    pub fn read(path: &Path) -> Result<Self> {
        let mut reader = BufReader::new(File::open(path).context("open plaintext vault")?);
        let mut line = String::new();
        let mut line_number = 0;
        let mut next = || -> Result<Option<Entry>> {
            line.clear();
            if reader
                .read_line(&mut line)
                .context("read plaintext vault")?
                == 0
            {
                return Ok(None);
            }
            line_number += 1;
            ensure!(
                line.ends_with('\n'),
                "vault contains an unterminated entry at line {line_number}"
            );
            let value = json::parse(&line)
                .with_context(|| format!("invalid vault JSON at line {line_number}"))?;
            let entry = Entry::parse(value)
                .with_context(|| format!("invalid vault entry at line {line_number}"))?;
            Ok(Some(entry))
        };
        let Some(Entry::Header(Header {
            version,
            run,
            input,
        })) = next()?
        else {
            anyhow::bail!("vault must begin with its header");
        };
        ensure!(
            version == 1 && valid_run(&run),
            "unsupported vault version or invalid run ID"
        );
        let mut values = HashMap::new();
        let mut unique = HashSet::new();
        let mut next_slot = 1u64;
        let mut next_record = 0u64;
        while let Some(entry) = next()? {
            let Entry::Record(Record {
                index,
                original,
                bindings,
            }) = entry
            else {
                anyhow::bail!("vault contains more than one header");
            };
            ensure!(index == next_record, "vault record order is invalid");
            ensure!(
                input.is_streaming() || index == 0,
                "single-document vault cannot contain multiple records"
            );
            input.validate_record(&original)?;
            validate_original(&original)?;
            for binding in bindings {
                ensure!(
                    binding.slot == next_slot,
                    "vault binding slots must be unique and consecutive"
                );
                let text = source(&original, &binding.path)?;
                let range = SourceRange::new(text, binding.start, binding.end)?;
                let value = range.text(text)?.to_owned();
                ensure!(
                    unique.insert(value.clone()),
                    "vault contains duplicate exact-value bindings"
                );
                values.insert(next_slot, value);
                next_slot = next_slot.checked_add(1).context("vault slot overflow")?;
            }
            next_record = next_record
                .checked_add(1)
                .context("vault record index overflow")?;
        }
        // A valid log prefix is usable after a later input/output failure. There
        // is deliberately no all-or-nothing completion footer. Truncated entries
        // are rejected; unknown tokens still fail during restoration.
        Ok(Self { run, values })
    }
    pub fn restore(&self, text: &str) -> Result<String> {
        let mut out = String::with_capacity(text.len());
        let mut cursor = 0;
        while let Some(at) = text[cursor..].find(PREFIX) {
            let at = cursor + at;
            out.push_str(&text[cursor..at]);
            let body_start = at + PREFIX.len();
            let end = text[body_start..]
                .find("]]")
                .map(|n| body_start + n)
                .context("unterminated Veil placeholder")?;
            let body = &text[body_start..end];
            let (run, slot) = body.split_once(':').context("malformed Veil placeholder")?;
            ensure!(
                run == self.run,
                "placeholder belongs to a different vault run"
            );
            let slot = slot
                .parse::<u64>()
                .ok()
                .filter(|n| *n > 0 && n.to_string() == slot)
                .context("malformed Veil placeholder slot")?;
            out.push_str(
                self.values
                    .get(&slot)
                    .context("placeholder is not present in this vault")?,
            );
            cursor = end + 2;
        }
        out.push_str(&text[cursor..]);
        Ok(out)
    }
}
