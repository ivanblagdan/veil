# Architecture

Veil has two main operations:

- `cloak` detects sensitive values, replaces them with exact placeholders, and saves the original records locally.
- `uncloak` reads that saved data and replaces known placeholders with their original values. It does not run detection.

All processing takes place in the current process. There is no background service, inference subprocess or network request during normal commands.

## Code layout

| Path | Responsibility |
|---|---|
| `src/main.rs` | Arguments, standard input/output and command selection |
| `src/lib.rs` | Model loading, text encoding, running the CPU model and reading its output |
| `src/detect/` | Pattern rules, model windows, source ranges and final replacement spans |
| `src/redact.rs` | Numbered redaction markers and optional email domains |
| `src/privacy/mod.rs` | Record formats, placeholder allocation and restoration |
| `src/privacy/json.rs` | JSON parsing without duplicate keys or loss of numeric precision |
| `src/privacy/vault.rs` | Vault creation, saved records and structural validation |
| `src/installation.rs` | Installed file lookup and explicit checksum verification |
| `scripts/install` | Source build, verified downloads and installation |

The `cloak` command replaces detected values in the original text. The model tokenizer splits text into model input pieces for detection.

## Detection

```text
Original string
  → pattern-based detection
  → prepare model text and source mapping
  → split into overlapping windows
  → run the CPU model
  → collect and extend detected spans
  → map spans back to the original string
  → combine overlaps and apply the keep policy
```

A detected span is a start and end byte offset in the original text.

Pattern rules cover structured values such as email addresses, URLs, IP/MAC addresses, valid SSNs and payment-card numbers. Whole digit sequences are checked before accepting SSN/card matches so a valid-looking substring is not taken out of a larger number.

Some structured values are replaced with markers in the model input. Text preparation also handles hyphens and normalization. Source mappings preserve the connection between prepared text and the original UTF-8 bytes. Output is always built from ranges in the original string, not from reconstructed model text.

A single CPU model session is created for each `cloak` or `redact` invocation and reused for every string and record. The Q4 ONNX model is loaded without conversion and produces 32-bit floating-point scores. Inputs use their actual lengths, with no padding or silent truncation. Model array names, dimensions, types, token IDs, masks and output values are checked.

Long input is split into windows of up to 500 content tokens with 64 tokens of overlap. Window boundaries preserve whole word pieces where possible and must make progress. Each string in a JSON value is processed separately; neighboring fields do not provide model context.

The decoder selects the first maximum when scores tie exactly. It does not round nearby scores into a tie. Candidate spans are built from token labels and scores; an outside label does not by itself flush an active candidate. The confidence limits are 0.4 for starting a span and 0.15 for extending one. Span repair is bounded to 32 iterations.

Final ranges are checked against UTF-8 character boundaries and expanded to avoid splitting a displayed character. Overlapping detections are combined and checked. City, state and ZIP-code labels are kept by default. Detection returns ordered, non-overlapping source ranges. Output formatting is separate from detection.

## Numbered redaction

The `redact` command creates one formatter for the whole invocation. For each label it stores a lookup from the exact original value to a number. A new value receives the next number for that label; repeats reuse it. The lookup size determines the next number, so there is no separate counter to keep in sync.

Before formatting a record, all source ranges are checked for valid UTF-8 boundaries, ordering and overlap. The formatter then reads left to right, copying untouched text and inserting markers such as `[GIVEN_NAME_1]`. Numbers follow first appearance in the original input, not reverse replacement order. JSONL records share the same formatter. A new invocation starts with empty lookups.

By default, an email becomes `[EMAIL_1]`. With `--keep-email-domains`, a complete supported address can become `[EMAIL_1]@example.com`. The entire detected value is still the lookup key, not just the portion before `@`. Case and Unicode forms are not normalized for number reuse.

Domain display accepts a standalone ASCII address with a supported local part and DNS-style domain. It does not extract a domain from a folded address, URL or larger detected span. Values that do not pass these checks remain fully replaced. The option changes display only; the detected spans and their labels are unchanged.

These markers do not establish a person's identity, link nicknames, or support restoration. Only the cloak/uncloak path saves a vault. Original text that already looks like a display marker is not authenticated or assigned an identity by the formatter.

The JSONL `latency_ms` value covers detection and formatting, before JSON output encoding. Optional JSONL audit output includes original substrings and internal decisions and must be treated as sensitive.

## Input records

- `text` reads one complete string and preserves its whitespace and line endings.
- `lines` streams text records, removes LF/CRLF delimiters, and emits LF delimiters. A final input record without a newline is still emitted with LF. An empty stream contains no records.
- `json` reads one complete JSON value and writes compact JSON plus LF.
- `jsonl` streams JSON string/object/array records and writes one compact record per line.

Only JSON string values are changed. Keys and other scalar values are preserved. Parsing rejects duplicate keys, including keys that become equal after escape decoding. Numbers are not converted to floating point, so large integers and decimal values keep their precision. Value nesting is limited to 64 levels.

Line mode rejects content that would introduce or confuse record boundaries. In particular, restoration cannot insert a value containing LF or ending in CR into a line record. Use text or JSON for those values.

## Placeholders

Each run receives a 128-bit identifier from the operating system's random source. Placeholders have the exact form:

```text
[[VEIL:<32 lowercase hexadecimal characters>:<positive slot number>]]
```

Slots start at 1. A run keeps one lookup from an exact detected UTF-8 value to its slot, so a repeated value can reuse the same placeholder across fields and records. Case and Unicode normalization differences are not treated as equal values.

Source strings and keys containing `[[VEIL:` are rejected rather than escaped. Restoration scans once and accepts only exact known tokens from the selected run. It does not guess, repair edited tokens, or scan newly restored values again. A run identifier prevents accidental mixing; it is not authentication.

## Vault

The plaintext vault is a version-1 JSONL file. It contains:

1. A header with the format version, run identifier and original record format.
2. A numbered entry for each saved record, including the complete original value and any new bindings.

A binding contains a slot, a path into the original JSON value, and a UTF-8 byte range. Paths use string object keys and integer array indices. The original value is read from that range rather than stored again in a separate mapping. Reused slots do not need another binding.

Line-mode originals contain record content without the input delimiter. The original choice of LF/CRLF and final file termination is therefore not retained in that mode.

The vault is created with exclusive creation and owner-only permissions (`0600`). Existing files and symlinks are refused. The header, file and parent directory entry are synced before protected output is written. For every record:

```text
Read and validate the record
  → detect string values and allocate placeholders
  → prepare the complete output record in memory
  → append the original and new bindings to the vault
  → sync the vault file
  → write the protected output and flush stdout
```

Saving first prevents successful output from referring to a value that was never saved. A failed output write can still leave an extra saved record or a partially delivered output record. Filesystem sync requests do not guarantee survival of every hardware failure.

Earlier complete records remain usable after a later ordinary input error. There is no completion footer or automatic resume. An incomplete final vault entry is rejected, not silently discarded.

Before restoration emits output, it validates the entire vault: header, record order, allowed record counts, consecutive unique slots, paths and source ranges. It then retains the token-to-value mapping, not all original records. There is no encryption or protection against someone who can edit the vault.

## Memory use

Cloaking streams retain the current record and the lookup of unique detected values. That lookup grows with the number of distinct detected values in the run. Text and JSON document modes retain the complete input document. Restoration retains unique token values after reading and validating the vault. Numbered redaction also retains unique detected values in memory, grouped by label, but writes no vault.

## Installation

The installer builds for the operating system and architecture of the Rust compiler it runs. It supports glibc Linux and macOS on x86-64/ARM64. Downloads are listed with checksums in `assets.lock.json`; normal Rust dependencies are fixed by `Cargo.lock`.

The runtime archive is downloaded as data. Only the selected library is copied out; no npm package scripts are executed. The model, tokenizer and configuration are copied without conversion. License terms and required notices are collected in the single installed `LICENSE` file.

Downloads use a checksum-verified build cache. A corrupt entry fails rather than silently being replaced. Offline installation requires both that cache and Cargo's own dependency cache to be ready.

Installation is prepared in a temporary directory beside the destination. An exclusive lock file prevents two installers from writing the same destination at once. Explicit verification and a real cloak/uncloak check run before the directory is renamed into place. Failed installs remove their temporary directory; an abruptly killed installer can leave a directory or lock that needs explicit removal. An existing destination is never merged or overwritten.

Installed commands find files relative to the real executable in `PREFIX/bin`, including when launched through a symlink. The manifest must match the executable version, platform and installed asset set. The only alternative is an explicit pair of model-directory and runtime-library flags. There is no search in the working directory and no download or backend retry if loading fails.

Normal commands read configuration and check the model's input/output requirements but do not hash large files on startup. Explicit `verify-artifacts` checks the installed files against the checksums built into Veil, including the expected license content. `uncloak` bypasses installation lookup entirely.

## Development checks

```sh
cargo test --locked
python3 -m unittest discover -s tests -p '*_test.py'
cargo clippy --all-targets --locked -- -D warnings
cargo fmt --check
```

The normal tests use small constructed inputs and temporary directories; they do not need the model or runtime. The installer also runs a real-model check. `tests/installation.Dockerfile` checks installation in a builder and then runs all four formats offline as a non-root user in a separate runtime image. It is a test, not a required deployment image.

Detection can miss sensitive values. These checks cover implementation behavior, not a promise that every private value will be detected.
