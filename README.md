# Veil

Veil is a local command-line tool that replaces detected sensitive values with placeholders. Send the resulting text to another tool, then use the saved vault to restore the original values.

It reads standard input and writes standard output, so it fits into existing scripts and pipelines. Detection runs on your CPU. Veil does not send your input to a service or require a background process.

**Detection can miss sensitive information. The vault contains plaintext originals and must stay private.**

## Requirements

To build and install:

- Rust and Cargo 1.92 or newer.
- A C/C++ build toolchain and linker.
- Python 3.9 or newer, with working HTTPS certificates. No Python packages are required.
- Network access for the first build and model/runtime download, unless the required files are already cached.

The installer supports glibc Linux and macOS, on x86-64 and ARM64. Build on the same operating system and architecture where Veil will run. Linux installations have been checked on Debian Bookworm on both architectures; macOS has been checked on ARM64. Alpine/musl and Windows are not supported by the installer.

At run time, keep the complete installation directory. Rust, Python, Node and the source checkout are not needed. Linux also needs compatible system libraries, including the C++ runtime (`libstdc++6` on Debian/Ubuntu).

## Installation

From a checkout of this repository:

```sh
./scripts/install --prefix "$HOME/.local/lib/veil/0.1.0"
export PATH="$HOME/.local/lib/veil/0.1.0/bin:$PATH"

veil --help
```

`--prefix` selects the installation directory. It must not already exist. The installer builds Veil, checks the downloaded files, and runs a small cloak/uncloak check before completing the installation. It does not use `sudo` or modify your shell configuration.

Installed commands find the model and runtime automatically. They do not download files, check for updates, or calculate file checksums on each run.

To upgrade, install into a new directory and update `PATH` or your executable symlink. You can move the complete installation directory, but moving only `bin/veil` is not enough for detection.

### Containers and CI

Install Veil inside the environment that already runs your other tools. It does not need its own container.

For a multi-stage Docker build, use a compatible build and runtime image:

```dockerfile
FROM rust:1.92-bookworm AS veil-build
RUN apt-get update \
    && apt-get install -y --no-install-recommends python3 ca-certificates \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /src/veil
COPY . .
RUN ./scripts/install --prefix /opt/veil

# Replace this with your application's compatible runtime image.
FROM debian:bookworm-slim AS application
RUN apt-get update \
    && apt-get install -y --no-install-recommends libstdc++6 \
    && rm -rf /var/lib/apt/lists/*
COPY --from=veil-build /opt/veil /opt/veil
ENV PATH="/opt/veil/bin:${PATH}"
# Continue setting up your application and its other tools here.
```

Copy **the whole installation directory**, not just the executable. Both stages must use the same architecture and compatible system libraries. A glibc build will not run in an Alpine image.

The installation can be read-only and used by a non-root user. The vault and output locations must be writable. Keep CI vaults private; do not publish them with ordinary build outputs.

### Caches and offline installation

The installer uses a download cache under `$XDG_CACHE_HOME/veil/downloads`, or `~/.cache/veil/downloads`. Cargo uses its own dependency cache.

```sh
./scripts/install --prefix /opt/veil --cache-dir /build-cache/veil

# Requires all downloads and Cargo dependencies to be cached already.
./scripts/install --prefix /opt/veil-other --cache-dir /build-cache/veil --offline
```

A missing offline file or a damaged cached download causes an error. The build cache is not needed after installation.

## Usage

### Cloak and uncloak text

```sh
printf '%s' 'Email alex@example.com' |
  veil cloak --vault message.vault > protected.txt

cat protected.txt
# Email [[VEIL:<run-id>:1]]

veil uncloak --vault message.vault < protected.txt
# Email alex@example.com
```

Each run creates a new vault. Veil refuses to overwrite an existing vault or follow a symlink at that path. Keep the vault locally; pass only the protected text to other tools. The same exact detected value uses the same placeholder within a run.

A response from another tool can also be restored, provided it preserves the exact placeholders:

```sh
veil uncloak --vault message.vault < response.txt > restored-response.txt
```

Restoration does not load the model or runtime. Unknown, malformed, edited or foreign-run placeholders cause an error rather than being silently left unresolved.

### Choose an input format

Both `cloak` and `uncloak` accept `--input`:

| Format | Input and output |
|---|---|
| `text` (default) | One complete text. Preserves whitespace and line endings. |
| `lines` | One text record per line, including empty records. Converts CRLF endings to LF and ends every output record with LF. |
| `json` | One complete JSON document, including multiline input, strings, numbers, booleans and null. Writes compact JSON and a final LF. |
| `jsonl` | One JSON string, object or array per line. Writes one compact JSON record per line. |

JSON modes replace **string values only**. Object keys, numbers, booleans and null values are not protected. JSON formatting and key order may change; restored JSON values are preserved, not the original file formatting.

```sh
# One JSON document.
veil cloak --input json --vault document.vault < input.json > protected.json
veil uncloak --input json --vault document.vault < protected.json > restored.json

# JSON records, read one at a time.
veil cloak --input jsonl --vault records.vault < input.jsonl > protected.jsonl
veil uncloak --input jsonl --vault records.vault < protected.jsonl > restored.jsonl

# Plain-text records, read one at a time.
veil cloak --input lines --vault lines.vault < input.txt > protected-lines.txt
veil uncloak --input lines --vault lines.vault < protected-lines.txt > restored-lines.txt
```

Restoration format is independent of the original input format. For example, a plain-text response containing placeholders from a JSONL run can be restored with `--input text`.

### Redact without a vault

Use `redact` when you want irreversible replacement rather than restorable placeholders:

```sh
printf '%s' 'Email alex@example.com' | veil redact
```

Its JSONL mode uses a separate record format: `{"uid":1,"source_text":"..."}`. It returns `uid`, `redacted` and `latency_ms`. The optional `--audit` flag includes original sensitive text and diagnostic details; keep that output private.

### Verify an installation

```sh
veil verify-artifacts
```

This explicitly checks installed model, tokenizer, configuration, runtime and license checksums without loading the runtime. Normal commands do not repeat these checks. If someone changes installed files after verification, normal startup will not detect that change through a new checksum check.

For a development build outside an installed directory, supply both `--artifacts DIR` and `--runtime FILE` before the subcommand. The runtime is executable native code; only use a trusted library. With explicit paths, `verify-artifacts` checks the model's expected checksum and reports the runtime's checksum, but does not approve that arbitrary runtime.

## Known limitations

- **Not a guarantee of complete removal.** Detection covers selected identifiers and personal details, not every kind of private information or secret. Check protected output before sending it somewhere sensitive.
- **Plaintext vaults.** Vaults contain complete original records, not just replaced values. They use owner-only file permissions on supported systems, but are not encrypted or protected from someone who can read or change your files.
- **Language coverage.** The model is designed for English, Spanish, French, German, Italian, Portuguese and Dutch. Other languages and non-Latin scripts have limited coverage.
- **Some locations are kept.** City, state and ZIP/postal-code labels are not replaced by the model policy; precise address parts may be replaced.
- **JSON gaps.** Sensitive object keys and numeric values are left unchanged. Each string is checked separately. Duplicate keys and documents nested more than 64 levels are rejected.
- **Reserved text.** Input strings and keys containing `[[VEIL:` are rejected to avoid confusion with generated placeholders. Keep placeholders unchanged when passing them through another tool.
- **Line boundaries.** Use `text` for exact line-ending preservation. Line mode rejects ambiguous trailing CR characters. Restoring a multiline value into `lines` is rejected rather than creating extra records.
- **Partial failure.** Streaming commands may have already written earlier records when a later record fails. Those records remain restorable from a complete, valid vault. A failed output write may leave an extra saved record. A vault ending in an incomplete entry is rejected; automatic repair and resume are not available.
- **No record joining.** Veil restores placeholders in text and JSON strings. It does not match separate result files back to source records.

## Further information

Implementation details are in [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md). License terms and third-party notices are in [LICENSE](LICENSE).
