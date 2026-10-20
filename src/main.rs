use anyhow::{Context, Result, ensure};
use clap::{Parser, Subcommand};
use serde::Deserialize;
use std::{
    io::{self, BufRead, BufWriter, Read, Write},
    path::PathBuf,
    time::Instant,
};
use veil_cli::{Detector, milliseconds};

#[derive(Parser)]
#[command(
    version,
    about = "Replace sensitive text with reversible placeholders. Vaults contain plaintext originals; detection can miss private data."
)]
struct Cli {
    /// Override the installed model directory; requires --runtime. Not needed for uncloak.
    #[arg(long)]
    artifacts: Option<PathBuf>,
    /// Override the installed runtime with a trusted library; requires --artifacts.
    #[arg(long)]
    runtime: Option<PathBuf>,
    /// CPU inference threads; omit to use the runtime default.
    #[arg(long)]
    threads: Option<usize>,
    #[command(subcommand)]
    command: Command,
}
#[derive(Subcommand)]
enum Command {
    /// Replace detected values with placeholders and save originals in a plaintext vault.
    Cloak {
        /// text/json read one document; lines/jsonl stream records.
        #[arg(long, value_enum, default_value_t = PrivacyFraming::Text)]
        input: PrivacyFraming,
        /// New local vault file; never overwrite an existing file.
        #[arg(long)]
        vault: PathBuf,
    },
    /// Restore exact placeholders from a vault. No model or runtime required.
    Uncloak {
        /// Input and output format; text preserves exact whitespace.
        #[arg(long, value_enum, default_value_t = PrivacyFraming::Text)]
        input: PrivacyFraming,
        #[arg(long)]
        vault: PathBuf,
    },
    /// Redact text without a vault. JSONL expects {uid,source_text} records.
    Redact {
        #[arg(long, value_enum, default_value_t = Framing::Text)]
        input: Framing,
        /// Include sensitive diagnostic details. Requires --input jsonl; keep output private.
        #[arg(long)]
        audit: bool,
    },
    /// Verify installed model, runtime and license files without loading native code.
    VerifyArtifacts,
}
#[derive(Clone, Copy, clap::ValueEnum)]
enum Framing {
    Text,
    Jsonl,
}
#[derive(Clone, Copy, clap::ValueEnum)]
enum PrivacyFraming {
    Text,
    Lines,
    Json,
    Jsonl,
}
impl From<PrivacyFraming> for veil_cli::privacy::Format {
    fn from(value: PrivacyFraming) -> Self {
        match value {
            PrivacyFraming::Text => Self::Text,
            PrivacyFraming::Lines => Self::Lines,
            PrivacyFraming::Json => Self::Json,
            PrivacyFraming::Jsonl => Self::Jsonl,
        }
    }
}

fn run() -> Result<()> {
    let process_start = Instant::now();
    let args = Cli::parse();
    if let Command::Uncloak { input, vault } = &args.command {
        return veil_cli::privacy::restore(
            io::stdin().lock(),
            &mut BufWriter::new(io::stdout().lock()),
            vault,
            (*input).into(),
        );
    }
    let assets = veil_cli::installation::Assets::resolve(args.artifacts, args.runtime)?;
    let (artifacts, runtime) = assets.paths();
    if matches!(args.command, Command::VerifyArtifacts) {
        if let veil_cli::installation::Assets::Installed(installation) = &assets {
            let report = installation.verify()?;
            println!("{}", serde_json::to_string(&report)?);
            ensure!(report.passed, "installed asset checksum mismatch");
            return Ok(());
        }
        let expected = veil_cli::installation::expected_model_hash()?;
        let model_hash = veil_cli::hash_file(&artifacts.join("onnx/model_q4.onnx"))?;
        let runtime_hash = veil_cli::hash_file(&runtime)?;
        let passed = model_hash == expected;
        println!(
            "{}",
            serde_json::json!({"model_verified":passed,"expected_model_sha256":expected,"model_sha256":model_hash,"runtime_sha256":runtime_hash,"runtime_verification":"fingerprint only; no approved runtime hash checked","elapsed_ms":milliseconds(process_start)})
        );
        ensure!(passed, "unrecognized model SHA256");
        return Ok(());
    }
    let detector = Detector::load(&artifacts, &runtime, args.threads)?;
    match args.command {
        Command::VerifyArtifacts | Command::Uncloak { .. } => {
            unreachable!("handled before detector loading")
        }
        Command::Cloak { input, vault } => {
            let mut pipeline = veil_cli::detect::Pipeline::new(detector)?;
            veil_cli::privacy::tokenize(
                io::stdin().lock(),
                &mut BufWriter::new(io::stdout().lock()),
                &vault,
                input.into(),
                |text| pipeline.analyze(text).map(|analysis| analysis.spans),
            )?;
        }
        Command::Redact { input, audit } => {
            use veil_cli::detect::{Analysis, Pipeline};
            let mut pipeline = Pipeline::new(detector)?;
            let mut output = BufWriter::new(io::stdout().lock());
            match input {
                Framing::Text => {
                    ensure!(!audit, "--audit requires --input jsonl");
                    let mut text = String::new();
                    io::stdin().read_to_string(&mut text)?;
                    output.write_all(pipeline.analyze(&text)?.redacted.as_bytes())?;
                }
                Framing::Jsonl => {
                    #[derive(Deserialize)]
                    struct TextRow {
                        uid: u64,
                        source_text: String,
                    }
                    for (index, line) in io::stdin().lock().lines().enumerate() {
                        let line = line?;
                        ensure!(
                            !line.trim().is_empty(),
                            "blank JSONL record at line {}",
                            index + 1
                        );
                        let row: TextRow = serde_json::from_str(&line).map_err(|_| {
                            anyhow::anyhow!("invalid detection input at line {}", index + 1)
                        })?;
                        let result = pipeline
                            .analyze(&row.source_text)
                            .with_context(|| format!("detection failed at line {}", index + 1))?;
                        let value = if audit {
                            serde_json::json!({"uid":row.uid,"redacted":result.redacted,"latency_ms":result.latency_ms,"model_input":result.model_input,"heuristic":Analysis::audit_spans(&result.heuristic,&row.source_text)?,"model_spans":Analysis::audit_spans(&result.model_spans,&row.source_text)?,"spans":Analysis::audit_spans(&result.spans,&row.source_text)?,"first_window_ids":result.first_window_ids,"windows":result.windows,"token_decisions":result.token_decisions})
                        } else {
                            serde_json::json!({"uid":row.uid,"redacted":result.redacted,"latency_ms":result.latency_ms})
                        };
                        serde_json::to_writer(&mut output, &value)?;
                        output.write_all(b"\n")?;
                        output.flush()?;
                    }
                }
            }
            output.flush()?;
        }
    }
    Ok(())
}
fn main() {
    if let Err(error) = run() {
        eprintln!("veil: {error:#}");
        std::process::exit(1);
    }
}
