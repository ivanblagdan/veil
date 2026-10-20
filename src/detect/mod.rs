//! Detection rules and model spans mapped back to the original text.
mod heuristics;
mod policy;
mod premask;
mod types;
use crate::{Detector, milliseconds};
use anyhow::{Context, Result, ensure};
use serde::Serialize;
use std::time::Instant;
pub use types::{Detection, Label, Source, SourceRange};
use unicode_segmentation::UnicodeSegmentation;

pub struct Pipeline {
    detector: Detector,
    heuristics: heuristics::Heuristics,
}
#[derive(Debug)]
pub struct Analysis {
    pub redacted: String,
    pub model_input: String,
    pub heuristic: Vec<Detection>,
    pub model_spans: Vec<Detection>,
    pub spans: Vec<Detection>,
    pub first_window_ids: Vec<i64>,
    pub windows: Vec<String>,
    pub token_decisions: Vec<TokenDecision>,
    pub latency_ms: f64,
}
#[derive(Debug, Serialize)]
pub struct TokenDecision {
    pub token: String,
    pub label: String,
    pub score: f32,
}
impl Pipeline {
    pub fn new(detector: Detector) -> Result<Self> {
        Ok(Self {
            detector,
            heuristics: heuristics::Heuristics::new()?,
        })
    }
    pub fn analyze(&mut self, text: &str) -> Result<Analysis> {
        let start = Instant::now();
        let heuristic = self.heuristics.detect(text)?;
        let masked = premask::Premasked::new(text, heuristic.clone())?;
        let ranges = model_windows(&self.detector.tokenizer, &masked.text)?;
        let mut model_spans = Vec::new();
        let mut first_window_ids = Vec::new();
        let mut windows = Vec::new();
        let mut decisions = Vec::new();
        for range in ranges {
            let window = &masked.text[range.clone()];
            let boundaries = GraphemeBounds::new(window);
            let encoded = self.detector.encode("window".into(), window)?;
            if first_window_ids.is_empty() {
                first_window_ids = encoded.input.input_ids.clone();
            }
            let prediction = self.detector.infer(&encoded.input)?;
            let mut candidates = Vec::new();
            let mut builder: Option<(Detection, usize)> = None;
            let flush = |builder: &mut Option<(Detection, usize)>,
                         candidates: &mut Vec<Detection>| {
                if let Some((mut span, count)) = builder.take() {
                    span.score /= count as f32;
                    if span.score >= 0.15 {
                        candidates.push(span);
                    }
                }
            };
            for (i, (&id, &score)) in prediction
                .label_ids
                .iter()
                .zip(&prediction.confidence)
                .enumerate()
            {
                let label = &self.detector.labels[id];
                let token = self
                    .detector
                    .tokenizer
                    .id_to_token(encoded.input.input_ids[i] as u32)
                    .context("missing vocabulary token")?;
                decisions.push(TokenDecision {
                    token: token.clone(),
                    label: label.clone(),
                    score,
                });
                let (a, b) = encoded.offsets[i];
                // Outside labels do not end an active candidate span.
                if label == "O" || encoded.special_tokens_mask[i] != 0 || a == b {
                    continue;
                }
                let (a, b) = boundaries.expand(a, b);
                let base = label
                    .strip_prefix("B-")
                    .or_else(|| label.strip_prefix("I-"))
                    .unwrap_or(label);
                let parsed = Label::parse(base)?;
                if let Some((current, count)) = builder.as_mut()
                    && current.label == parsed
                    && (token.starts_with("##")
                        || label.starts_with("I-")
                        || (a < current.range.end() && b > current.range.start()))
                {
                    current.range = SourceRange::new(
                        window,
                        current.range.start().min(a),
                        current.range.end().max(b),
                    )?;
                    current.score += score;
                    *count += 1;
                } else {
                    flush(&mut builder, &mut candidates);
                    builder = Some((
                        Detection::new(window, a, b, parsed, score, Source::Model)?,
                        1,
                    ));
                }
            }
            flush(&mut builder, &mut candidates);
            // Repair against exactly the text seen by the model, never expanded sentinels.
            for mut span in policy::repair(candidates, window, 0.4)? {
                let (a, b) = boundaries.expand(span.range.start(), span.range.end());
                span.range = SourceRange::new(window, a, b)?;
                span.range = masked.project(
                    SourceRange::new(
                        &masked.text,
                        range.start + span.range.start(),
                        range.start + span.range.end(),
                    )?,
                    text,
                )?;
                model_spans.push(span);
            }
            windows.push(window.to_owned());
        }
        let model_spans = policy::merge(model_spans, text)?;
        let spans = policy::merge(
            heuristic.iter().chain(&model_spans).cloned().collect(),
            text,
        )?
        .into_iter()
        .filter(|s| !s.label.kept())
        .collect::<Vec<_>>();
        let mut redacted = text.to_owned();
        for span in spans.iter().rev() {
            redacted.replace_range(
                span.range.start()..span.range.end(),
                &format!("[{}]", span.label.as_str()),
            );
        }
        Ok(Analysis {
            redacted,
            model_input: masked.text,
            heuristic,
            model_spans,
            spans,
            first_window_ids,
            windows,
            token_decisions: decisions,
            latency_ms: milliseconds(start),
        })
    }
}
fn model_windows(
    tokenizer: &tokenizers::Tokenizer,
    text: &str,
) -> Result<Vec<std::ops::Range<usize>>> {
    let encoding = tokenizer
        .encode(text, false)
        .map_err(|e| anyhow::anyhow!("window tokenization failed: {e}"))?;
    let offsets = encoding.get_offsets();
    let boundaries = GraphemeBounds::new(text);
    let tokens = encoding.get_tokens();
    for &(a, b) in offsets {
        ensure!(
            a < b && b <= text.len() && text.is_char_boundary(a) && text.is_char_boundary(b),
            "invalid window-token range"
        );
    }
    const BUDGET: usize = 500;
    const OVERLAP: usize = 64;
    if tokens.len() <= BUDGET {
        return Ok(std::iter::once(0..text.len()).collect());
    }
    let mut ranges = Vec::new();
    let mut start = 0;
    while start < tokens.len() {
        let mut end = (start + BUDGET).min(tokens.len());
        if end < tokens.len() {
            while end > start + 1 && tokens[end].starts_with("##") {
                end -= 1;
            }
        }
        let (a, b) = boundaries.expand(offsets[start].0, offsets[end - 1].1);
        ranges.push(a..b);
        if end == tokens.len() {
            break;
        }
        let mut next = (end.saturating_sub(OVERLAP)).max(start + 1);
        while next > start + 1 && tokens[next].starts_with("##") {
            next -= 1;
        }
        ensure!(next > start, "window cursor failed to advance");
        start = next;
    }
    Ok(ranges)
}

// Keep stripped trailing accents and multi-scalar graphemes inside the source span.
// These maps address model-input bytes only; original offsets still use Premasked.
struct GraphemeBounds {
    starts: Vec<usize>,
    ends: Vec<usize>,
}
impl GraphemeBounds {
    fn new(text: &str) -> Self {
        let mut starts = vec![0; text.len()];
        let mut ends = vec![0; text.len()];
        for (start, g) in text.grapheme_indices(true) {
            starts[start..start + g.len()].fill(start);
            ends[start..start + g.len()].fill(start + g.len());
        }
        Self { starts, ends }
    }
    fn expand(&self, start: usize, end: usize) -> (usize, usize) {
        if start == end {
            (start, end)
        } else {
            (self.starts[start], self.ends[end - 1])
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn tokenizer() -> tokenizers::Tokenizer {
        let json = serde_json::json!({"version":"1.0","truncation":null,"padding":null,"added_tokens":[],
            "normalizer":{"type":"BertNormalizer","clean_text":true,"handle_chinese_chars":true,"strip_accents":true,"lowercase":true},
            "pre_tokenizer":{"type":"BertPreTokenizer"},"post_processor":null,"decoder":null,
            "model":{"type":"WordPiece","unk_token":"[UNK]","continuing_subword_prefix":"##","max_input_chars_per_word":100,
            "vocab":{"[UNK]":0,"hello":1,"alex":2,"jose":3,"long":4,"##er":5,"name":6}}});
        tokenizers::Tokenizer::from_bytes(serde_json::to_vec(&json).unwrap()).unwrap()
    }
    #[test]
    fn long_windows_overlap_and_cover_every_token() {
        let t = tokenizer();
        let text = format!("{} {}", "hello ".repeat(500), "longer name ".repeat(400));
        let windows = model_windows(&t, &text).unwrap();
        assert!(windows.len() > 2);
        assert_eq!(windows[0].start, 0);
        assert_eq!(windows.last().unwrap().end, text.len() - 1);
        for pair in windows.windows(2) {
            assert!(pair[0].end > pair[1].start);
            assert!(pair[0].start < pair[1].start);
        }
        for window in windows {
            assert!(t.encode(&text[window], false).unwrap().len() <= 500);
        }
    }
    #[test]
    fn tokenizer_removes_format_control_not_neighbor_letter() {
        let t = tokenizer();
        let text = "A\u{200d}lex";
        let e = t.encode(text, false).unwrap();
        assert_eq!(e.get_tokens(), &["alex"]);
        assert_eq!(&text[e.get_offsets()[0].0..e.get_offsets()[0].1], text);
    }
    #[test]
    fn trailing_combining_mark_stays_inside_source_range() {
        let text = "Jose\u{301}";
        let b = GraphemeBounds::new(text);
        assert_eq!(b.expand(0, 4), (0, text.len()));
        assert_eq!(b.expand(0, 0), (0, 0));
    }
    #[test]
    fn empty_and_whitespace_have_one_untruncated_window() {
        let t = tokenizer();
        for s in ["", "  \n"] {
            let ranges = model_windows(&t, s).unwrap();
            assert_eq!(ranges.len(), 1);
            assert_eq!(ranges[0], 0..s.len());
        }
    }
}

/// Diagnostic output uses UTF-16 offsets. Internal ranges remain UTF-8 bytes.
#[derive(Serialize)]
pub struct AuditSpan<'a> {
    pub start: usize,
    pub end: usize,
    pub label: Label,
    pub score: f32,
    pub source: Source,
    pub text: &'a str,
}
impl Analysis {
    pub fn audit_spans<'a>(spans: &[Detection], text: &'a str) -> Result<Vec<AuditSpan<'a>>> {
        spans
            .iter()
            .map(|s| {
                Ok(AuditSpan {
                    start: text[..s.range.start()].encode_utf16().count(),
                    end: text[..s.range.end()].encode_utf16().count(),
                    label: s.label,
                    score: s.score,
                    source: s.source,
                    text: s.range.text(text)?,
                })
            })
            .collect()
    }
}
