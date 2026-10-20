//! Numbered, non-restorable replacements for final detection spans.
use crate::detect::{Detection, Label};
use anyhow::{Context, Result, ensure};
use std::collections::HashMap;

#[derive(Clone, Copy)]
pub enum EmailDomains {
    Hide,
    Keep,
}

/// One formatter per command invocation. Each label has its own exact-value lookup.
pub struct Redactor {
    email_domains: EmailDomains,
    values: HashMap<Label, HashMap<String, usize>>,
}

impl Redactor {
    pub fn new(email_domains: EmailDomains) -> Self {
        Self {
            email_domains,
            values: HashMap::new(),
        }
    }

    /// Spans must be ordered, non-overlapping UTF-8 ranges in this source string.
    pub fn render(&mut self, text: &str, spans: &[Detection]) -> Result<String> {
        // Validate the whole record before allocating any numbers.
        let mut end = 0;
        for span in spans {
            ensure!(
                span.range.start() >= end,
                "redaction spans overlap or are out of order"
            );
            span.range.text(text)?;
            end = span.range.end();
        }

        let mut output = String::with_capacity(text.len());
        let mut cursor = 0;
        for span in spans {
            output.push_str(&text[cursor..span.range.start()]);
            let value = span.range.text(text)?;
            let values = self.values.entry(span.label).or_default();
            let slot = if let Some(&slot) = values.get(value) {
                slot
            } else {
                let slot = values
                    .len()
                    .checked_add(1)
                    .context("too many distinct redacted values")?;
                values.insert(value.to_owned(), slot);
                slot
            };
            output.push_str(&format!("[{}_{}]", span.label.as_str(), slot));
            if span.label == Label::Email
                && matches!(self.email_domains, EmailDomains::Keep)
                && let Some(domain) = email_domain(value)
            {
                output.push('@');
                output.push_str(domain);
            }
            cursor = span.range.end();
        }
        output.push_str(&text[cursor..]);
        Ok(output)
    }
}

/// Expose only a complete ASCII domain, never a fragment from a larger detected value.
/// This controls display only; it does not add or change email detections.
fn email_domain(value: &str) -> Option<&str> {
    let (local, domain) = value.split_once('@')?;
    if local.is_empty()
        || local.len() > 64
        || value.len() > 254
        || local.starts_with('.')
        || local.ends_with('.')
        || local.contains("..")
        || !local
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"._%+-".contains(&c))
        || domain.len() > 253
    {
        return None;
    }
    let (host, suffix) = domain.rsplit_once('.')?;
    if host.is_empty() || suffix.len() < 2 || !suffix.bytes().all(|c| c.is_ascii_alphabetic()) {
        return None;
    }
    for label in domain.split('.') {
        if label.is_empty()
            || label.len() > 63
            || !label.as_bytes().first()?.is_ascii_alphanumeric()
            || !label.as_bytes().last()?.is_ascii_alphanumeric()
            || !label
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || c == b'-')
        {
            return None;
        }
    }
    Some(domain)
}
