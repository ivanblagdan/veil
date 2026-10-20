//! Pattern-based detection for structured values.
use super::types::{Detection, Label, Source};
use anyhow::Result;
use fancy_regex::Regex;

pub struct Heuristics {
    digits: regex::Regex,
    rules: Vec<(Label, Regex)>,
}
impl Heuristics {
    pub fn new() -> Result<Self> {
        let rules = [
            (
                Label::Email,
                r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b",
            ),
            (Label::Url, r#"\bhttps?://[^\s<>"'\])}]+"#),
            (
                Label::Url,
                r#"\bwww\.[A-Za-z0-9.-]+\.[A-Za-z]{2,}(?:/[^\s<>"'\])}]*)?"#,
            ),
            (
                Label::IpAddress,
                r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b",
            ),
            (
                Label::IpAddress,
                r"(?<![:.\w])(?:(?:[0-9A-Fa-f]{1,4}:){7}[0-9A-Fa-f]{1,4}|(?:[0-9A-Fa-f]{1,4}:){1,7}:|(?:[0-9A-Fa-f]{1,4}:){1,6}:[0-9A-Fa-f]{1,4}|(?:[0-9A-Fa-f]{1,4}:){1,5}(?::[0-9A-Fa-f]{1,4}){1,2}|(?:[0-9A-Fa-f]{1,4}:){1,4}(?::[0-9A-Fa-f]{1,4}){1,3}|(?:[0-9A-Fa-f]{1,4}:){1,3}(?::[0-9A-Fa-f]{1,4}){1,4}|(?:[0-9A-Fa-f]{1,4}:){1,2}(?::[0-9A-Fa-f]{1,4}){1,5}|[0-9A-Fa-f]{1,4}:(?::[0-9A-Fa-f]{1,4}){1,6}|::(?:[0-9A-Fa-f]{1,4}:){0,6}[0-9A-Fa-f]{1,4})(?![:.\w])",
            ),
            (
                Label::IpAddress,
                r"\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b",
            ),
        ];
        let boundary = r"(?:(?<![A-Za-z0-9_])(?=[A-Za-z0-9_])|(?<=[A-Za-z0-9_])(?![A-Za-z0-9_]))";
        let rules = rules
            .into_iter()
            .map(|(label, p)| {
                let p = p
                    .replace(r"\b", boundary)
                    .replace(r"\d", "[0-9]")
                    .replace(r"[:.\w]", "[:.A-Za-z0-9_]");
                Ok((label, Regex::new(&p)?))
            })
            .collect::<Result<_>>()?;
        Ok(Self {
            digits: regex::Regex::new(r"[0-9](?:[ .-]?[0-9])*")?,
            rules,
        })
    }
    pub fn detect(&self, text: &str) -> Result<Vec<Detection>> {
        let mut spans = Vec::new();
        for m in self.digits.find_iter(text) {
            let digits: Vec<u8> = m.as_str().bytes().filter(u8::is_ascii_digit).collect();
            let label = if [14, 15, 16].contains(&digits.len()) && luhn(&digits) {
                Some(Label::CreditCard)
            } else if valid_ssn(&digits) {
                Some(Label::Ssn)
            } else {
                None
            };
            if let Some(label) = label {
                spans.push(Detection::new(
                    text,
                    m.start(),
                    m.end(),
                    label,
                    1.,
                    Source::Heuristic,
                )?);
            }
        }
        for (label, regex) in &self.rules {
            for m in regex.find_iter(text) {
                let m = m?; // Fail on regex resource exhaustion, never silently skip.
                spans.push(Detection::new(
                    text,
                    m.start(),
                    m.end(),
                    *label,
                    1.,
                    Source::Heuristic,
                )?);
            }
        }
        spans.sort_by_key(|s| s.range.start());
        Ok(spans)
    }
}
fn luhn(digits: &[u8]) -> bool {
    let sum: u32 = digits
        .iter()
        .rev()
        .enumerate()
        .map(|(i, &v)| {
            let mut d = u32::from(v - b'0');
            if i % 2 == 1 {
                d *= 2;
                if d > 9 {
                    d -= 9;
                }
            }
            d
        })
        .sum();
    sum.is_multiple_of(10)
}
fn valid_ssn(d: &[u8]) -> bool {
    d.len() == 9
        && &d[..3] != b"000"
        && &d[..3] != b"666"
        && d[0] < b'9'
        && &d[3..5] != b"00"
        && &d[5..] != b"0000"
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn validates_whole_digit_runs() {
        let h = Heuristics::new().unwrap();
        let s = h
            .detect("SSN 123-45-6789; card 4111 1111 1111 1111; not 000-00-0000; longer 1234567890")
            .unwrap();
        assert_eq!(s.len(), 2);
        assert_eq!(s[0].label, Label::Ssn);
        assert_eq!(s[1].label, Label::CreditCard);
    }
    #[test]
    fn uses_ascii_word_and_digit_semantics() {
        let h = Heuristics::new().unwrap();
        let s = h
            .detect("éabc@example.com １２３-４５-６７８９ 🙂 https://example.com 2001:db8::1")
            .unwrap();
        assert_eq!(s.iter().filter(|s| s.label == Label::Ssn).count(), 0);
        assert_eq!(
            s[0].range
                .text("éabc@example.com １２３-４５-６７８９ 🙂 https://example.com 2001:db8::1")
                .unwrap(),
            "abc@example.com"
        );
        assert!(s.iter().any(|s| s.label == Label::IpAddress));
    }
}
