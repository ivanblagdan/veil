//! Prepared model text and byte mappings back to the source.
use super::{
    policy,
    types::{Detection, SourceRange},
};
use anyhow::{Result, ensure};

pub struct Premasked {
    pub text: String,
    starts: Vec<usize>,
    ends: Vec<usize>,
}
impl Premasked {
    pub fn new(raw: &str, spans: Vec<Detection>) -> Result<Self> {
        let mut result = Self {
            text: String::new(),
            starts: Vec::new(),
            ends: Vec::new(),
        };
        let mut cursor = 0;
        for span in policy::merge(spans, raw)? {
            ensure!(span.range.start() >= cursor, "overlapping premask ranges");
            result.copy(raw, cursor, span.range.start());
            let sentinel = format!("[{}]", span.label.as_str());
            result.text.push_str(&sentinel);
            result
                .starts
                .extend(std::iter::repeat_n(span.range.start(), sentinel.len()));
            result
                .ends
                .extend(std::iter::repeat_n(span.range.end(), sentinel.len()));
            cursor = span.range.end();
        }
        result.copy(raw, cursor, raw.len());
        Ok(result)
    }
    fn copy(&mut self, raw: &str, start: usize, end: usize) {
        for (at, c) in raw[start..end].char_indices() {
            let c = if c == '-' { ' ' } else { c };
            self.text.push(c);
            self.starts
                .extend(std::iter::repeat_n(start + at, c.len_utf8()));
            self.ends
                .extend(std::iter::repeat_n(start + at + c.len_utf8(), c.len_utf8()));
        }
    }
    pub fn project(&self, range: SourceRange, raw: &str) -> Result<SourceRange> {
        SourceRange::new(&self.text, range.start(), range.end())?;
        SourceRange::new(raw, self.starts[range.start()], self.ends[range.end() - 1])
    }
}
#[cfg(test)]
mod tests {
    use super::super::heuristics::Heuristics;
    use super::*;
    #[test]
    fn unicode_and_sentinel_ranges() {
        let raw = "🙂 José: a@example.com - end";
        let masked = Premasked::new(raw, Heuristics::new().unwrap().detect(raw).unwrap()).unwrap();
        assert_eq!(masked.text, "🙂 José: [EMAIL]   end");
        let start = masked.text.find("EMAIL").unwrap();
        let r = SourceRange::new(&masked.text, start, start + 5).unwrap();
        assert_eq!(
            masked.project(r, raw).unwrap().text(raw).unwrap(),
            "a@example.com"
        );
        assert_eq!(
            masked
                .project(SourceRange::new(&masked.text, 0, 4).unwrap(), raw)
                .unwrap()
                .text(raw)
                .unwrap(),
            "🙂"
        );
        assert!(SourceRange::new(raw, 1, 4).is_err());
    }
}
