//! Confidence filtering, span repair, overlap handling and keep rules.
use super::types::{Detection, Source, SourceRange};
use anyhow::Result;
use unicode_categories::UnicodeCategories;

pub fn merge(mut spans: Vec<Detection>, text: &str) -> Result<Vec<Detection>> {
    spans.sort_by_key(|s| (s.range.start(), std::cmp::Reverse(s.range.end())));
    let mut out: Vec<Detection> = Vec::new();
    for span in spans {
        let Some(prev) = out.last_mut() else {
            out.push(span);
            continue;
        };
        if span.range.start() >= prev.range.end() {
            out.push(span);
            continue;
        }
        let prev_contains =
            prev.range.start() <= span.range.start() && prev.range.end() >= span.range.end();
        let span_contains =
            span.range.start() <= prev.range.start() && span.range.end() >= prev.range.end();
        let len = |s: &Detection| -> usize { text[s.range.start()..s.range.end()].chars().count() };
        let mut winner = if prev.score > span.score
            || (prev.score == span.score
                && (len(prev) > len(&span)
                    || (len(prev) == len(&span) && prev.source == Source::Heuristic)))
        {
            prev.clone()
        } else {
            span.clone()
        };
        if !prev_contains && !span_contains {
            winner.range = SourceRange::new(
                text,
                prev.range.start().min(span.range.start()),
                prev.range.end().max(span.range.end()),
            )?;
        }
        *prev = winner;
    }
    Ok(out)
}
fn connector(c: char) -> bool {
    c.is_whitespace() || matches!(c, '\u{feff}' | '\'' | '\u{2019}' | '.' | '-')
}
fn letter(c: char) -> bool {
    c.is_letter() || c.is_mark_nonspacing()
}
fn particle(c: char) -> bool {
    letter(c) || matches!(c, '\'' | '\u{2019}')
}
fn initial(text: &str, end: usize) -> bool {
    let mut chars = text[..end].chars().rev();
    chars.next().is_some_and(|c| c.is_letter_uppercase()) && chars.next().is_none_or(|c| !letter(c))
}
fn bridge(a: &Detection, b: &Detection, text: &str) -> bool {
    if a.label != b.label {
        return false;
    }
    let (left, right) = if a.range.start() <= b.range.start() {
        (a, b)
    } else {
        (b, a)
    };
    if left.range.end() > right.range.start() {
        return true;
    }
    let gap = &text[left.range.end()..right.range.start()];
    !gap.is_empty()
        && gap.chars().all(connector)
        && (!gap.contains('.') || initial(text, left.range.end()))
}
fn adjacent(mut spans: Vec<Detection>, text: &str) -> Result<Vec<Detection>> {
    spans.sort_by_key(|s| s.range.start());
    let mut out: Vec<Detection> = Vec::new();
    for span in spans {
        if let Some(prev) = out.last_mut()
            && bridge(prev, &span, text)
        {
            prev.range = SourceRange::new(
                text,
                prev.range.start().min(span.range.start()),
                prev.range.end().max(span.range.end()),
            )?;
            prev.score = prev.score.max(span.score);
        } else {
            out.push(span);
        }
    }
    Ok(out)
}
fn rescue(span: &Detection, all: &[Detection], index: usize, text: &str) -> Result<Detection> {
    if !span.label.person() {
        return Ok(span.clone());
    }
    let (mut left, mut right) = (0, text.len());
    for (i, other) in all.iter().enumerate() {
        if i == index {
            continue;
        }
        if other.range.end() <= span.range.start() {
            left = left.max(other.range.end());
        }
        if other.range.start() >= span.range.end() {
            right = right.min(other.range.start());
        }
    }
    let (mut start, mut end) = (span.range.start(), span.range.end());
    let mut before = text[left..start].char_indices().rev().peekable();
    let mut conn_start = start;
    for _ in 0..3 {
        if let Some(&(at, c)) = before.peek()
            && connector(c)
        {
            conn_start = left + at;
            before.next();
        } else {
            break;
        }
    }
    if conn_start < start {
        let mut word_start = conn_start;
        let mut count = 0;
        for _ in 0..4 {
            if let Some(&(at, c)) = before.peek()
                && particle(c)
            {
                word_start = left + at;
                count += 1;
                before.next();
            } else {
                break;
            }
        }
        if count > 0
            && text[word_start..]
                .chars()
                .next()
                .is_some_and(|c| c.is_letter_uppercase())
            && (!text[conn_start..start].contains('.') || count == 1)
        {
            start = word_start;
        }
    }
    let mut after = text[end..right].char_indices().peekable();
    let mut conn_end = end;
    for _ in 0..3 {
        if let Some(&(at, c)) = after.peek()
            && connector(c)
        {
            conn_end = end + at + c.len_utf8();
            after.next();
        } else {
            break;
        }
    }
    if conn_end > end
        && !text[end..conn_end].contains('.')
        && after.peek().is_some_and(|(_, c)| c.is_letter_uppercase())
    {
        let mut word_end = conn_end;
        for _ in 0..4 {
            if let Some(&(at, c)) = after.peek()
                && particle(c)
            {
                word_end = end + at + c.len_utf8();
                after.next();
            } else {
                break;
            }
        }
        end = word_end;
    }
    let mut out = span.clone();
    out.range = SourceRange::new(text, start, end)?;
    Ok(out)
}
pub fn repair(spans: Vec<Detection>, text: &str, minimum: f32) -> Result<Vec<Detection>> {
    let (mut kept, mut candidates): (Vec<_>, Vec<_>) = spans
        .into_iter()
        .filter(|s| s.score >= 0.15)
        .partition(|s| s.score >= minimum);
    // Stop when spans no longer change, with a fixed iteration limit.
    for _ in 0..32 {
        let mut changed = false;
        for i in (0..candidates.len()).rev() {
            if kept.iter().any(|s| bridge(s, &candidates[i], text)) {
                kept.push(candidates.remove(i));
                changed = true;
            }
        }
        let merged = adjacent(kept.clone(), text)?;
        changed |=
            merged.len() != kept.len() || merged.iter().zip(&kept).any(|(a, b)| a.range != b.range);
        kept = merged;
        for i in 0..kept.len() {
            let fixed = rescue(&kept[i], &kept, i, text)?;
            changed |= fixed.range != kept[i].range;
            kept[i] = fixed;
        }
        if !changed {
            break;
        }
    }
    kept.sort_by_key(|s| s.range.start());
    Ok(kept)
}

#[cfg(test)]
mod tests {
    use super::super::types::Label;
    use super::*;
    fn span(t: &str, a: usize, b: usize, label: Label, p: f32) -> Detection {
        Detection::new(t, a, b, label, p, Source::Model).unwrap()
    }
    #[test]
    fn partial_overlap_keeps_union() {
        let t = "abcdef";
        let spans = merge(
            vec![
                span(t, 0, 4, Label::Phone, 0.9),
                span(t, 3, 6, Label::TaxId, 0.8),
            ],
            t,
        )
        .unwrap();
        assert_eq!(spans[0].range.text(t).unwrap(), t);
    }
    #[test]
    fn low_score_fragment_extends_anchor() {
        let t = "123 456";
        let spans = repair(
            vec![
                span(t, 0, 3, Label::Phone, 0.9),
                span(t, 4, 7, Label::Phone, 0.2),
            ],
            t,
            0.5,
        )
        .unwrap();
        assert_eq!(spans.len(), 1);
        assert_eq!(spans[0].range.text(t).unwrap(), t);
    }
    #[test]
    fn periods_only_bridge_initials() {
        let t = "Garcia. I";
        assert!(!bridge(
            &span(t, 0, 6, Label::Surname, 0.9),
            &span(t, 8, 9, Label::Surname, 0.9),
            t
        ));
        let t = "J. R";
        assert!(bridge(
            &span(t, 0, 1, Label::Surname, 0.9),
            &span(t, 3, 4, Label::Surname, 0.9),
            t
        ));
    }
    #[test]
    fn crlf_pairs_count_as_two_connector_scalars() {
        // Count CR and LF separately within the three-character connector limit,
        // so two CRLF pairs do not pull a preceding heading into a name.
        let t = "Plan\r\n\r\nDear Alice";
        let start = t.find("Alice").unwrap();
        let s = repair(vec![span(t, start, t.len(), Label::GivenName, 0.9)], t, 0.4).unwrap();
        assert_eq!(s[0].range.text(t).unwrap(), "Dear Alice");
        let lf = "Plan\n\nDear Alice";
        let start = lf.find("Alice").unwrap();
        let s = repair(
            vec![span(lf, start, lf.len(), Label::GivenName, 0.9)],
            lf,
            0.4,
        )
        .unwrap();
        assert_eq!(s[0].range.text(lf).unwrap(), lf);
    }
    #[test]
    fn crlf_list_separator_does_not_rescue_next_field_heading() {
        let t = "Alice\r\n- Date of Birth";
        let s = repair(vec![span(t, 0, 5, Label::GivenName, 0.9)], t, 0.4).unwrap();
        assert_eq!(s[0].range.text(t).unwrap(), "Alice");
    }
    #[test]
    fn particle_rescue_stops_at_other_entity() {
        let t = "John Van Gogh";
        let s = repair(
            vec![
                span(t, 0, 4, Label::GivenName, 0.9),
                span(t, 9, 13, Label::Surname, 0.9),
            ],
            t,
            0.5,
        )
        .unwrap();
        assert!(s[0].range.end() <= s[1].range.start());
    }
}
