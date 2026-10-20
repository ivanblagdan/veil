use veil_cli::{
    detect::{Detection, Label, Source},
    redact::{EmailDomains, Redactor},
};

fn detections(text: &str, values: &[(&str, Label)]) -> Vec<Detection> {
    let mut spans = values
        .iter()
        .flat_map(|(value, label)| {
            text.match_indices(*value).map(move |(start, value)| {
                Detection::new(
                    text,
                    start,
                    start + value.len(),
                    *label,
                    1.0,
                    Source::Heuristic,
                )
                .unwrap()
            })
        })
        .collect::<Vec<_>>();
    spans.sort_by_key(|span| span.range.start());
    spans
}

#[test]
fn numbers_follow_source_order_and_repeat_by_label_and_exact_value() {
    let text = "Alex Rivera met José. Alex emailed Rivera.";
    let spans = detections(
        text,
        &[
            ("Alex", Label::GivenName),
            ("Rivera", Label::Surname),
            ("José", Label::GivenName),
        ],
    );
    let mut redactor = Redactor::new(EmailDomains::Hide);
    assert_eq!(
        redactor.render(text, &spans).unwrap(),
        "[GIVEN_NAME_1] [SURNAME_1] met [GIVEN_NAME_2]. [GIVEN_NAME_1] emailed [SURNAME_1]."
    );
}

#[test]
fn numbers_continue_across_records_but_not_across_runs() {
    let mut redactor = Redactor::new(EmailDomains::Hide);
    for (text, expected) in [
        ("Alex", "[GIVEN_NAME_1]"),
        ("Jordan", "[GIVEN_NAME_2]"),
        ("Alex", "[GIVEN_NAME_1]"),
    ] {
        assert_eq!(
            redactor
                .render(text, &detections(text, &[(text, Label::GivenName)]))
                .unwrap(),
            expected
        );
    }
    let mut another = Redactor::new(EmailDomains::Hide);
    assert_eq!(
        another
            .render(
                "Jordan",
                &detections("Jordan", &[("Jordan", Label::GivenName)])
            )
            .unwrap(),
        "[GIVEN_NAME_1]"
    );
}

#[test]
fn case_and_unicode_forms_remain_distinct() {
    let text = "Alex alex José Jose\u{301} José";
    let spans = detections(
        text,
        &[
            ("Alex", Label::GivenName),
            ("alex", Label::GivenName),
            ("José", Label::GivenName),
            ("Jose\u{301}", Label::GivenName),
        ],
    );
    assert_eq!(
        Redactor::new(EmailDomains::Hide)
            .render(text, &spans)
            .unwrap(),
        "[GIVEN_NAME_1] [GIVEN_NAME_2] [GIVEN_NAME_3] [GIVEN_NAME_4] [GIVEN_NAME_3]"
    );
}

#[test]
fn labels_have_independent_numbering_even_for_the_same_value() {
    let text = "Lee / Lee";
    let spans = vec![
        Detection::new(text, 0, 3, Label::GivenName, 1.0, Source::Model).unwrap(),
        Detection::new(text, 6, 9, Label::Surname, 1.0, Source::Model).unwrap(),
    ];
    let mut redactor = Redactor::new(EmailDomains::Hide);
    assert_eq!(
        redactor.render(text, &spans).unwrap(),
        "[GIVEN_NAME_1] / [SURNAME_1]"
    );
    assert_eq!(
        redactor
            .render("Alex", &detections("Alex", &[("Alex", Label::GivenName)]))
            .unwrap(),
        "[GIVEN_NAME_2]"
    );
}

#[test]
fn domains_are_hidden_unless_requested() {
    let text = "alex@example.com jordan@other.org alex@example.com";
    let spans = detections(
        text,
        &[
            ("alex@example.com", Label::Email),
            ("jordan@other.org", Label::Email),
        ],
    );
    assert_eq!(
        Redactor::new(EmailDomains::Hide)
            .render(text, &spans)
            .unwrap(),
        "[EMAIL_1] [EMAIL_2] [EMAIL_1]"
    );
    assert_eq!(
        Redactor::new(EmailDomains::Keep)
            .render(text, &spans)
            .unwrap(),
        "[EMAIL_1]@example.com [EMAIL_2]@other.org [EMAIL_1]@example.com"
    );
}

#[test]
fn email_identity_uses_the_whole_address_without_normalizing_case() {
    let text = "alex@example.com alex@other.org Alex@example.com alex@EXAMPLE.com alex@example.com";
    let spans = detections(
        text,
        &[
            ("alex@example.com", Label::Email),
            ("alex@other.org", Label::Email),
            ("Alex@example.com", Label::Email),
            ("alex@EXAMPLE.com", Label::Email),
        ],
    );
    assert_eq!(
        Redactor::new(EmailDomains::Keep)
            .render(text, &spans)
            .unwrap(),
        "[EMAIL_1]@example.com [EMAIL_2]@other.org [EMAIL_3]@example.com [EMAIL_4]@EXAMPLE.com [EMAIL_1]@example.com"
    );
}

#[test]
fn keep_domains_does_not_expose_fragments_or_malformed_values() {
    let mut values = vec![
        "not an email".to_owned(),
        "alex@ss=\ncinc.com".into(),
        "alex@example.com extra text".into(),
        "alex@example.com@secret.org".into(),
        "Name <alex@example.com>".into(),
        "mailto:alex@example.com".into(),
        "alex@example.com/path".into(),
        "alex@-example.com".into(),
        "alex@example-.com".into(),
        "alex@example..com".into(),
        "alex@localhost".into(),
        "alex@éxample.com".into(),
        ".alex@example.com".into(),
        "alex..x@example.com".into(),
        "alex.@example.com".into(),
        "@example.com".into(),
    ];
    values.push(format!("{}@example.com", "a".repeat(65)));
    values.push(format!("alex@{}.com", "a".repeat(64)));
    values.push(format!(
        "alex@{}.{}.{}.{}.com",
        "a".repeat(63),
        "b".repeat(63),
        "c".repeat(63),
        "d".repeat(63)
    ));
    for value in values {
        let spans = detections(&value, &[(value.as_str(), Label::Email)]);
        assert_eq!(
            Redactor::new(EmailDomains::Keep)
                .render(&value, &spans)
                .unwrap(),
            "[EMAIL_1]"
        );
    }
}

#[test]
fn keeps_complete_subdomains_and_plus_addresses() {
    let text = "alex+tag@team.example.org";
    assert_eq!(
        Redactor::new(EmailDomains::Keep)
            .render(text, &detections(text, &[(text, Label::Email)]))
            .unwrap(),
        "[EMAIL_1]@team.example.org"
    );
}

#[test]
fn domain_option_applies_only_to_email_labels() {
    let text = "https://example.com/a alex@example.com";
    let spans = detections(
        text,
        &[
            ("https://example.com/a", Label::Url),
            ("alex@example.com", Label::Surname),
        ],
    );
    assert_eq!(
        Redactor::new(EmailDomains::Keep)
            .render(text, &spans)
            .unwrap(),
        "[URL_1] [SURNAME_1]"
    );
}

#[test]
fn preserves_untouched_unicode_line_endings_and_empty_input() {
    let text = "🙂 Alex\r\nunchanged\n";
    let mut redactor = Redactor::new(EmailDomains::Hide);
    assert_eq!(
        redactor
            .render(text, &detections(text, &[("Alex", Label::GivenName)]))
            .unwrap(),
        "🙂 [GIVEN_NAME_1]\r\nunchanged\n"
    );
    assert_eq!(redactor.render("", &[]).unwrap(), "");
    assert_eq!(redactor.render(" \r\n", &[]).unwrap(), " \r\n");
}

#[test]
fn rejects_invalid_spans_before_assigning_numbers() {
    let text = "Alex Jordan";
    let first = Detection::new(text, 0, 4, Label::GivenName, 1.0, Source::Model).unwrap();
    let overlap = Detection::new(text, 3, 7, Label::Surname, 1.0, Source::Model).unwrap();
    let second = Detection::new(text, 5, text.len(), Label::GivenName, 1.0, Source::Model).unwrap();
    let mut redactor = Redactor::new(EmailDomains::Hide);
    assert!(redactor.render(text, &[first.clone(), overlap]).is_err());
    assert!(redactor.render(text, &[second, first]).is_err());
    let wrong_source = Detection::new("ab", 1, 2, Label::GivenName, 1.0, Source::Model).unwrap();
    assert!(redactor.render("é", &[wrong_source]).is_err());
    assert_eq!(
        redactor
            .render(
                "Jordan",
                &detections("Jordan", &[("Jordan", Label::GivenName)])
            )
            .unwrap(),
        "[GIVEN_NAME_1]"
    );
}
