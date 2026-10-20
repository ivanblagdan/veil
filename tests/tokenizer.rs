//! Tiny synthetic tokenizer fixtures: no model or native inference runtime needed.
use tokenizers::Tokenizer;

fn tokenizer() -> Tokenizer {
    let json = serde_json::json!({
        "version":"1.0", "truncation":null,"padding":null,
        "added_tokens":[
            {"id":0,"content":"[PAD]","single_word":false,"lstrip":false,"rstrip":false,"normalized":false,"special":true},
            {"id":1,"content":"[UNK]","single_word":false,"lstrip":false,"rstrip":false,"normalized":false,"special":true},
            {"id":2,"content":"[CLS]","single_word":false,"lstrip":false,"rstrip":false,"normalized":false,"special":true},
            {"id":3,"content":"[SEP]","single_word":false,"lstrip":false,"rstrip":false,"normalized":false,"special":true}
        ],
        "normalizer":{"type":"BertNormalizer","clean_text":true,"handle_chinese_chars":true,"strip_accents":true,"lowercase":true},
        "pre_tokenizer":{"type":"BertPreTokenizer"},
        "post_processor":{"type":"BertProcessing","sep":["[SEP]",3],"cls":["[CLS]",2]},
        "decoder":{"type":"WordPiece","prefix":"##","cleanup":true},
        "model":{"type":"WordPiece","unk_token":"[UNK]","continuing_subword_prefix":"##","max_input_chars_per_word":100,
        "vocab":{"[PAD]":0,"[UNK]":1,"[CLS]":2,"[SEP]":3,"jose":4,"alex":5,"rivera":6,"hello":7,"world":8,"中":9,"ラ":10,"##ー":11,"##モ":12,"##ス":13,"通":14,"り":15,"क":16,"##प":17,"##य":18,"##ा":19}}
    });
    Tokenizer::from_bytes(serde_json::to_vec(&json).unwrap()).unwrap()
}
#[test]
fn accents_and_emoji_have_original_utf8_byte_offsets() {
    let t = tokenizer();
    let text = "🙂 José Rivera";
    let e = t.encode(text, true).unwrap();
    assert_eq!(e.get_ids(), &[2, 1, 4, 6, 3]);
    let offsets = e.get_offsets();
    assert_eq!(&text[offsets[2].0..offsets[2].1], "José");
    assert_eq!(&text[offsets[3].0..offsets[3].1], "Rivera");
    assert_eq!(offsets[2].0, 5); // UTF-8 bytes, not code points or UTF-16 units.
}
#[test]
fn format_controls_and_combining_marks_keep_alignment() {
    let t = tokenizer();
    for text in [
        "Al\u{200d}ex Rivera",
        "Al\u{200b}ex Rivera",
        "Jose\u{301} Rivera",
    ] {
        let e = t.encode(text, true).unwrap();
        assert_eq!(e.get_ids()[2], 6);
        for &(start, end) in e.get_offsets() {
            assert!(start <= end && end <= text.len());
            assert!(text.is_char_boundary(start) && text.is_char_boundary(end));
        }
    }
}
#[test]
fn joiner_sequences_are_not_dropped_as_whole_graphemes() {
    let t = tokenizer();
    let e = t.encode("👩\u{200d}🏫 hello", true).unwrap();
    assert_eq!(e.get_ids(), &[2, 1, 7, 3]);
    let e = t.encode("A\u{200c}lex", true).unwrap();
    assert_eq!(e.get_ids(), &[2, 5, 3]);
}
#[test]
fn replacement_characters_are_cleaned_before_wordpiece() {
    let t = tokenizer();
    assert_eq!(
        t.encode("hel\u{fffd}lo", true).unwrap().get_ids(),
        &[2, 7, 3]
    );
}
#[test]
fn cjk_separation_preserves_neighboring_japanese_wordpieces() {
    let t = tokenizer();
    assert_eq!(
        t.encode("hello中world", true).unwrap().get_ids(),
        &[2, 7, 9, 8, 3]
    );
    assert_eq!(
        t.encode("ラーモス通り", true).unwrap().get_ids(),
        &[2, 10, 11, 12, 13, 14, 15, 3]
    );
}
#[test]
fn indic_wordpiece_uses_scalars_not_grapheme_clusters() {
    let t = tokenizer();
    // Mn vowel sign vocalic R is stripped; Mc vowel sign AA is retained.
    assert_eq!(
        t.encode("कृपया", true).unwrap().get_ids(),
        &[2, 16, 17, 18, 19, 3]
    );
}
#[test]
fn empty_input_has_special_tokens_and_no_truncation_is_implicit() {
    let t = tokenizer();
    assert_eq!(t.encode("", true).unwrap().get_ids(), &[2, 3]);
    let e = t.encode("hello ".repeat(600), true).unwrap();
    assert_eq!(e.len(), 602);
}
