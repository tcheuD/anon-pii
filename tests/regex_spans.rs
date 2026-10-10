use anon_pii::config::RecognizerConfigFile;
use anon_pii::detection::Anonymizer;
use std::ops::Range;

fn assert_custom_span(pattern: &str, input: &str, expected: Range<usize>) {
    let config = RecognizerConfigFile::from_yaml(&format!(
        "recognizers:\n  - name: Synthetic value\n    entity_type: SYNTHETIC_VALUE\n    patterns:\n      - regex: '{pattern}'\n        score: 1.0\n"
    ))
    .unwrap();
    let mut anonymizer = Anonymizer::new(1.0);
    anonymizer.add_custom_patterns(&config);

    let (prepared, detections) = anonymizer.anonymize_text(input);
    assert_eq!(detections.len(), 1, "{pattern}: {detections:?}");
    let detection = &detections[0];
    assert_eq!(detection.entity_type, "SYNTHETIC_VALUE");
    assert_eq!(detection.start..detection.end, expected);
    assert_eq!(detection.original, input[expected.clone()]);
    assert_eq!(anonymizer.mapping.mappings.len(), 1);

    let (token, original) = anonymizer.mapping.mappings.iter().next().unwrap();
    assert_eq!(original, &input[expected.clone()]);
    assert_eq!(
        prepared,
        format!(
            "{}{token}{}",
            &input[..expected.start],
            &input[expected.end..]
        )
    );
    assert_eq!(anonymizer.mapping.restore_bracketed(&prepared), input);
}

// Upstream rust-lang/regex#1364: reverse literal searches must still return
// the leftmost-first span. A shorter later match would leave part of a
// configured sensitive value in the prepared text even if restoration works.
#[test]
fn custom_recognizer_preserves_leftmost_span_with_reverse_suffix() {
    assert_custom_span(".abb|b", "zabb", 0..4);
    assert_custom_span(".abb|b", "🧪 za%62%62", 5..13);
}

#[test]
fn custom_recognizer_preserves_leftmost_span_with_reverse_inner_literal() {
    assert_custom_span("(?:..acbb|b)a(?:c|d)", "xzbacbbac", 1..9);
}
