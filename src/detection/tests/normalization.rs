use super::super::*;
use crate::ner::{MockNerDetector, NerSpan};

fn detection<'a>(detections: &'a [Detection], entity_type: &str) -> &'a Detection {
    detections
        .iter()
        .find(|detection| detection.entity_type == entity_type)
        .unwrap_or_else(|| panic!("missing {entity_type} detection: {detections:?}"))
}

fn assert_raw_span(input: &str, detection: &Detection) {
    assert_eq!(
        input.get(detection.start..detection.end),
        Some(detection.original.as_str()),
        "detection must reference its exact raw input"
    );
}

#[test]
fn no_match_preserves_non_nfkc_and_malformed_escapes_exactly() {
    let mut anonymizer = Anonymizer::new(1.0);
    let input = "markers: ① ﬀ e\u{301} \\u00ZZ %GG";

    let (output, detections) = anonymizer.anonymize_text(input);

    assert_eq!(output, input);
    assert!(detections.is_empty());
}

#[test]
fn keep_preserves_fullwidth_email_and_reports_raw_span() {
    let mut anonymizer = Anonymizer::new(0.0);
    anonymizer.operator = Operator::Keep;
    let input = "contact user＠example.com now";

    let (output, detections) = anonymizer.anonymize_text(input);
    let email = detection(&detections, "EMAIL_ADDRESS");

    assert_eq!(output, input);
    assert_eq!(email.original, "user＠example.com");
    assert_raw_span(input, email);
}

#[test]
fn nfkc_expansion_projects_to_the_whole_raw_grapheme() {
    let mut anonymizer = Anonymizer::new(0.0);
    let input = "send to oﬀice@example.com today";

    let (output, detections) = anonymizer.anonymize_text(input);
    let email = detection(&detections, "EMAIL_ADDRESS");

    assert_eq!(email.original, "oﬀice@example.com");
    assert_raw_span(input, email);
    assert_eq!(anonymizer.mapping.restore_bracketed(&output), input);
}

#[test]
fn unicode_escape_detection_restores_the_exact_escape_spelling() {
    let mut anonymizer = Anonymizer::new(0.0);
    let input = "😀 before client\\u0040company.com after";

    let (output, detections) = anonymizer.anonymize_text(input);
    let email = detection(&detections, "EMAIL_ADDRESS");

    assert_eq!(email.original, r"client\u0040company.com");
    assert_raw_span(input, email);
    assert_eq!(anonymizer.mapping.restore_bracketed(&output), input);
}

#[test]
fn percent_encoded_detection_restores_the_exact_encoding() {
    let mut anonymizer = Anonymizer::new(0.0);
    let input = "query=j.smith%40provider.net&ok=true";

    let (output, detections) = anonymizer.anonymize_text(input);
    let email = detection(&detections, "EMAIL_ADDRESS");

    assert_eq!(email.original, "j.smith%40provider.net");
    assert_raw_span(input, email);
    assert_eq!(anonymizer.mapping.restore_bracketed(&output), input);
}

#[test]
fn multibyte_and_combining_text_before_match_keeps_raw_offsets() {
    let mut anonymizer = Anonymizer::new(0.0);
    let input = "Préfixe e\u{301} 😀 john@example.com fin";

    let (_, detections) = anonymizer.anonymize_text(input);
    let email = detection(&detections, "EMAIL_ADDRESS");
    let expected_start = input.find("john@example.com").unwrap();

    assert_eq!(email.start, expected_start);
    assert_eq!(email.end, expected_start + "john@example.com".len());
    assert_raw_span(input, email);
}

#[test]
fn chained_nfkc_and_escape_decoding_roundtrips_raw_input() {
    let mut anonymizer = Anonymizer::new(0.0);
    let input = "recipient=oﬀice\\u0040example%2Ecom";

    let (output, detections) = anonymizer.anonymize_text(input);
    let email = detection(&detections, "EMAIL_ADDRESS");

    assert_eq!(email.original, "oﬀice\\u0040example%2Ecom");
    assert_raw_span(input, email);
    assert_eq!(anonymizer.mapping.restore_bracketed(&output), input);
}

#[test]
fn normalized_multiline_match_projects_to_exact_raw_span() {
    let mut anonymizer = Anonymizer::new(0.0);
    let input = "card: ４１１１ １１１１\n  １１１１ １１１１ done";

    let (output, detections) = anonymizer.anonymize_text(input);
    let card = detection(&detections, "CREDIT_CARD");

    assert!(card.original.contains('\n'));
    assert_raw_span(input, card);
    assert_eq!(anonymizer.mapping.restore_bracketed(&output), input);
}

#[test]
fn raw_signoff_pass_keeps_offsets_after_normalized_prefix() {
    let mut anonymizer = Anonymizer::new(0.0);
    let input = "ticket ①\nBest regards,\nPrzemek";

    let (_, detections) = anonymizer.anonymize_text(input);
    let person = detection(&detections, "PERSON");

    assert_eq!(person.original, "Przemek");
    assert_raw_span(input, person);
}

#[test]
fn raw_ner_pass_keeps_offsets_after_non_nfkc_multibyte_prefix() {
    let input = "ticket ① 😀 Dupont replied";
    let start = input.find("Dupont").unwrap();
    let mock = MockNerDetector {
        spans: vec![NerSpan {
            text: "Dupont".to_string(),
            start,
            end: start + "Dupont".len(),
            score: 0.9,
            label: "PERSON".to_string(),
        }],
    };
    let mut anonymizer = Anonymizer::new(0.0);
    anonymizer.set_ner_detector(Box::new(mock));

    let (_, detections) = anonymizer.anonymize_text(input);
    let person = detection(&detections, "PERSON");

    assert_eq!(person.start, start);
    assert_eq!(person.original, "Dupont");
    assert_raw_span(input, person);
}
