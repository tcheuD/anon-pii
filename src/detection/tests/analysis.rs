use super::super::*;
use crate::ner::{MockNerDetector, NerSpan};

#[test]
fn selected_analysis_filters_ner_before_password_precedence_without_mapping_writes() {
    let text = "Échec 📨 password=\"Avery Quill\"";
    let name = "Avery Quill";
    let start = text.find(name).unwrap();
    let mut anonymizer = Anonymizer::new(0.5);
    anonymizer.set_ner_detector(Box::new(MockNerDetector {
        spans: vec![NerSpan {
            text: name.into(),
            start,
            end: start + name.len(),
            score: 0.9,
            label: "PER".into(),
        }],
    }));
    let saved_token = anonymizer
        .mapping
        .add("EMAIL_ADDRESS", "prior@example.invalid");
    let saved_mapping = serde_json::to_string(&anonymizer.mapping).unwrap();
    for (entity, expected) in [("PERSON", name), ("PASSWORD", "password=\"Avery Quill\"")] {
        let detections = anonymizer.analyze_with_entities(text, Some(&[entity.into()]));
        assert_eq!(detections.len(), 1, "{detections:?}");
        assert_eq!(detections[0].entity_type, entity);
        assert_eq!(detections[0].original, expected);
        assert_eq!(&text[detections[0].start..detections[0].end], expected);
        assert_eq!(anonymizer.operator, Operator::Token);
        assert_eq!(
            serde_json::to_string(&anonymizer.mapping).unwrap(),
            saved_mapping
        );
    }
    assert!(anonymizer.analyze_with_entities(text, Some(&[])).is_empty());
    let default = anonymizer.analyze(text);
    assert_eq!(default.len(), 1);
    assert_eq!(default[0].entity_type, "PERSON");
    assert_eq!(
        serde_json::to_string(&anonymizer.mapping).unwrap(),
        saved_mapping
    );
    assert_eq!(
        anonymizer.mapping.restore_bracketed(&saved_token),
        "prior@example.invalid"
    );
}

#[test]
fn selected_analysis_filters_ner_locations_before_regex_overlap() {
    let text = "ada@example.invalid";
    let mut anonymizer = Anonymizer::new(0.5);
    anonymizer.set_ner_detector(Box::new(MockNerDetector {
        spans: vec![NerSpan {
            text: text.into(),
            start: 0,
            end: text.len(),
            score: 1.0,
            label: "LOC".into(),
        }],
    }));
    for entity in ["EMAIL_ADDRESS", "LOCATION"] {
        let detections = anonymizer.analyze_with_entities(text, Some(&[entity.into()]));
        assert_eq!(detections.len(), 1, "{detections:?}");
        assert_eq!(detections[0].entity_type, entity);
        assert_eq!(detections[0].original, text);
    }
}
