use super::super::*;
use crate::ner::{MockNerDetector, NerSpan};

// -- NER pipeline tests (always compiled, use MockNerDetector) --

#[test]
fn test_ner_pipeline_person_blocklist() {
    let mock = MockNerDetector {
        spans: vec![NerSpan {
            text: "Amelia".into(),
            start: 0,
            end: 6,
            score: 0.9,
            label: "PER".into(),
        }],
    };
    let mut a = Anonymizer::new(0.0);
    a.set_ner_detector(Box::new(mock));
    let (result, dets) = a.anonymize_text("Amelia said hello");
    assert!(
        !dets
            .iter()
            .any(|d| d.entity_type == "PERSON" && d.original == "Amelia"),
        "Blocklisted name 'Amelia' should not be detected as PERSON: {:?}",
        dets
    );
    assert!(result.contains("Amelia"));
}

#[test]
fn test_ner_pipeline_person_detected() {
    let mock = MockNerDetector {
        spans: vec![NerSpan {
            text: "Dupont".into(),
            start: 12,
            end: 18,
            score: 0.9,
            label: "PER".into(),
        }],
    };
    let mut a = Anonymizer::new(0.0);
    a.set_ner_detector(Box::new(mock));
    let (result, dets) = a.anonymize_text("Le pilote M. Dupont a décollé.");
    assert!(
        dets.iter().any(|d| d.entity_type == "PERSON"),
        "Non-blocklisted name should be detected as PERSON: {:?}",
        dets
    );
    assert!(result.contains("[PERSON_"));
}

#[test]
fn test_ner_pipeline_span_extension_allcaps() {
    let text = "Damien DUPONT a signé";
    let mock = MockNerDetector {
        spans: vec![NerSpan {
            text: "Damien".into(),
            start: 0,
            end: 6,
            score: 0.9,
            label: "PER".into(),
        }],
    };
    let mut a = Anonymizer::new(0.0);
    a.set_ner_detector(Box::new(mock));
    let (result, dets) = a.anonymize_text(text);
    assert!(
        dets.iter()
            .any(|d| d.entity_type == "PERSON" && d.original.contains("DUPONT")),
        "Span should extend to ALL-CAPS last name: {:?}",
        dets
    );
    assert!(!result.contains("DUPONT"));
    assert!(!result.contains("Damien"));
}

#[test]
fn test_ner_pipeline_consistency_pass() {
    let text = "Pierre DUPONT a dit bonjour. Plus tard, Pierre a fait signe.";
    let mock = MockNerDetector {
        spans: vec![NerSpan {
            text: "Pierre".into(),
            start: 0,
            end: 6,
            score: 0.9,
            label: "PER".into(),
        }],
    };
    let mut a = Anonymizer::new(0.0);
    a.set_ner_detector(Box::new(mock));
    let (result, _dets) = a.anonymize_text(text);
    assert!(!result.contains("DUPONT"), "Full name should be anonymized");
    assert!(
        !result.contains("Pierre"),
        "Bare first name should be anonymized by consistency pass"
    );
}

#[test]
fn test_ner_pipeline_no_detector_no_person() {
    let mut a = Anonymizer::new(0.0);
    let (_, dets) = a.anonymize_text("Le pilote M. Dupont a décollé.");
    assert!(
        !dets.iter().any(|d| d.entity_type == "PERSON"),
        "Without NER detector, PERSON should not be detected: {:?}",
        dets
    );
}

// -- LOCATION entity tests (via NER) --

#[test]
fn test_ner_location_detected() {
    let mock = MockNerDetector {
        spans: vec![NerSpan {
            text: "Paris".into(),
            start: 12,
            end: 17,
            score: 0.9,
            label: "LOCATION".into(),
        }],
    };
    let mut a = Anonymizer::new(0.0);
    a.set_ner_detector(Box::new(mock));
    let (result, dets) = a.anonymize_text("Departure at Paris CDG terminal");
    assert!(
        dets.iter().any(|d| d.entity_type == "LOCATION"),
        "LOCATION not detected: {dets:?}"
    );
    assert!(result.contains("[LOCATION_"));
}

#[test]
fn test_ner_location_and_person_together() {
    let mock = MockNerDetector {
        spans: vec![
            NerSpan {
                text: "Dupont".into(),
                start: 0,
                end: 6,
                score: 0.9,
                label: "PERSON".into(),
            },
            NerSpan {
                text: "Lyon".into(),
                start: 18,
                end: 22,
                score: 0.85,
                label: "LOCATION".into(),
            },
        ],
    };
    let mut a = Anonymizer::new(0.0);
    a.set_ner_detector(Box::new(mock));
    let (result, dets) = a.anonymize_text("Dupont arrived at Lyon airport");
    assert!(
        dets.iter().any(|d| d.entity_type == "PERSON"),
        "PERSON not detected: {dets:?}"
    );
    assert!(
        dets.iter().any(|d| d.entity_type == "LOCATION"),
        "LOCATION not detected: {dets:?}"
    );
    assert!(result.contains("[PERSON_"));
    assert!(result.contains("[LOCATION_"));
}

#[test]
fn test_ner_location_no_span_extension() {
    // LOCATION should NOT get PERSON-style span extension to adjacent ALL-CAPS words
    let mock = MockNerDetector {
        spans: vec![NerSpan {
            text: "Paris".into(),
            start: 0,
            end: 5,
            score: 0.9,
            label: "LOCATION".into(),
        }],
    };
    let mut a = Anonymizer::new(0.0);
    a.set_ner_detector(Box::new(mock));
    let (result, _dets) = a.anonymize_text("Paris FRANCE is beautiful");
    // "FRANCE" should NOT be swallowed into the LOCATION span
    assert!(
        result.contains("FRANCE"),
        "LOCATION should not extend to adjacent words"
    );
}

// -- NER integration tests (feature-gated, use real detectors) --

#[cfg(feature = "ner-lite")]
#[test]
fn test_ner_lite_person_detected() {
    use crate::ner::heuristic::HeuristicNerDetector;
    let mut a = Anonymizer::new(0.0);
    a.set_ner_detector(Box::new(HeuristicNerDetector::new()));
    let (result, dets) = a.anonymize_text("Le pilote M. Dupont a décollé.");
    assert!(
        dets.iter().any(|d| d.entity_type == "PERSON"),
        "NER-lite should detect PERSON in 'M. Dupont': {:?}",
        dets
    );
    assert!(result.contains("[PERSON_"));
}

#[cfg(feature = "ner-lite")]
#[test]
fn test_ner_lite_no_person_without_detector() {
    let mut a = Anonymizer::new(0.0);
    let (_, dets) = a.anonymize_text("Le pilote M. Dupont a décollé.");
    assert!(
        !dets.iter().any(|d| d.entity_type == "PERSON"),
        "Without NER detector, PERSON should not be detected: {:?}",
        dets
    );
}

#[cfg(feature = "ner-lite")]
#[test]
fn test_ner_lite_person_in_complex_log() {
    use crate::ner::heuristic::HeuristicNerDetector;
    let mut a = Anonymizer::new(0.0);
    a.set_ner_detector(Box::new(HeuristicNerDetector::new()));
    let input = "2024-03-15 [INFO] Passager Philippe Martin a embarqué, email: phil@example.com";
    let (result, dets) = a.anonymize_text(input);
    assert!(
        dets.iter().any(|d| d.entity_type == "PERSON"),
        "PERSON should be detected alongside other PII: {:?}",
        dets
    );
    assert!(
        dets.iter().any(|d| d.entity_type == "EMAIL_ADDRESS"),
        "EMAIL should still be detected with NER active: {:?}",
        dets
    );
    assert!(result.contains("[PERSON_"));
    assert!(result.contains("[EMAIL_ADDRESS_"));
}

#[cfg(feature = "ner-lite")]
#[test]
fn test_ner_lite_standalone_alice_with_user_context() {
    use crate::ner::heuristic::HeuristicNerDetector;
    let mut a = Anonymizer::new(0.0);
    a.set_ner_detector(Box::new(HeuristicNerDetector::new()));
    // This is the benchmark complex log line - "User: Alice" should trigger PERSON
    let input = r#"2024-03-15 10:20:01 [INFO] Dumping raw socket:
Header: Auth-Token=XYZ-123
Body: User: Alice | CC: 4111
1111 1111 1111
{"metadata": "{\"source\": \"partner_api\", \"raw\": \"client%40email.com\"}"}"#;
    let (result, dets) = a.anonymize_text(input);
    assert!(
        dets.iter().any(|d| d.entity_type == "PERSON"),
        "Alice should be detected as PERSON with 'User:' context.\nDetections: {:?}\nResult: {}",
        dets,
        result
    );
}

#[cfg(feature = "ner-lite")]
#[test]
fn test_person_blocklist_amelia() {
    use crate::ner::heuristic::HeuristicNerDetector;
    let mut a = Anonymizer::new(0.0);
    a.set_ner_detector(Box::new(HeuristicNerDetector::new()));
    // "Amelia 1.0" is a product/company name, not a person
    let input = "Amelia 1.0\nDamien DUPONT\nFull-Stack Developer";
    let (result, dets) = a.anonymize_text(input);
    // Amelia should NOT be detected as PERSON
    assert!(
        !dets
            .iter()
            .any(|d| d.entity_type == "PERSON" && d.original.contains("Amelia")),
        "Amelia should be blocklisted as PERSON.\nDetections: {:?}",
        dets
    );
    assert!(result.contains("Amelia"), "Amelia should remain in output");
}

#[cfg(feature = "ner-lite")]
#[test]
fn test_person_allcaps_lastname_full_pipeline() {
    use crate::ner::heuristic::HeuristicNerDetector;
    let mut a = Anonymizer::new(0.0);
    a.set_ner_detector(Box::new(HeuristicNerDetector::new()));
    let input = "Created by Damien DUPONT 29 Jan 2026";
    let (result, dets) = a.anonymize_text(input);
    assert!(
        dets.iter()
            .any(|d| d.entity_type == "PERSON" && d.original.contains("DUPONT")),
        "Damien DUPONT should be detected as PERSON.\nDetections: {:?}\nResult: {}",
        dets,
        result
    );
    assert!(!result.contains("DUPONT"), "DUPONT should be anonymized");
    assert!(!result.contains("Damien"), "Damien should be anonymized");
}

#[cfg(feature = "ner-lite")]
#[test]
fn test_email_thread_anonymization() {
    use crate::ner::heuristic::HeuristicNerDetector;
    let mut a = Anonymizer::new(0.0);
    a.set_ner_detector(Box::new(HeuristicNerDetector::new()));
    let input = r#"--
Amelia 1.0
Sylvain Martin
Captain EMB145
Mobile : +33612345678
example-air.com"#;
    let (result, dets) = a.anonymize_text(input);
    // Sylvain Martin should be detected
    assert!(
        dets.iter()
            .any(|d| d.entity_type == "PERSON" && d.original.contains("Sylvain")),
        "Sylvain Martin should be detected.\nDetections: {:?}",
        dets
    );
    assert!(!result.contains("Sylvain"), "Sylvain should be anonymized");
    // Phone should be detected
    assert!(
        dets.iter().any(|d| d.entity_type == "FR_PHONE_NUMBER"),
        "Phone number should be detected.\nDetections: {:?}",
        dets
    );
    // Amelia should NOT be a person
    assert!(result.contains("Amelia"), "Amelia should remain in output");
}

#[cfg(feature = "ner-lite")]
#[test]
fn test_email_thread_realistic_format() {
    // Regression: real-world email threads have names repeated in headers,
    // signatures, forwarded blocks, and bare first names in greetings.
    use crate::ner::heuristic::HeuristicNerDetector;
    let mut a = Anonymizer::new(0.0);
    a.set_ner_detector(Box::new(HeuristicNerDetector::new()));
    let input = r#"Gaël FONTAINE
mar. 27 janv. 16:45
À Camille, moi

Hello @Damien DUPONT,

Pourrais-tu STP nous apporter tes lumières ?

--
Amelia 1.0
Gaël FONTAINE
DSI / CIO
example-air.com

Le mar. 27 janv. 2026 à 16:41, Camille BERNARD <cbernard@example-air.com> a écrit :
hello Gaël,

Merci d'avoir répondu à Mr DUPONT.

Amelia 1.0
Camille BERNARD
HR Director
Mobile : +33 7 00 00 00 01
example-air.com"#;
    let (result, dets) = a.anonymize_text(input);

    // Full names (first + last) should be anonymized
    assert!(
        !result.contains("FONTAINE"),
        "FONTAINE should be anonymized"
    );
    assert!(!result.contains("DUPONT"), "DUPONT should be anonymized");
    assert!(!result.contains("BERNARD"), "BERNARD should be anonymized");
    // Bare first names should also be caught by the name consistency pass
    // (they appear as part of full "Firstname LASTNAME" elsewhere in the text).
    assert!(
        !result.contains("Gaël"),
        "Bare 'Gaël' should be anonymized by consistency pass"
    );
    assert!(
        !result.contains("Camille"),
        "Bare 'Camille' should be anonymized by consistency pass"
    );

    // Email and phone should be caught
    assert!(
        !result.contains("cbernard@example-air.com"),
        "Email should be anonymized"
    );
    assert!(
        dets.iter().any(|d| d.entity_type == "FR_PHONE_NUMBER"),
        "Phone should be detected.\nDetections: {:?}",
        dets
    );

    // Amelia (company) should NOT be anonymized
    assert!(
        result.contains("Amelia"),
        "Amelia is a company name, not a person"
    );

    // Job titles in signature blocks should be anonymized
    assert!(
        !result.contains("HR Director"),
        "HR Director should be anonymized as JOB_TITLE"
    );
    assert!(
        !result.contains("DSI / CIO"),
        "DSI / CIO should be anonymized as JOB_TITLE"
    );

    assert!(
        !result.contains("FONTAINE"),
        "All FONTAINE instances should be anonymized"
    );
}

#[test]
#[cfg(feature = "ner-lite")]
fn test_name_consistency_pass_bare_first_names() {
    // When a full "Firstname LASTNAME" is detected, all bare occurrences
    // of that first name should also be anonymized.
    use crate::ner::heuristic::HeuristicNerDetector;
    let mut a = Anonymizer::new(0.0);
    a.set_ner_detector(Box::new(HeuristicNerDetector::new()));
    let input = "Pierre DUPONT a dit bonjour. Plus tard, Pierre a fait signe.";
    let (result, _dets) = a.anonymize_text(input);

    assert!(!result.contains("DUPONT"), "Full name should be anonymized");
    assert!(
        !result.contains("Pierre"),
        "Bare first name should be anonymized by consistency pass"
    );
}

// -- Ticket #35: extend person span to Title-case last names --

#[test]
fn test_extend_person_span_titlecase_lastname() {
    // "Kowalski" is Title-case, not ALL-CAPS. The span extension should still
    // include it when it immediately follows a detected first name.
    let text = "Przemysław Kowalski\n13/Jan/26, 22:33\nDear Gaël,";
    let mock = MockNerDetector {
        spans: vec![NerSpan {
            text: "Przemysław".into(),
            start: 0,
            end: "Przemysław".len(),
            score: 0.9,
            label: "PER".into(),
        }],
    };
    let mut a = Anonymizer::new(0.0);
    a.set_ner_detector(Box::new(mock));
    let (result, dets) = a.anonymize_text(text);
    assert!(
        dets.iter()
            .any(|d| d.entity_type == "PERSON" && d.original.contains("Kowalski")),
        "Span should extend to Title-case last name 'Kowalski': {:?}",
        dets
    );
    assert!(
        !result.contains("Kowalski"),
        "Title-case last name should be anonymized"
    );
}

#[test]
#[cfg(feature = "ner-lite")]
fn test_extend_person_span_titlecase_full_pipeline() {
    // Full pipeline: heuristic NER detects a known first name followed by
    // a Title-case last name. Both should be anonymized together.
    use crate::ner::heuristic::HeuristicNerDetector;
    let mut a = Anonymizer::new(0.0);
    a.set_ner_detector(Box::new(HeuristicNerDetector::new()));
    let input = "Contact: Pierre Durand for details.";
    let (result, dets) = a.anonymize_text(input);
    assert!(
        dets.iter()
            .any(|d| d.entity_type == "PERSON" && d.original.contains("Durand")),
        "Pierre Durand should be detected as a full name.\nDetections: {:?}",
        dets
    );
    assert!(
        !result.contains("Durand"),
        "Title-case last name should be anonymized"
    );
    assert!(
        !result.contains("Pierre"),
        "First name should be anonymized"
    );
}

// -- Ticket #36: accent-insensitive name consistency --

#[test]
fn test_name_consistency_accent_insensitive() {
    // When "Gaël" is detected, bare "Gael" (no accent) should also be caught.
    let text = "Gaël DUPONT a signé. Dear Gael, merci.";
    let gael_len = "Gaël".len(); // 5 bytes (ë = 2 bytes in UTF-8)
    let mock = MockNerDetector {
        spans: vec![NerSpan {
            text: "Gaël".into(),
            start: 0,
            end: gael_len,
            score: 0.9,
            label: "PER".into(),
        }],
    };
    let mut a = Anonymizer::new(0.0);
    a.set_ner_detector(Box::new(mock));
    let (result, _dets) = a.anonymize_text(text);
    assert!(
        !result.contains("Gael"),
        "Bare 'Gael' (no accent) should be anonymized when 'Gaël' was detected"
    );
}

#[test]
#[cfg(feature = "ner-lite")]
fn test_name_consistency_accent_insensitive_full_pipeline() {
    use crate::ner::heuristic::HeuristicNerDetector;
    let mut a = Anonymizer::new(0.0);
    a.set_ner_detector(Box::new(HeuristicNerDetector::new()));
    let input = "Gaël DUPONT a signé. Plus tard, Gael a confirmé.";
    let (result, _dets) = a.anonymize_text(input);
    assert!(
        !result.contains("Gael"),
        "Bare 'Gael' (no accent) should be caught by consistency pass"
    );
}

#[test]
fn test_name_consistency_accent_insensitive_preserves_surrounding_text() {
    // Verify that replacing accent-stripped names doesn't corrupt adjacent multi-byte text.
    // "Héloïse" (7 bytes in UTF-8) and "café" surround the bare name to stress byte offsets.
    let text = "Héloïse saw Gaël DUPONT at the café. Later, Gael ordered thé.";
    let gael_start = text.find("Gaël").unwrap();
    let gael_len = "Gaël".len();
    let mock = MockNerDetector {
        spans: vec![NerSpan {
            text: "Gaël".into(),
            start: gael_start,
            end: gael_start + gael_len,
            score: 0.9,
            label: "PER".into(),
        }],
    };
    let mut a = Anonymizer::new(0.0);
    a.set_ner_detector(Box::new(mock));
    let (result, _dets) = a.anonymize_text(text);
    // Bare "Gael" should be caught
    assert!(!result.contains("Gael"), "Bare 'Gael' should be anonymized");
    // Surrounding multi-byte text must be intact
    assert!(
        result.contains("Héloïse"),
        "Multi-byte text before name should be preserved: {result}"
    );
    assert!(
        result.contains("café"),
        "Multi-byte text after name should be preserved: {result}"
    );
    assert!(
        result.contains("thé"),
        "Multi-byte text at end should be preserved: {result}"
    );
}

// -- Ticket #37: last-name consistency pass --

#[test]
fn test_name_consistency_bare_last_name() {
    // When "Pierre DUPONT" is detected, bare "DUPONT" elsewhere should also be caught.
    let text = "Pierre DUPONT joined. Later, DUPONT confirmed the schedule.";
    let mock = MockNerDetector {
        spans: vec![NerSpan {
            text: "Pierre".into(),
            start: 0,
            end: 6,
            score: 0.9,
            label: "PER".into(),
        }],
    };
    let mut a = Anonymizer::new(0.0);
    a.set_ner_detector(Box::new(mock));
    let (result, _dets) = a.anonymize_text(text);
    assert!(
        !result.contains("DUPONT"),
        "Bare last name 'DUPONT' should be caught by consistency pass"
    );
}

#[test]
fn test_name_consistency_bare_titlecase_last_name() {
    // Title-case last name appearing alone after the full name was detected.
    let text = "Przemysław Kowalski joined. Later, Kowalski confirmed.";
    let mock = MockNerDetector {
        spans: vec![NerSpan {
            text: "Przemysław".into(),
            start: 0,
            end: "Przemysław".len(),
            score: 0.9,
            label: "PER".into(),
        }],
    };
    let mut a = Anonymizer::new(0.0);
    a.set_ner_detector(Box::new(mock));
    let (result, _dets) = a.anonymize_text(text);
    assert!(
        !result.contains("Kowalski"),
        "Bare last name 'Kowalski' should be caught by consistency pass"
    );
}

#[test]
fn test_name_consistency_short_last_name_skipped() {
    // Last names shorter than 3 chars should NOT be searched for bare occurrences
    // to avoid false positives (e.g., "Li", "Wu", "Ma" are too common).
    let text = "Wei Li joined the team. The Li River is beautiful.";
    let mock = MockNerDetector {
        spans: vec![NerSpan {
            text: "Wei".into(),
            start: 0,
            end: 3,
            score: 0.9,
            label: "PER".into(),
        }],
    };
    let mut a = Anonymizer::new(0.0);
    a.set_ner_detector(Box::new(mock));
    let (result, _dets) = a.anonymize_text(text);
    // "Li River" should NOT be anonymized - "Li" is too short for bare last name matching
    assert!(
        result.contains("Li River"),
        "Short last name 'Li' should not trigger bare last name consistency: result = {result}"
    );
}

// -- Ticket #38: sign-off name detection --

#[test]
fn test_signoff_name_best_regards() {
    // "Przemek" after "Best regards," should be detected even without NER
    let mut a = Anonymizer::new(0.0);
    let input = "Our team has confirmed the change.\n\nBest regards,\nPrzemek";
    let (result, dets) = a.anonymize_text(input);
    assert!(
        dets.iter()
            .any(|d| d.entity_type == "PERSON" && d.original == "Przemek"),
        "Sign-off name 'Przemek' should be detected.\nDetections: {:?}",
        dets
    );
    assert!(
        !result.contains("Przemek"),
        "Sign-off name should be anonymized"
    );
}

#[test]
fn test_signoff_name_brgds() {
    let mut a = Anonymizer::new(0.0);
    let input = "Please confirm.\n\nBrgds,\nJulia";
    let (result, dets) = a.anonymize_text(input);
    assert!(
        dets.iter()
            .any(|d| d.entity_type == "PERSON" && d.original == "Julia"),
        "Sign-off name 'Julia' should be detected.\nDetections: {:?}",
        dets
    );
    assert!(
        !result.contains("Julia"),
        "Sign-off name should be anonymized"
    );
}

#[test]
fn test_signoff_name_cordialement() {
    let mut a = Anonymizer::new(0.0);
    let input = "Merci pour votre retour.\n\nCordialement,\nDamien";
    let (result, dets) = a.anonymize_text(input);
    assert!(
        dets.iter()
            .any(|d| d.entity_type == "PERSON" && d.original == "Damien"),
        "Sign-off name 'Damien' should be detected.\nDetections: {:?}",
        dets
    );
    assert!(
        !result.contains("Damien"),
        "Sign-off name should be anonymized"
    );
}

#[test]
fn test_signoff_name_same_line() {
    // "Best regards, Przemek" on the same line
    let mut a = Anonymizer::new(0.0);
    let input = "I will revert once I receive details.\n\nBest regards, Przemek";
    let (result, _dets) = a.anonymize_text(input);
    assert!(
        !result.contains("Przemek"),
        "Sign-off name on same line should be anonymized"
    );
}

#[test]
fn test_signoff_does_not_match_blocklist() {
    // Company names in PERSON_BLOCKLIST should not be detected
    let mut a = Anonymizer::new(0.0);
    let input = "Thank you.\n\nBest regards,\nAmelia";
    let (result, dets) = a.anonymize_text(input);
    assert!(
        !dets
            .iter()
            .any(|d| d.entity_type == "PERSON" && d.original == "Amelia"),
        "Blocklisted word 'Amelia' should NOT be detected as PERSON.\nDetections: {:?}",
        dets
    );
    // Amelia is blocklisted so it should remain
    assert!(
        result.contains("Amelia"),
        "Blocklisted name should not be anonymized"
    );
}

#[test]
fn test_job_title_in_signature() {
    let mut a = Anonymizer::new(0.0);
    // Signature block with context keywords (example-air, linkedin)
    let input = "Jean DUPONT\nHR Director\nMobile : +33 6 12 34 56 78\nexample-air.com\nLinkedIn";
    let (result, dets) = a.anonymize_text(input);
    assert!(
        dets.iter().any(|d| d.entity_type == "JOB_TITLE"),
        "HR Director should be detected as JOB_TITLE.\nDetections: {:?}",
        dets
    );
    assert!(
        !result.contains("HR Director"),
        "Job title should be replaced"
    );
}

#[test]
fn test_job_title_csuite_in_signature() {
    let mut a = Anonymizer::new(0.0);
    let input = "Jean DUPONT\nDSI / CIO\nexample-air.com\nLinkedIn";
    let (result, dets) = a.anonymize_text(input);
    assert!(
        dets.iter().any(|d| d.entity_type == "JOB_TITLE"),
        "DSI / CIO should be detected as JOB_TITLE.\nDetections: {:?}",
        dets
    );
    assert!(
        !result.contains("DSI / CIO"),
        "C-suite title should be replaced"
    );
}

#[test]
fn test_job_title_not_in_prose() {
    let mut a = Anonymizer::new(0.0);
    // Without signature context keywords, titles should NOT match
    let input = "The HR Director asked about the report.";
    let (_result, dets) = a.anonymize_text(input);
    assert!(
        !dets.iter().any(|d| d.entity_type == "JOB_TITLE"),
        "JOB_TITLE should not match in regular prose without context.\nDetections: {:?}",
        dets
    );
}
