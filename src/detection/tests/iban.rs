use super::super::*;

#[test]
fn test_fr_iban() {
    let mut a = Anonymizer::new(0.0);
    let (result, dets) = a.anonymize_text("IBAN: FR14 2004 1010 0505 0001 3M02 606");
    assert!(
        dets.iter().any(|d| d.entity_type == "FR_IBAN"),
        "canonical French IBAN not detected: {dets:?}"
    );
    assert!(result.contains("[FR_IBAN_"));
}

#[test]
fn test_fr_iban_compact() {
    for iban in ["FR1420041010050500013M02606", "FR7630006000011234567890189"] {
        let mut a = Anonymizer::new(0.0);
        let (result, dets) = a.anonymize_text(&format!("IBAN: {iban}"));
        assert!(
            dets.iter().any(|d| d.entity_type == "FR_IBAN"),
            "valid French IBAN rejected: {iban}; detections: {dets:?}"
        );
        assert!(result.contains("[FR_IBAN_"));
    }
}

#[test]
fn test_fr_iban_invalid_checksums_rejected() {
    for iban in [
        "FR7612345678901234567890123",
        "FR1520041010050500013M02606",
        "FR1420041010050500013M02607",
        "FR1420041010050500013N02606",
    ] {
        let mut a = Anonymizer::new(0.0);
        let (_, dets) = a.anonymize_text(&format!("IBAN: {iban}"));
        assert!(
            !dets
                .iter()
                .any(|d| matches!(d.entity_type.as_ref(), "FR_IBAN" | "IBAN_CODE")),
            "invalid French IBAN accepted: {iban}; detections: {dets:?}"
        );
    }
}

#[test]
fn test_fr_iban_url_inner_checksum_validation() {
    let mut valid = Anonymizer::new(0.0);
    let (_, valid_dets) =
        valid.anonymize_text("visit https://example.com/pay?iban=FR1420041010050500013%4D02606");
    assert!(
        valid_dets.iter().any(|d| d.entity_type == "FR_IBAN"),
        "valid URL-encoded French IBAN not reported: {valid_dets:?}"
    );

    let mut invalid = Anonymizer::new(0.0);
    let (_, invalid_dets) =
        invalid.anonymize_text("visit https://example.com/pay?iban=FR1520041010050500013%4D02606");
    assert!(
        !invalid_dets
            .iter()
            .any(|d| matches!(d.entity_type.as_ref(), "FR_IBAN" | "IBAN_CODE")),
        "invalid URL-encoded French IBAN reported: {invalid_dets:?}"
    );
}

#[test]
fn test_fr_iban_roundtrip_preserves_alphanumeric_account() {
    let mut a = Anonymizer::new(0.0);
    let input = "virement sur IBAN FR14 2004 1010 0505 0001 3M02 606";
    let (anon, dets) = a.anonymize_text(input);
    assert!(dets.iter().any(|d| {
        d.entity_type == "FR_IBAN" && d.original == "FR14 2004 1010 0505 0001 3M02 606"
    }));
    assert_eq!(a.mapping.restore(&anon), input);
}

// -- Generic IBAN tests --

#[test]
fn test_iban_german() {
    let mut a = Anonymizer::new(0.0);
    // DE89 3704 0044 0532 0130 00 - valid mod-97
    let (result, dets) = a.anonymize_text("iban DE89 3704 0044 0532 0130 00");
    assert!(
        dets.iter().any(|d| d.entity_type == "IBAN_CODE"),
        "German IBAN not detected: {dets:?}"
    );
    assert!(result.contains("[IBAN_CODE_"));
}

#[test]
fn test_iban_british() {
    let mut a = Anonymizer::new(0.0);
    // GB29 NWBK 6016 1331 9268 19 - valid mod-97
    let (result, dets) = a.anonymize_text("account GB29NWBK60161331926819");
    assert!(
        dets.iter().any(|d| d.entity_type == "IBAN_CODE"),
        "British IBAN not detected: {dets:?}"
    );
    assert!(result.contains("[IBAN_CODE_"));
}

#[test]
fn test_uk_iban_compact_without_context_exact_spans_and_roundtrip() {
    for iban in [
        "GB82WEST12345698765432",
        "GB29NWBK60161331926819",
        "gb82west12345698765432",
        "gb29nwbk60161331926819",
        "gB82WeSt12345698765432",
        "Gb29NwBk60161331926819",
    ] {
        for prefix in ["value=", "Échec 🧪 — value="] {
            for suffix in ["", "; please investigate.", " HELP", " 1234 AB12"] {
                assert_iban_exact_roundtrip(iban, "IBAN_CODE", prefix, suffix);
            }
        }
    }
}

#[test]
fn test_uk_iban_compact_keeps_score_and_strict_threshold_with_context() {
    for prefix in ["value=", "IBAN "] {
        let input = format!("{prefix}GB82WEST12345698765432");
        let mut anonymizer = Anonymizer::new(0.7);
        anonymizer.context_boost = 1.0;
        let (_, detections) = anonymizer.anonymize_text(&input);
        assert_eq!(detections.len(), 1, "{input}; {detections:?}");
        assert_eq!(detections[0].entity_type, "IBAN_CODE");
        assert_eq!(
            detections[0].score, 0.7,
            "context must not inflate the score"
        );

        let mut strict = Anonymizer::new(0.8);
        strict.context_boost = 1.0;
        let (output, detections) = strict.anonymize_text(&input);
        assert_eq!(output, input);
        assert!(detections.is_empty(), "{input}; {detections:?}");
        assert!(strict.mapping.mappings.is_empty());
    }
}

#[test]
fn test_uk_iban_compact_rejects_checksum_valid_structural_impostors() {
    // These fictional values all pass mod-97. A checksum alone cannot justify
    // recognizing an unsupported country, wrong fields, or invalid check digits.
    for iban in [
        "ZZ33WEST12345698765432", // unsupported country
        "GB88WEST1234569876543",  // wrong GB length
        "GB93WES112345698765432", // digit in the four-letter bank code
        "GB00TEST00000000000090", // check digits below 02
        "GB01TEST00000000000072",
        "GB99TEST00000000000054", // check digits above 98
    ] {
        assert!(
            crate::patterns::iban_mod97(iban),
            "fixture checksum: {iban}"
        );
        assert_no_iban_detection(&format!("value={iban}"));
    }
}

#[test]
fn test_uk_iban_compact_rejects_bad_checksums_and_embedded_values() {
    for value in [
        "GB83WEST12345698765432",
        "GB82WEST12345698765433",
        "xGB82WEST12345698765432",
        "éGB82WEST12345698765432",
        "_GB82WEST12345698765432",
        "GB82WEST12345698765432_foo",
        "GB82WEST12345698765432abc",
        "GB82WEST12345698765432é",
        "GB82WEST123456987654321",
        "GB82WEST1234569876543",
    ] {
        assert_no_iban_detection(&format!("value={value}"));
    }
}

#[test]
fn test_uk_iban_grouped_uppercase_still_requires_context() {
    for iban in ["GB82 WEST 1234 5698 7654 32", "GB29 NWBK 6016 1331 9268 19"] {
        assert_no_iban_detection(&format!("value={iban}"));
        assert_iban_exact_roundtrip(iban, "IBAN_CODE", "IBAN ", "");
    }
}

#[test]
fn test_uk_iban_print_ascii_casing_exact_spans_and_roundtrip() {
    for (iban, prefix, suffix) in [
        ("gb82 west 1234 5698 7654 32", "Échec 🧪 — IBAN ", ""),
        ("gB82 WeSt 1234 5698 7654 32", "Échec 🧪 — IBAN ", " help"),
        (
            "gb29 nwbk 6016 1331 9268 19",
            "account ",
            "; please investigate.",
        ),
        ("Gb29 NwBk 6016 1331 9268 19", "account ", " HELP"),
        (
            "GB82 WEST 1234 5698 7654 32",
            "Échec 🧪 — IBAN ",
            "; please investigate.",
        ),
        ("GB29 NWBK 6016 1331 9268 19", "account ", " HELP"),
        ("gb82\twest\t1234\t5698\t7654\t32", "account ", " HELP"),
        (
            "gB82\tWeSt\t1234\t5698\t7654\t32",
            "Échec 🧪 — IBAN ",
            " help",
        ),
        (
            "gb29\tnwbk\t6016\t1331\t9268\t19",
            "Échec 🧪 — IBAN ",
            "; please investigate.",
        ),
        ("Gb29\tNwBk\t6016\t1331\t9268\t19", "account ", ""),
        ("GB82\tWEST\t1234\t5698\t7654\t32", "Échec 🧪 — IBAN ", ""),
        ("GB29\tNWBK\t6016\t1331\t9268\t19", "account ", " help"),
    ] {
        assert_iban_exact_roundtrip(iban, "IBAN_CODE", prefix, suffix);
    }
}

#[test]
fn test_uk_iban_print_keeps_context_gate_score_and_threshold() {
    for iban in [
        "gb82 west 1234 5698 7654 32",
        "gB29\tNwBk\t6016\t1331\t9268\t19",
    ] {
        assert_no_iban_detection(&format!("value={iban}"));

        let input = format!("IBAN {iban}");
        let mut anonymizer = Anonymizer::new(0.7);
        anonymizer.context_boost = 1.0;
        let (_, detections) = anonymizer.anonymize_text(&input);
        assert_eq!(detections.len(), 1, "{input}; {detections:?}");
        assert_eq!(detections[0].entity_type, "IBAN_CODE");
        assert_eq!(
            detections[0].score, 0.7,
            "context must not inflate the score"
        );

        let mut strict = Anonymizer::new(0.8);
        strict.context_boost = 1.0;
        let (output, detections) = strict.anonymize_text(&input);
        assert_eq!(output, input);
        assert!(detections.is_empty(), "{input}; {detections:?}");
        assert!(strict.mapping.mappings.is_empty());
    }
}

#[test]
fn test_uk_iban_print_cannot_supply_its_own_context() {
    for iban in [
        "gb69 bank 1234 5698 7654 32",
        "gb86 bica 1234 5698 7654 32",
        "gB69\tBaNk\t1234\t5698\t7654\t32",
    ] {
        assert!(
            crate::patterns::iban_mod97(iban),
            "fixture checksum: {iban}"
        );
        let input = format!("Échec 🧪 — value={iban}");
        let mut anonymizer = Anonymizer::new(0.5);
        let (output, detections) = anonymizer.anonymize_text(&input);
        assert_eq!(output, input, "bank letters must not supply context");
        assert!(detections.is_empty(), "{input}; {detections:?}");
        assert!(anonymizer.mapping.mappings.is_empty());
    }
}

#[test]
fn test_uk_iban_print_accepts_external_financial_context() {
    for (iban, prefix, suffix) in [
        (
            "gb69 bank 1234 5698 7654 32",
            "Échec 🧪 — bank ",
            "; review.",
        ),
        (
            "gb86 bica 1234 5698 7654 32",
            "Échec 🧪 — bic ",
            "; review.",
        ),
        ("gb69 bank 1234 5698 7654 32", "IBAN ", ""),
        ("gb86 bica 1234 5698 7654 32", "account ", ""),
        ("gB69\tBaNk\t1234\t5698\t7654\t32", "value=", "; bank"),
        ("gb86 bica 1234 5698 7654 32", "value=", "; bic"),
    ] {
        assert_iban_exact_roundtrip(iban, "IBAN_CODE", prefix, suffix);
    }

    // The header is outside the nearby 80-character window but aligned with
    // the value's column, which remains a supported source of context.
    let prefix = format!("IBAN\n{}\n", "-".repeat(100));
    assert_iban_exact_roundtrip(
        "gb69 bank 1234 5698 7654 32",
        "IBAN_CODE",
        &prefix,
        "; review.",
    );
}

#[test]
fn test_uk_iban_print_custom_url_audit_context_excludes_the_encoded_value() {
    let selected = vec!["IBAN_CODE".to_string()];
    // The default URL regex stops at normalized spaces. A custom recognizer
    // that includes them exercises URL-inner auditing of grouped values.
    let config = crate::config::RecognizerConfigFile::from_yaml(
        r#"
recognizers:
  - name: complete_query_url
    entity_type: URL
    patterns:
      - regex: 'https://example\.invalid/\?[^\r\n]+'
        score: 1.0
"#,
    )
    .unwrap();
    for iban in ["gb69 bank 1234 5698 7654 32", "gb86 bica 1234 5698 7654 32"] {
        let encoded = iban.replace(' ', "%20");
        for (key, expected_count) in [("value", 0), ("account", 1)] {
            let input = format!("Échec 🧪 — https://example.invalid/?{key}={encoded}");
            let mut anonymizer = Anonymizer::new(0.5);
            anonymizer.add_custom_patterns(&config);
            // Unfiltered analysis exercises the URL-inner audit path; selecting
            // IBAN_CODE alone exercises the main normalized-text matcher.
            for entities in [None, Some(selected.as_slice())] {
                let detections = anonymizer.analyze_with_entities(&input, entities);
                let ibans: Vec<_> = detections
                    .iter()
                    .filter(|d| d.entity_type == "IBAN_CODE")
                    .collect();
                assert_eq!(ibans.len(), expected_count, "{input}; {detections:?}");
                assert_eq!(
                    detections.iter().filter(|d| d.entity_type == "URL").count(),
                    usize::from(entities.is_none()),
                );
                if let Some(url) = detections.iter().find(|d| d.entity_type == "URL") {
                    assert_eq!(url.start, input.find("https://").unwrap());
                    assert_eq!(url.end, input.len());
                }
                if let Some(detection) = ibans.first() {
                    let start = input.find(&encoded).unwrap();
                    assert_eq!(detection.original, encoded);
                    assert_eq!(
                        (detection.start, detection.end),
                        (start, start + encoded.len())
                    );
                    assert_eq!(detection.score, 0.7);
                }
                assert!(anonymizer.mapping.mappings.is_empty());
            }
        }
    }
}

#[test]
fn test_uk_iban_print_context_guard_preserves_generic_matching() {
    // The existing broad uppercase recognizer retains its inclusive context
    // behavior; only the separate UK print rule excludes its own match.
    for iban in ["GB69 BANK 1234 5698 7654 32", "GB86 BICA 1234 5698 7654 32"] {
        assert_iban_exact_roundtrip(iban, "IBAN_CODE", "value=", "");
    }
}

#[test]
fn test_uk_iban_print_context_guard_preserves_custom_name_collisions() {
    for (entity_type, regex) in [
        ("IBAN_CODE", "gb69 bank 1234 5698 7654 32"),
        ("CUSTOM_IBAN", crate::patterns::UK_IBAN_PRINT_PATTERN),
    ] {
        let yaml = format!(
            "recognizers:\n  - name: uk_iban_print\n    entity_type: {entity_type}\n    patterns:\n      - regex: '{regex}'\n        score: 0.7\n    context_keywords: [bank]\n    context_required: true\n"
        );
        let config = crate::config::RecognizerConfigFile::from_yaml(&yaml).unwrap();
        let mut anonymizer = Anonymizer::new(0.5);
        anonymizer.add_custom_patterns(&config);
        let input = "value=gb69 bank 1234 5698 7654 32";
        let (output, detections) = anonymizer.anonymize_text(input);
        assert_eq!(detections.len(), 1, "{entity_type}; {detections:?}");
        assert_eq!(detections[0].entity_type, entity_type);
        assert_eq!(detections[0].original, "gb69 bank 1234 5698 7654 32");
        assert_eq!((detections[0].start, detections[0].end), (6, input.len()));
        assert!(output.starts_with(&format!("value=[{entity_type}_")));
        assert_eq!(anonymizer.mapping.restore_bracketed(&output), input);
    }
}

#[test]
fn test_uk_iban_print_rejects_checksum_valid_structural_impostors() {
    // Lowercase print fields exercise the new rule, not the pre-existing broad
    // uppercase matcher. Each fictional malformed value still passes mod-97.
    for iban in [
        "zz33 west 1234 5698 7654 32", // unsupported country
        "gb88 west 1234 5698 7654 3",  // wrong GB length
        "gB93 WeS1 1234 5698 7654 32", // digit in the four-letter bank code
        "gb00 test 0000 0000 0000 90", // check digits outside 02-98
        "gb01 test 0000 0000 0000 72",
        "gb99 test 0000 0000 0000 54",
        "gb82 west 12345 6987 6543 2", // valid compact value, wrong print groups
    ] {
        assert!(
            crate::patterns::iban_mod97(iban),
            "fixture checksum: {iban}"
        );
        assert_no_iban_detection(&format!("IBAN {iban}"));
    }
}

#[test]
fn test_uk_iban_print_rejects_bad_checksums_and_embedded_values() {
    for value in [
        "gb83 west 1234 5698 7654 32",
        "gB82 WeSt 1234 5698 7654 33",
        "xgb82 west 1234 5698 7654 32",
        "égb82 west 1234 5698 7654 32",
        "_gb82 west 1234 5698 7654 32",
        "gb82 west 1234 5698 7654 32_foo",
        "gb82 west 1234 5698 7654 32abc",
        "gb82 west 1234 5698 7654 32é",
        "gb82 west 1234 5698 7654 321",
        "gb82 west 1234 5698 7654 3",
        "gb82 weßt 1234 5698 7654 32",
        "gb82 west1234 5698 7654 32", // missing group separator
        "gb82 west 12345698 7654 32",
    ] {
        assert_no_iban_detection(&format!("IBAN {value}"));
    }
}

#[test]
fn test_uk_iban_print_does_not_join_lowercase_or_mixed_groups_across_lines() {
    for iban in [
        "gb82 west 1234\n5698 7654 32",
        "gB29\tNwBk\t6016\r\n 1331\t9268\t19",
        "gb82 we\nst 1234 5698 7654 32", // split inside a field
    ] {
        assert_no_iban_detection(&format!("IBAN {iban}"));
        assert_no_iban_detection(&format!("value={iban}"));
    }
}

#[test]
fn test_iban_spanish() {
    let mut a = Anonymizer::new(0.0);
    // ES91 2100 0418 4502 0005 1332 - valid mod-97
    let (result, dets) = a.anonymize_text("virement ES91 2100 0418 4502 0005 1332");
    assert!(
        dets.iter().any(|d| d.entity_type == "IBAN_CODE"),
        "Spanish IBAN not detected: {dets:?}"
    );
    assert!(result.contains("[IBAN_CODE_"));
}

#[test]
fn test_iban_invalid_checksum_rejected() {
    let mut a = Anonymizer::new(0.0);
    // DE00 3704 0044 0532 0130 00 - invalid check digits
    let (_, dets) = a.anonymize_text("iban DE00 3704 0044 0532 0130 00");
    assert!(
        !dets.iter().any(|d| d.entity_type == "IBAN_CODE"),
        "IBAN with invalid checksum should be rejected: {dets:?}"
    );
}

#[test]
fn test_iban_context_required() {
    let mut a = Anonymizer::new(0.0);
    // Valid IBAN but no context keyword - should be rejected
    let (_, dets) = a.anonymize_text("code DE89370400440532013000 here");
    assert!(
        !dets.iter().any(|d| d.entity_type == "IBAN_CODE"),
        "IBAN without context should be rejected: {dets:?}"
    );
}

#[test]
fn test_iban_fr_stays_fr_iban() {
    // French IBANs should still be detected as FR_IBAN (higher confidence)
    let mut a = Anonymizer::new(0.0);
    let (result, dets) = a.anonymize_text("IBAN: FR14 2004 1010 0505 0001 3M02 606");
    assert!(
        dets.iter().any(|d| d.entity_type == "FR_IBAN"),
        "French IBAN should stay FR_IBAN: {dets:?}"
    );
    assert!(result.contains("[FR_IBAN_"));
}

// -- IBAN_CODE (generic) battle tests --

#[test]
fn test_iban_dutch() {
    let mut a = Anonymizer::new(0.0);
    // NL91 ABNA 0417 1643 00 - valid mod-97
    let (result, dets) = a.anonymize_text("bank account NL91ABNA0417164300");
    assert!(
        dets.iter().any(|d| d.entity_type == "IBAN_CODE"),
        "Dutch IBAN not detected: {dets:?}"
    );
    assert!(result.contains("[IBAN_CODE_"));
}

#[test]
fn test_iban_belgian() {
    let mut a = Anonymizer::new(0.0);
    // BE68 5390 0754 7034 - valid mod-97
    let (result, dets) = a.anonymize_text("iban: BE68539007547034");
    assert!(
        dets.iter().any(|d| d.entity_type == "IBAN_CODE"),
        "Belgian IBAN not detected: {dets:?}"
    );
    assert!(result.contains("[IBAN_CODE_"));
}

#[test]
fn test_iban_swiss() {
    let mut a = Anonymizer::new(0.0);
    // CH93 0076 2011 6238 5295 7 - valid mod-97
    let (result, dets) = a.anonymize_text("swift transfer CH9300762011623852957");
    assert!(
        dets.iter().any(|d| d.entity_type == "IBAN_CODE"),
        "Swiss IBAN not detected: {dets:?}"
    );
    assert!(result.contains("[IBAN_CODE_"));
}

#[test]
fn test_iban_with_spaces() {
    let mut a = Anonymizer::new(0.0);
    // Same German IBAN but with standard 4-char groups
    let (result, dets) = a.anonymize_text("payment DE89 3704 0044 0532 0130 00");
    assert!(
        dets.iter().any(|d| d.entity_type == "IBAN_CODE"),
        "spaced IBAN not detected: {dets:?}"
    );
    assert!(result.contains("[IBAN_CODE_"));
}

#[test]
fn test_iban_off_by_one_checksum_rejected() {
    let mut a = Anonymizer::new(0.0);
    // DE90 instead of DE89 - should fail mod-97
    let (_, dets) = a.anonymize_text("iban DE90370400440532013000");
    assert!(
        !dets.iter().any(|d| d.entity_type == "IBAN_CODE"),
        "IBAN with wrong check digits should be rejected: {dets:?}"
    );
}

#[test]
fn test_iban_compact_ascii_casing_exact_spans_and_roundtrip() {
    for iban in [
        "gb82west12345698765432",
        "gB82WeSt12345698765432",
        "GB82west12345698765432",
        "gb82WEST12345698765432",
        "de89370400440532013000",
        "nL91AbNa0417164300",
        "be68539007547034",
        "cH9300762011623852957",
    ] {
        for suffix in [
            "",
            " please investigate.",
            " help",
            " bank",
            " 1234 AB12",
            " abcd1234",
        ] {
            assert_iban_exact_roundtrip(iban, "IBAN_CODE", "Échec — IBAN ", suffix);
        }
    }
}

fn assert_iban_exact_roundtrip(iban: &str, entity_type: &str, prefix: &str, suffix: &str) {
    let mut anonymizer = Anonymizer::new(0.5);
    let input = format!("{prefix}{iban}{suffix}");
    let (output, detections) = anonymizer.anonymize_text(&input);
    assert_eq!(
        detections.len(),
        1,
        "expected one complete IBAN: {input}; {detections:?}"
    );
    let detection = &detections[0];
    assert_eq!(detection.entity_type, entity_type, "{input}");
    if entity_type == "IBAN_CODE" {
        assert_eq!(detection.score, 0.7, "{input}");
    }
    assert_eq!(detection.original, iban, "{input}");
    assert_eq!(detection.start, prefix.len(), "{input}");
    assert_eq!(detection.end, prefix.len() + iban.len(), "{input}");
    assert!(
        output.starts_with(&format!("{prefix}[{entity_type}_")),
        "{output}"
    );
    assert!(output.ends_with(&format!("]{suffix}")), "{output}");
    assert_eq!(anonymizer.mapping.restore_bracketed(&output), input);
}

#[test]
fn test_fr_iban_ascii_casing_keeps_priority_and_exact_source() {
    for iban in [
        "fr1420041010050500013m02606",
        "Fr1420041010050500013m02606",
        "fR1420041010050500013M02606",
        "fr14 2004 1010 0505 0001 3m02 606",
        "Fr14 2004 1010 0505 0001 3M02 606",
        "fR14\t2004\t1010\t0505\t0001\t3m02\t606",
    ] {
        for prefix in ["Échec — IBAN ", "Échec — "] {
            assert_iban_exact_roundtrip(iban, "FR_IBAN", prefix, " please investigate.");
        }
    }
}

#[test]
fn test_iban_ascii_casing_keeps_checksum_and_context_gates() {
    for input in [
        "IBAN gb83west12345698765432", // wrong check digits
        "IBAN gB82WeSt12345698765433", // modified account
        "IBAN de90370400440532013000",
        "IBAN fr1520041010050500013m02606",
        "IBAN fr14 2004 1010 0505 0001 3m02 607",
        "code de89370400440532013000 here", // non-UK generic context is still required
        "code nL91AbNa0417164300 here",
    ] {
        assert_no_iban_detection(input);
    }
    let mut strict = Anonymizer::new(0.8);
    let (_, detections) = strict.anonymize_text("IBAN gb82west12345698765432");
    assert!(!detections.iter().any(|d| d.entity_type == "IBAN_CODE"));
}

#[test]
fn test_iban_ascii_casing_rejects_embedded_or_extended_candidates() {
    for input in [
        "IBAN xgb82west12345698765432", // embedded within a larger word
        "IBAN _gb82west12345698765432",
        "IBAN gb82west12345698765432_foo",
        "IBAN gb82west123456987654321", // valid prefix, invalid full checksum
        "IBAN gB82WeSt12345698765432abc",
        "IBAN gb82west12345698765432abcdefghijklmnop", // beyond compact length limit
        "IBAN fr1420041010050500013m026061",
        "IBAN fr14 2004 1010 0505 0001 3m02 6061",
        "IBAN gb82weßt12345698765432", // non-ASCII letters are not case-folded
        "IBAN gb82weİt12345698765432",
    ] {
        assert_no_iban_detection(input);
    }
}

#[test]
fn test_generic_grouped_lowercase_is_not_rescued_by_shorter_prefixes() {
    // Generic mixed/lowercase support is deliberately compact-only. In
    // particular, never trim a failed candidate until its checksum happens to
    // pass. French and UK fixed print formats are covered separately above.
    for input in [
        "value=gb82 west 1234 5698 7654 32",
        "IBAN de89 3704 0044 0532 0130 00",
        "IBAN nL91 AbNa 0417 1643 00 help",
        "IBAN ch93 0076 2011 6238 5295 7 please investigate",
        "IBAN gb83 west 1234 5698 7654 32 bank",
    ] {
        assert_no_iban_detection(input);
    }
}

fn assert_no_iban_detection(input: &str) {
    let mut anonymizer = Anonymizer::new(0.0);
    let (_, detections) = anonymizer.anonymize_text(input);
    assert!(
        !detections
            .iter()
            .any(|d| matches!(d.entity_type.as_ref(), "FR_IBAN" | "IBAN_CODE")),
        "unexpected IBAN detection: {input}; {detections:?}"
    );
}

#[test]
fn test_iban_too_short_rejected() {
    let mut a = Anonymizer::new(0.0);
    // 4 check + only 6 BBAN chars = too short
    let (_, dets) = a.anonymize_text("iban XX12ABCDEF");
    assert!(
        !dets.iter().any(|d| d.entity_type == "IBAN_CODE"),
        "too-short IBAN should not match: {dets:?}"
    );
}

#[test]
fn test_iban_roundtrip() {
    let mut a = Anonymizer::new(0.0);
    let input = "virement sur le compte iban DE89370400440532013000";
    let (anon, _) = a.anonymize_text(input);
    let restored = a.mapping.restore(&anon);
    assert_eq!(restored, input, "IBAN roundtrip should restore original");
}
