use super::super::*;

#[test]
fn test_email() {
    let mut a = Anonymizer::new(0.0);
    let (result, dets) = a.anonymize_text("contact john@example.com now");
    assert_eq!(dets.len(), 1);
    assert_eq!(dets[0].entity_type, "EMAIL_ADDRESS");
    assert!(result.contains("[EMAIL_ADDRESS_"));
}

#[test]
fn wrapped_email_preserves_exact_source_span_and_roundtrip() {
    for address in [
        "ada@\nexample.com",
        "iñes@\r\nexample.org",
        "dev+alerts@\n \tmail.example.org",
        "Ada@\r\n\tEXAMPLE.COM",
        "ada@\nexample-domain.com",
        "ａｄａ＠\nｅｘａｍｐｌｅ．ｃｏｍ",
        r"ada%40%0D%0A%09example.com",
        r"ada\u0040\u000Aexample.com",
    ] {
        let prefix = "Réponse 😀 — contact ";
        let suffix = "; please investigate.\n";
        let input = format!("{prefix}{address}{suffix}");
        let mut a = Anonymizer::new(0.5);
        let (prepared, dets) = a.anonymize_text(&input);
        assert_eq!(dets.len(), 1, "{address:?}: {dets:?}");
        let det = &dets[0];
        assert_eq!(det.entity_type, "EMAIL_ADDRESS");
        assert_eq!(det.original, address);
        assert_eq!(
            (det.start, det.end),
            (prefix.len(), prefix.len() + address.len())
        );
        let token = &prepared[prefix.len()..prepared.len() - suffix.len()];
        assert!(token.starts_with("[EMAIL_ADDRESS_") && token.ends_with(']'));
        assert_eq!(prepared, format!("{prefix}{token}{suffix}"));
        assert_eq!(a.mapping.restore_bracketed(&prepared), input);
    }
}

#[test]
fn wrapped_email_does_not_join_blank_lines_or_partial_domains() {
    for input in [
        "ada@\n\nexample.com",
        "ada@\r\n \r\nexample.com",
        "ada@\rexample.com",
        "ada@ \nexample.com",
        "ada@ example.com",
        "ada@\nexample",
        "ada\n@example.com",
        "ada@\nexample.\ncom",
        "ada@\n.example.com",
        "ada@\nexample..com",
        "ada@\n-example.com",
        "ada@\nexample-.com",
        "ada@\nexample.com2",
        "ada@\nexample.com_extra",
        "ada@\nexample.com-suffix",
        "ada@\nexample.com.123",
        "ada@\nexample.comé",
        "ada@\nexample.com\u{301}",
    ] {
        let mut a = Anonymizer::new(0.5);
        let (prepared, dets) = a.anonymize_text(input);
        assert!(dets.is_empty(), "{input:?}: {dets:?}");
        assert_eq!(prepared, input);
    }
}

#[test]
fn wrapped_email_keeps_independent_second_line_addresses_complete() {
    for address in [
        "bob.smith@example.com",
        "bob.smith+tag@example.com",
        "bob.smith%tag@example.com",
        "bob.smith_1@example.com",
        "bob.smithé@example.com",
    ] {
        let input = format!("ada@\n{address}");
        let mut a = Anonymizer::new(0.5);
        let (prepared, dets) = a.anonymize_text(&input);
        assert_eq!(dets.len(), 1, "{input:?}: {dets:?}");
        assert_eq!(dets[0].original, address);
        assert_eq!((dets[0].start, dets[0].end), (5, input.len()));
        assert!(prepared.starts_with("ada@\n[EMAIL_ADDRESS_"));
        assert_eq!(a.mapping.restore_bracketed(&prepared), input);
    }
}

#[test]
fn wrapped_email_keeps_sentence_punctuation_and_the_email_threshold() {
    for suffix in [".", "...", "). Next line", ", please investigate"] {
        let address = "ada@\nexample.com";
        let input = format!("{address}{suffix}");
        let mut a = Anonymizer::new(0.9);
        let (prepared, dets) = a.anonymize_text(&input);
        assert_eq!(dets.len(), 1);
        assert_eq!(dets[0].original, address);
        assert_eq!(dets[0].score, 0.9);
        assert!(prepared.ends_with(suffix));
        assert_eq!(a.mapping.restore_bracketed(&prepared), input);

        let (prepared, dets) = Anonymizer::new(0.91).anonymize_text(&input);
        assert!(dets.is_empty());
        assert_eq!(prepared, input);
    }
}

#[test]
fn wrapped_email_reconsiders_a_rejected_candidates_domain_line() {
    for (prefix, address) in [
        ("ada@\n", "bob.smith@\nexample.com"),
        ("Préfixe 😀 ada@\r\n \t", "iñes.smith@\r\n\texample.com"),
        ("ada@\nbob.smith@\n", "dev.alerts@\nexample.org"),
    ] {
        let input = format!("{prefix}{address}");
        let mut a = Anonymizer::new(0.5);
        let (prepared, dets) = a.anonymize_text(&input);
        assert_eq!(dets.len(), 1, "{input:?}: {dets:?}");
        assert_eq!(dets[0].original, address);
        assert_eq!((dets[0].start, dets[0].end), (prefix.len(), input.len()));
        assert!(prepared.starts_with(&format!("{prefix}[EMAIL_ADDRESS_")));
        assert_eq!(a.mapping.restore_bracketed(&prepared), input);
    }
}

#[test]
fn wrapped_email_restores_format_specific_source_bytes() {
    let mut a = Anonymizer::new(0.5);
    let csv = "id,contact\r\n1,\"Préfixe 😀 ada@\r\n\texample.com\"\r\n";
    let (prepared, dets) = a.anonymize_csv(csv);
    assert_eq!(dets.len(), 1);
    assert_eq!(dets[0].original, "ada@\r\n\texample.com");
    assert_eq!(a.mapping.restore_bracketed(&prepared), csv);

    let mut a = Anonymizer::new(0.5);
    let sql = "INSERT INTO tickets VALUES ('Préfixe 😀 ada@\r\n\texample.com');";
    let (prepared, dets) = a.anonymize_sql(sql);
    assert_eq!(dets.len(), 1);
    assert_eq!(dets[0].original, "ada@\r\n\texample.com");
    assert_eq!(a.mapping.restore_bracketed(&prepared), sql);

    let mut a = Anonymizer::new(0.5);
    let input = serde_json::json!({"contact": "Préfixe 😀 ada@\r\n\texample.com", "count": 1});
    let (prepared, dets) = a.anonymize_json_value(&input);
    assert_eq!(dets.len(), 1);
    assert_eq!(dets[0].original, "ada@\r\n\texample.com");
    assert_eq!(prepared["count"], input["count"]);
    assert_eq!(
        a.mapping
            .restore_bracketed(prepared["contact"].as_str().unwrap()),
        input["contact"].as_str().unwrap()
    );
}

#[test]
fn test_unicode_local_part_is_detected_as_one_complete_email() {
    let mut a = Anonymizer::new(0.0);
    let input = "Email iñes@example.com";
    let (result, dets) = a.anonymize_text(input);

    assert_eq!(dets.len(), 1);
    assert_eq!(dets[0].entity_type, "EMAIL_ADDRESS");
    assert_eq!(dets[0].original, "iñes@example.com");
    assert_eq!((dets[0].start, dets[0].end), (6, input.len()));
    assert_eq!(a.mapping.restore_bracketed(&result), input);
}

#[test]
fn test_utf8_email_in_accented_text() {
    let mut a = Anonymizer::new(0.0);
    let input = "Heloise a envoye un mail a heloise@example.com depuis Zurich";
    let (result, _) = a.anonymize_text(input);
    assert!(result.contains("[EMAIL_ADDRESS_"));
    // Verify the surrounding accented text is preserved
    assert!(result.contains("Heloise"));
    assert!(result.contains("Zurich"));
}

#[test]
fn test_unicode_fullwidth_email_detected() {
    let mut a = Anonymizer::new(0.0);
    // Fullwidth '@' (U+FF20) should be NFKC-normalized to ASCII '@'
    let input = "contact user\u{FF20}example.com now";
    let (result, dets) = a.anonymize_text(input);
    assert!(
        dets.iter().any(|d| d.entity_type == "EMAIL_ADDRESS"),
        "Fullwidth @ should be normalized and detected as email"
    );
    assert!(result.contains("[EMAIL_ADDRESS_"));
}

#[test]
fn test_unicode_normalization_preserves_ascii() {
    let mut a = Anonymizer::new(0.0);
    // Pure ASCII input should be unchanged by NFKC
    let (result, dets) = a.anonymize_text("contact john@example.com now");
    assert_eq!(dets.len(), 1);
    assert!(result.contains("[EMAIL_ADDRESS_"));
}

#[test]
fn test_unicode_escape_email_detected() {
    let mut a = Anonymizer::new(0.0);
    // \u0040 is @ - should be decoded and detected as email
    let (result, dets) = a.anonymize_text(r"client\u0040company.com requested refund");
    assert!(
        dets.iter().any(|d| d.entity_type == "EMAIL_ADDRESS"),
        "Email with \\u0040 should be detected: {:?}",
        dets
    );
    assert!(result.contains("[EMAIL_ADDRESS_"));
}

#[test]
fn test_unicode_escape_multiple_sequences() {
    let mut a = Anonymizer::new(0.0);
    // Multiple unicode escapes in one email
    let (result, dets) = a.anonymize_text(r"user\u0040domain\u002Ecom");
    assert!(
        dets.iter().any(|d| d.entity_type == "EMAIL_ADDRESS"),
        "Email with multiple unicode escapes should be detected: {:?}",
        dets
    );
    assert!(result.contains("[EMAIL_ADDRESS_"));
}

#[test]
fn test_unicode_escape_no_double_mask() {
    let mut a = Anonymizer::new(0.0);
    // Plain email (no escapes) should still work normally
    let (result, dets) = a.anonymize_text("contact jane@example.com here");
    assert_eq!(dets.len(), 1);
    assert_eq!(dets[0].entity_type, "EMAIL_ADDRESS");
    assert!(result.contains("[EMAIL_ADDRESS_"));
}

#[test]
fn test_unicode_escape_malformed_passthrough() {
    // Malformed \u sequences should pass through without panic
    let mut a = Anonymizer::new(0.0);
    let (result, _) = a.anonymize_text(r"bad escape \u00 and \u00GG here");
    assert!(result.contains(r"\u00"));
}

#[test]
fn test_percent_encoded_email_detected() {
    let mut a = Anonymizer::new(0.0);
    let (result, dets) = a.anonymize_text("email=j.smith%40provider.net&loyalty_id=9928374");
    assert!(
        dets.iter().any(|d| d.entity_type == "EMAIL_ADDRESS"),
        "Email with %40 should be detected: {:?}",
        dets
    );
    assert!(result.contains("[EMAIL_ADDRESS_"));
}

#[test]
fn test_percent_encoded_no_double_mask() {
    let mut a = Anonymizer::new(0.0);
    // Plain email (no encoding) should still work
    let (result, dets) = a.anonymize_text("email=j.smith@provider.net");
    assert_eq!(
        dets.iter()
            .filter(|d| d.entity_type == "EMAIL_ADDRESS")
            .count(),
        1
    );
    assert!(result.contains("[EMAIL_ADDRESS_"));
}
