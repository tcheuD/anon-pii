use super::super::*;

// -- SQL tests --

#[test]
fn test_sql_anonymizes_string_literals_only() {
    let mut a = Anonymizer::new(0.0);
    let sql = "INSERT INTO users VALUES (1, 'john@example.com', 'admin')";
    let (result, dets) = a.anonymize_sql(sql);
    // Email inside string literal should be detected
    assert!(dets.iter().any(|d| d.entity_type == "EMAIL_ADDRESS"));
    assert!(result.contains("[EMAIL_ADDRESS_"));
    // SQL keywords and structure should be preserved
    assert!(result.starts_with("INSERT INTO users VALUES"));
}

#[test]
fn test_sql_preserves_identifiers() {
    let mut a = Anonymizer::new(0.0);
    // UUID is an identifier here, not PII — it's not inside quotes
    let sql = "SELECT uuid FROM sessions WHERE id = '550e8400-e29b-41d4-a716-446655440000'";
    let (result, dets) = a.anonymize_sql(sql);
    // The UUID in the string literal should be detected
    assert!(dets.iter().any(|d| d.entity_type == "UUID"));
    // "uuid" as a column name should NOT be anonymized
    assert!(result.contains("SELECT uuid FROM"));
}

#[test]
fn test_sql_escaped_quotes() {
    let mut a = Anonymizer::new(0.0);
    let sql = "INSERT INTO logs VALUES ('it''s john@test.com')";
    let (result, dets) = a.anonymize_sql(sql);
    assert!(dets.iter().any(|d| d.entity_type == "EMAIL_ADDRESS"));
    assert!(result.contains("[EMAIL_ADDRESS_"));
    assert!(result.contains("'it''s [EMAIL_ADDRESS_"));
    assert_eq!(a.mapping.restore_bracketed(&result), sql);
}

#[test]
fn test_sql_multibyte_utf8_literal_not_corrupted() {
    let mut a = Anonymizer::new(0.0);
    // Accented characters inside and outside literals must not be corrupted
    // by byte-wise scanning.
    let sql =
        "INSERT INTO clients VALUES ('Gaël Müller, réf café', 'mail: john@test.com') -- N° dossier";
    let (result, dets) = a.anonymize_sql(sql);
    assert!(dets.iter().any(|d| d.entity_type == "EMAIL_ADDRESS"));
    assert!(result.contains("[EMAIL_ADDRESS_"));
    assert!(
        result.contains("-- N° dossier"),
        "Non-literal SQL must pass through byte-identical: {result}"
    );
    assert!(
        !result.contains('\u{FFFD}') && !result.contains("GaÃ«l"),
        "Multibyte characters must not be corrupted: {result}"
    );
}

#[test]
fn test_sql_unterminated_literal_is_left_byte_identical() {
    let mut a = Anonymizer::new(0.0);
    let sql = "INSERT INTO logs VALUES ('john@example.com";
    let (result, dets) = a.anonymize_sql(sql);

    assert!(dets.is_empty());
    assert_eq!(result, sql);
}

#[test]
fn test_sql_without_changes_is_byte_identical() {
    let mut a = Anonymizer::new(0.0);
    let sql = "SELECT 'it''s ordinary' AS note;\r\nSELECT 42;\r\n";
    let (result, dets) = a.anonymize_sql(sql);

    assert!(dets.is_empty());
    assert_eq!(result, sql);
}

#[test]
fn test_sql_changed_literal_preserves_crlf_and_surrounding_source() {
    let mut a = Anonymizer::new(0.0);
    let sql = "INSERT INTO logs(value)\r\nVALUES ('email john@example.com');\r\n";
    let (result, dets) = a.anonymize_sql(sql);

    assert!(dets.iter().any(|d| d.entity_type == "EMAIL_ADDRESS"));
    assert!(result.starts_with("INSERT INTO logs(value)\r\nVALUES ('email "));
    assert!(result.ends_with("');\r\n"));
    assert_eq!(result.matches("\r\n").count(), 2);
    assert_eq!(a.mapping.restore_bracketed(&result), sql);
}

#[test]
fn test_sql_does_not_anonymize_quotes_inside_comments_or_identifiers() {
    let mut a = Anonymizer::new(0.0);
    let sql = "-- 'john@example.com'\r\nSELECT \"'jane@example.com'\" FROM users /* 'x@y.test' */;";
    let (result, dets) = a.anonymize_sql(sql);

    assert!(dets.is_empty());
    assert_eq!(result, sql);
}

#[test]
fn test_sql_backslash_escaped_quote_does_not_hide_later_pii() {
    let mut a = Anonymizer::new(0.0);
    let sql = r"SELECT E'it\'s john@example.com' AS note;";
    let (result, dets) = a.anonymize_sql(sql);

    assert!(dets.iter().any(|d| d.entity_type == "EMAIL_ADDRESS"));
    assert!(result.contains(r"E'it\'s [EMAIL_ADDRESS_"));
    assert!(result.ends_with("' AS note;"));
    assert_eq!(a.mapping.restore_bracketed(&result), sql);
}

#[test]
fn test_sql_standard_backslash_does_not_consume_the_next_literal() {
    let mut a = Anonymizer::new(0.0);
    let sql = r"SELECT 'john@example.com\', 'jane@example.com';";
    let (result, dets) = a.anonymize_sql(sql);

    assert_eq!(
        dets.iter()
            .filter(|d| d.entity_type == "EMAIL_ADDRESS")
            .count(),
        2
    );
    assert_eq!(result.matches("[EMAIL_ADDRESS_").count(), 2);
    assert_eq!(a.mapping.restore_bracketed(&result), sql);
}

#[test]
fn sql_e_string_controls_mask_wrapped_emails_and_restore_exact_source() {
    let mut anonymizer = Anonymizer::new(0.5);
    let mut prepared = Vec::new();
    for (marker, address) in [
        ("E", r"ada@\nexample.com"),
        ("e", r"ada@\r\n\texample.com"),
        ("E", r"ａｄａ＠\n\tｅｘａｍｐｌｅ．ｃｏｍ"),
        ("E", "ada@\nexample.com"),
    ] {
        let prefix = r"Préfixe 😀 it\'s ";
        let suffix = r"; suffix\nunchanged";
        let literal = format!("{prefix}{address}{suffix}");
        let sql = format!("INSERT INTO tickets VALUES ({marker}'{literal}');\r\n");
        let (output, detections) = anonymizer.anonymize_sql(&sql);
        assert_eq!(detections.len(), 1, "{sql:?}: {detections:?}");
        let detection = &detections[0];
        assert_eq!(detection.entity_type, "EMAIL_ADDRESS");
        assert_eq!(detection.original, address);
        assert_eq!(
            (detection.start, detection.end),
            (prefix.len(), prefix.len() + address.len())
        );
        assert_eq!(&literal[detection.start..detection.end], address);
        assert!(output.starts_with(&format!(
            "INSERT INTO tickets VALUES ({marker}'{prefix}[EMAIL_ADDRESS_"
        )));
        assert!(output.ends_with(&format!("]{suffix}');\r\n")));
        assert!(!output.contains(address));
        prepared.push((sql, output));
    }
    // Equivalent decoded values with distinct source spelling need distinct
    // mappings; later preparations must not change earlier restorations.
    assert_eq!(anonymizer.mapping.mappings.len(), prepared.len());
    for (sql, output) in prepared {
        assert_eq!(anonymizer.mapping.restore_bracketed(&output), sql);
    }
}

#[test]
fn sql_e_string_controls_keep_literal_and_context_boundaries() {
    for sql in [
        r"SELECT 'ada@\nexample.com';",
        r"SELECT $body$ada@\nexample.com$body$;",
        r"SELECT E'ada@\\nexample.com';",
        r"SELECT E'ada@\r\n\\texample.com';",
        r"SELECT E'ada@\n\nexample.com';",
        r"SELECT E'ada@\rexample.com';",
        r"SELECT E'ada@ \nexample.com';",
        r"SELECT E'ada@\nexample.\ncom';",
        r"SELECT E'ada@\qexample.com';",
        r"SELECT E'ada@\nexample.com",
        r"SELECT E 'ada@\nexample.com';",
        r"SELECT someE'ada@\nexample.com';",
        r#"SELECT "E'ada@\nexample.com'"; -- E'ada@\nexample.com'"#,
        r"/* E'ada@\nexample.com' */ SELECT 42;",
    ] {
        let mut anonymizer = Anonymizer::new(0.5);
        let (output, detections) = anonymizer.anonymize_sql(sql);
        assert!(detections.is_empty(), "{sql:?}: {detections:?}");
        assert_eq!(output, sql);
    }
    let text = r"Contact ada@\nexample.com";
    let (output, detections) = Anonymizer::new(0.5).anonymize_text(text);
    assert!(detections.is_empty());
    assert_eq!(output, text);
    let sql = r"SELECT E'ada@\nexample.com';";
    let (output, detections) = Anonymizer::new(0.91).anonymize_sql(sql);
    assert!(detections.is_empty());
    assert_eq!(output, sql);
}

#[test]
fn sql_e_string_control_spanning_custom_match_retains_source_bytes() {
    let mut anonymizer = Anonymizer::new(0.5);
    anonymizer.patterns = vec![CompiledPattern {
        name: Cow::Borrowed("sql_control_fixture"),
        entity_type: Cow::Borrowed("SQL_FIXTURE"),
        regex: Regex::new(r"debug\x08\x0c\n\r\tend").unwrap(),
        score: 1.0,
        context_keywords: Cow::Borrowed(&[]),
        context_required: false,
    }];
    let original = r"debug\b\f\n\r\tend";
    let sql = format!(r"SELECT E'😀 {original}';");
    let (output, detections) = anonymizer.anonymize_sql(&sql);
    assert_eq!(detections.len(), 1);
    assert_eq!(detections[0].original, original);
    assert_eq!(
        (detections[0].start, detections[0].end),
        ("😀 ".len(), "😀 ".len() + original.len())
    );
    assert!(output.starts_with("SELECT E'😀 [SQL_FIXTURE_"));
    assert_eq!(anonymizer.mapping.restore_bracketed(&output), sql);
}

#[test]
fn test_sql_dollar_quoted_literal_is_anonymized_and_roundtrips() {
    let mut a = Anonymizer::new(0.0);
    let sql = "SELECT $body$owner john@example.com's address$body$ AS note;";
    let (result, dets) = a.anonymize_sql(sql);

    assert_eq!(
        dets.iter()
            .filter(|d| d.entity_type == "EMAIL_ADDRESS")
            .count(),
        1,
        "a dollar-quoted literal must report each detection exactly once"
    );
    assert!(result.contains("$body$owner [EMAIL_ADDRESS_"));
    assert_eq!(a.mapping.restore_bracketed(&result), sql);
}

fn sql_escape_spanning_anonymizer() -> Anonymizer {
    let mut anonymizer = Anonymizer::new(0.5);
    // Exercise a recognizer whose match crosses both a quote and a backslash.
    // The synthetic value is deliberately independent of any built-in entity.
    anonymizer.patterns = vec![CompiledPattern {
        name: Cow::Borrowed("sql_escape_fixture"),
        entity_type: Cow::Borrowed("SQL_FIXTURE"),
        regex: Regex::new(r"debug'owner\\local").unwrap(),
        score: 1.0,
        context_keywords: Cow::Borrowed(&[]),
        context_required: false,
    }];
    anonymizer
}

#[test]
fn sql_quote_spanning_tokens_retain_distinct_original_escape_spellings() {
    let mut anonymizer = sql_escape_spanning_anonymizer();
    let raw = r"debug'owner\local";
    let (plain_output, _) = anonymizer.anonymize_text(raw);
    let mut results = Vec::new();
    for sql in [
        r"SELECT 'debug''owner\local';",
        r"SELECT E'debug\'owner\\local';",
        r"SELECT E'debug''owner\\local';",
        r"SELECT $body$debug'owner\local$body$;",
    ] {
        let (output, detections) = anonymizer.anonymize_sql(sql);
        assert_eq!(detections.len(), 1, "input: {sql}");
        assert!(output.contains("[SQL_FIXTURE_"));
        assert_eq!(anonymizer.mapping.restore_bracketed(&output), sql);
        results.push((sql, output));
    }
    // The plain/dollar-quoted spelling shares one token, while each distinct
    // escaped SQL spelling owns its own token. Earlier mappings stay intact.
    assert_eq!(anonymizer.mapping.mappings.len(), 4);
    assert_eq!(anonymizer.mapping.restore_bracketed(&plain_output), raw);
    for (sql, output) in results {
        assert_eq!(anonymizer.mapping.restore_bracketed(&output), sql);
    }
}

#[test]
fn sql_escape_provenance_composes_with_unicode_and_encoded_detection() {
    for raw_literal in [
        r"Préfixe 🏡 ｄebug''owner\local suffixe",
        r"Préfixe 🏡 debug%27owner\local suffixe",
        r"Préfixe 🏡 debug\u0027owner\local suffixe",
    ] {
        let sql = format!("SELECT '{raw_literal}';\r\n");
        let mut anonymizer = sql_escape_spanning_anonymizer();
        let (output, detections) = anonymizer.anonymize_sql(&sql);
        assert_eq!(detections.len(), 1, "input: {sql}");
        let detection = &detections[0];
        assert_eq!(
            &raw_literal[detection.start..detection.end],
            detection.original
        );
        assert!(output.starts_with("SELECT 'Préfixe 🏡 [SQL_FIXTURE_"));
        assert!(output.ends_with(" suffixe';\r\n"));
        assert_eq!(anonymizer.mapping.restore_bracketed(&output), sql);
    }
}

#[cfg(feature = "ner-lite")]
#[test]
fn sql_token_mode_runs_name_detection_on_decoded_literals() {
    for (sql, original_name) in [
        ("SELECT 'My name is Avery o''neill';", "Avery o''neill"),
        ("SELECT 'Dr O''Neill';", "O''Neill"),
        (r"SELECT E'My name is Avery o\'neill';", r"Avery o\'neill"),
        (
            "SELECT '🏡 My name is Avery o''neill. Contact o''neill later.';",
            "Avery o''neill",
        ),
    ] {
        let mut anonymizer = Anonymizer::new(0.5);
        anonymizer.set_ner_detector(Box::new(crate::ner::heuristic::HeuristicNerDetector::new()));
        let (output, detections) = anonymizer.anonymize_sql(sql);
        assert!(
            detections.iter().any(|detection| {
                detection.entity_type == "PERSON" && detection.original == original_name
            }),
            "name detection lost decoded SQL input for {sql}: {detections:?}"
        );
        assert!(
            !output.to_lowercase().contains("neill"),
            "name leaked: {output}"
        );
        assert_eq!(anonymizer.mapping.restore_bracketed(&output), sql);
    }
}
