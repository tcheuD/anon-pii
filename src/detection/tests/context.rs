use super::super::*;

// -- Context tests --

#[test]
fn test_context_score_boost() {
    // Without context keyword: base score
    let mut a = Anonymizer::new(0.0);
    let (_, dets) = a.anonymize_text("call 06 12 34 56 78");
    let phone_det = dets
        .iter()
        .find(|d| d.entity_type == "FR_PHONE_NUMBER")
        .unwrap();
    assert!((phone_det.score - 0.7).abs() < 0.01);

    // With context keyword "telephone": boosted score
    let mut a2 = Anonymizer::new(0.0);
    let (_, dets2) = a2.anonymize_text("telephone 06 12 34 56 78");
    let phone_det2 = dets2
        .iter()
        .find(|d| d.entity_type == "FR_PHONE_NUMBER")
        .unwrap();
    assert!((phone_det2.score - 0.85).abs() < 0.01); // 0.7 + 0.15 boost
}

#[test]
fn test_threshold() {
    let mut a = Anonymizer::new(0.8);
    let (_, dets) = a.anonymize_text("visit https://example.com call 06 12 34 56 78");
    // URL (0.9) should pass, fr_phone_national (0.7) should be filtered
    assert!(dets.iter().any(|d| d.entity_type == "URL"));
    assert!(!dets.iter().any(|d| d.entity_type == "FR_PHONE_NUMBER"));
}

#[test]
fn test_tabular_crew_codes_with_login_context() {
    let mut a = Anonymizer::new(0.0);
    let input = r#"Clean Orphaned Leave Records
     ===============================

      Found 3 orphaned leaves from 3 mappings.

      ------- ------------------------- ----------------- --------------- ------------- ------------ ------------
       Login   Email                     Leave ID          Duty IDs        Mapping IDs   Start        End
      ------- ------------------------- ----------------- --------------- ------------- ------------ ------------
       ZKP     zpetit@example-air.com     26062001          65880001        90001         2026-03-01   2026-03-01
       VQM     vmercier@example-air.com   26072001          65100001        90002         2026-03-02   2026-03-02
       XRL     xrenard@example-air.com     26055001          65090001        90003         2026-03-03   2026-03-03
      ------- ------------------------- ----------------- --------------- ------------- ------------ ------------"#;
    let (result, dets) = a.anonymize_text(input);

    // Crew codes should be anonymized (Login header provides context)
    assert!(
        dets.iter().any(|d| d.entity_type == "CREW_CODE"),
        "Crew codes (ZKP, VQM, XRL) should be detected with 'Login' context.\nDetections: {:?}\nResult: {}",
        dets,
        result
    );
    assert!(!result.contains("ZKP"), "ZKP should be anonymized");
    assert!(!result.contains("VQM"), "VQM should be anonymized");
    assert!(!result.contains("XRL"), "XRL should be anonymized");

    // Emails should be anonymized
    assert!(
        !result.contains("zpetit@example-air.com"),
        "Email should be anonymized"
    );
    assert!(
        !result.contains("vmercier@example-air.com"),
        "Email should be anonymized"
    );
    assert!(
        !result.contains("xrenard@example-air.com"),
        "Email should be anonymized"
    );
}

#[test]
fn test_column_header_no_false_positive_wrong_column() {
    // Crew code at a column that does NOT align with "Login" header
    let mut a = Anonymizer::new(0.0);
    let input = "Login   Status\n------  ------\nOK      XYZ";
    let (_, dets) = a.anonymize_text(input);
    // XYZ is in the "Status" column, not "Login" — should NOT match CREW_CODE
    assert!(
        !dets
            .iter()
            .any(|d| d.entity_type == "CREW_CODE" && d.original == "XYZ"),
        "XYZ under 'Status' column should not be detected as CREW_CODE.\nDetections: {:?}",
        dets
    );
}

#[test]
fn test_column_header_context_with_duty_keyword() {
    // "Duty" is also a CREW_CODE context keyword — test it as a column header
    let mut a = Anonymizer::new(0.0);
    let input = "Duty    Name\n------  ------\nZKP     Someone\nVQM     Another";
    let (result, dets) = a.anonymize_text(input);
    assert!(
        dets.iter().any(|d| d.entity_type == "CREW_CODE"),
        "Crew codes should be detected under 'Duty' header.\nDetections: {:?}\nResult: {}",
        dets,
        result
    );
    assert!(!result.contains("ZKP"), "ZKP should be anonymized");
    assert!(!result.contains("VQM"), "VQM should be anonymized");
}

#[test]
fn test_column_header_no_header_above() {
    // No header line at all — crew code should NOT be detected
    let mut a = Anonymizer::new(0.0);
    let input = "ZKP     some text here";
    let (_, dets) = a.anonymize_text(input);
    assert!(
        !dets.iter().any(|d| d.entity_type == "CREW_CODE"),
        "ZKP without any context should not be detected.\nDetections: {:?}",
        dets
    );
}

#[test]
fn test_column_header_many_rows_below_header() {
    // Header is 10+ rows above — should still work (within 20-line lookback)
    let mut a = Anonymizer::new(0.0);
    let mut lines = vec!["Crew  Info".to_string(), "----  ----".to_string()];
    for i in 0..15 {
        lines.push(format!("C{:02}   row {}", i, i));
    }
    lines.push("ZKP   last row".to_string());
    let input = lines.join("\n");
    let (result, dets) = a.anonymize_text(&input);
    assert!(
        dets.iter()
            .any(|d| d.entity_type == "CREW_CODE" && d.original == "ZKP"),
        "ZKP should be detected with 'Crew' header 17 lines above.\nDetections: {:?}\nResult: {}",
        dets,
        result
    );
}

#[test]
fn test_context_window_counts_chars_not_bytes_cjk() {
    // Keyword "telephone" sits ~31 characters (~91 bytes) before the phone
    // number, separated by 3-byte CJK filler. A byte-based 80-window would drop
    // the keyword (91 > 80 bytes) and leave the score at base 0.7; a char-based
    // 80-window keeps it (31 <= 80 chars) and boosts the score.
    let filler: String = std::iter::repeat('\u{3042}').take(30).collect();
    let input = format!("telephone {filler} 06 12 34 56 78");
    let mut a = Anonymizer::new(0.0);
    let (_, dets) = a.anonymize_text(&input);
    let phone = dets
        .iter()
        .find(|d| d.entity_type == "FR_PHONE_NUMBER")
        .expect("phone detected past CJK filler");
    assert!(
        phone.score > 0.7,
        "keyword within char-window should boost score, got {}",
        phone.score
    );
}

fn assert_phone_column(header: &str, row_prefix: &str, intervening: usize, expected: bool) {
    let phone = "+1 202 555 0142";
    // Keep the header outside the local context window, even on the next line.
    let separator = format!("{}\n", "-".repeat(100));
    let input = format!(
        "{header}\n{}{row_prefix}{phone}",
        separator.repeat(intervening)
    );
    let mut a = Anonymizer::new(0.5);
    let (prepared, dets) = a.anonymize_text(&input);
    let phones: Vec<_> = dets
        .iter()
        .filter(|d| d.entity_type == "PHONE_NUMBER")
        .collect();
    assert_eq!(phones.len(), usize::from(expected), "{input:?}: {dets:?}");
    if expected {
        let start = input.len() - phone.len();
        assert_eq!(phones[0].original, phone);
        assert_eq!((phones[0].start, phones[0].end), (start, input.len()));
        assert_eq!(phones[0].score, 0.6);
        assert!(!prepared.contains(phone), "{prepared:?}");
        assert_eq!(a.mapping.restore_bracketed(&prepared), input);
    } else {
        assert_eq!(prepared, input);
    }
}

#[test]
fn test_column_header_unicode_phone_roundtrip() {
    for header in [
        "Elements deja verifies  phone".to_string(),
        "Éléments déjà vérifiés  phone".to_string(),
        format!("{}{}phone", "İ".repeat(12), " ".repeat(12)),
        format!("{}phone", "x\u{301}".repeat(12)),
    ] {
        assert_phone_column(&header, "example                 ", 1, true);
    }
    // The value's column must also count scalars, rather than UTF-8 bytes.
    assert_phone_column("                        phone", &"界".repeat(24), 1, true);
}

#[test]
fn test_column_header_scalar_tolerance_and_tabs() {
    // Keyword interval [24,29): preserve the existing inclusive +/-4 tolerance.
    for (column, expected) in [(19, false), (20, true), (33, true), (34, false)] {
        assert_phone_column(
            "Éléments déjà vérifiés  phone",
            &" ".repeat(column),
            1,
            expected,
        );
    }
    // Tabs count once; these checks intentionally do not use terminal tab stops.
    assert_phone_column("\t\t\t\t\t\tphone", "      ", 1, true);
    assert_phone_column("\t\t\t\t\t\tphone", &" ".repeat(48), 1, false);
    assert_phone_column("                        phone", &"\t".repeat(24), 1, true);
}

#[test]
fn test_column_header_context_boundaries_remain_required() {
    let header = "Éléments déjà vérifiés  phone";
    assert_phone_column(header, &" ".repeat(24), 19, true); // 20th line above
    assert_phone_column(header, &" ".repeat(24), 20, false); // 21st line above
    assert_phone_column("Éléments déjà vérifiés  status", &" ".repeat(24), 1, false);
    // Retain first-occurrence matching; a later duplicate does not widen context.
    assert_phone_column(
        "phone                        phone",
        &" ".repeat(29),
        1,
        false,
    );

    let input = format!(
        "{header}\n{}\n{}+1 202 555 0142",
        "-".repeat(100),
        " ".repeat(24)
    );
    let mut a = Anonymizer::new(0.7);
    let (prepared, dets) = a.anonymize_text(&input);
    assert!(dets.is_empty());
    assert_eq!(
        prepared, input,
        "column context must not raise the required-context score"
    );
}

#[test]
fn test_column_header_custom_keyword_case_projection() {
    use crate::config::RecognizerConfigFile;

    for (header_word, keyword, column, expected) in [
        ("İ", "i", 16, true),
        ("İ", "i", 15, false),
        ("İ", "i", 25, true),
        ("İ", "i", 26, false),
        ("İ", "\u{307}", 16, true),
        ("İ", "\u{307}", 25, true),
        ("İ", "\u{307}", 26, false),
        ("İ", "i\u{307}", 25, true),
        ("İ", "i\u{307}", 26, false),
        ("ΟΣ", "ος", 26, true), // Whole-string lowercase preserves final sigma.
        ("ΟΣ", "ΟΣ", 20, false), // Configured keywords retain their spelling.
        ("téléphone", "téléphone", 33, true),
        ("téléphone", "téléphone", 34, false),
    ] {
        let config = RecognizerConfigFile::from_yaml(&format!(
            "recognizers:\n  - name: column-test\n    entity_type: FICTIONAL_VALUE\n    patterns:\n      - regex: QZXVALUE\n        score: 0.8\n    context_keywords: [{}]\n    context_required: true\n",
            serde_json::to_string(keyword).unwrap()
        )).unwrap();
        let mut a = Anonymizer::new(0.5);
        a.add_custom_patterns(&config);
        let input = format!(
            "{}{header_word}\n{}\n{}QZXVALUE",
            " ".repeat(20),
            "-".repeat(100),
            " ".repeat(column)
        );
        let (prepared, dets) = a.anonymize_text(&input);
        assert_eq!(
            dets.len(),
            usize::from(expected),
            "{header_word:?}/{keyword:?} at {column}: {dets:?}"
        );
        if expected {
            assert_eq!(dets[0].entity_type, "FICTIONAL_VALUE");
            assert_eq!(dets[0].original, "QZXVALUE");
            assert_eq!(dets[0].score, 0.8);
            assert!(!prepared.contains("QZXVALUE"));
            assert_eq!(a.mapping.restore_bracketed(&prepared), input);
        } else {
            assert_eq!(prepared, input);
        }
    }
}
