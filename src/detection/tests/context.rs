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
       JDU     jdupont@example-air.com     26062001          65880001        90001         2026-03-01   2026-03-01
       MMA     mmartinez@example-air.com   26072001          65100001        90002         2026-03-02   2026-03-02
       BRN     bruneau@example-air.com     26055001          65090001        90003         2026-03-03   2026-03-03
      ------- ------------------------- ----------------- --------------- ------------- ------------ ------------"#;
    let (result, dets) = a.anonymize_text(input);

    // Crew codes should be anonymized (Login header provides context)
    assert!(
        dets.iter().any(|d| d.entity_type == "CREW_CODE"),
        "Crew codes (JDU, MMA, BRN) should be detected with 'Login' context.\nDetections: {:?}\nResult: {}",
        dets,
        result
    );
    assert!(!result.contains("JDU"), "JDU should be anonymized");
    assert!(!result.contains("MMA"), "MMA should be anonymized");
    assert!(!result.contains("BRN"), "BRN should be anonymized");

    // Emails should be anonymized
    assert!(
        !result.contains("jdupont@example-air.com"),
        "Email should be anonymized"
    );
    assert!(
        !result.contains("mmartinez@example-air.com"),
        "Email should be anonymized"
    );
    assert!(
        !result.contains("bruneau@example-air.com"),
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
    let input = "Duty    Name\n------  ------\nJDU     Someone\nMMA     Another";
    let (result, dets) = a.anonymize_text(input);
    assert!(
        dets.iter().any(|d| d.entity_type == "CREW_CODE"),
        "Crew codes should be detected under 'Duty' header.\nDetections: {:?}\nResult: {}",
        dets,
        result
    );
    assert!(!result.contains("JDU"), "JDU should be anonymized");
    assert!(!result.contains("MMA"), "MMA should be anonymized");
}

#[test]
fn test_column_header_no_header_above() {
    // No header line at all — crew code should NOT be detected
    let mut a = Anonymizer::new(0.0);
    let input = "JDU     some text here";
    let (_, dets) = a.anonymize_text(input);
    assert!(
        !dets.iter().any(|d| d.entity_type == "CREW_CODE"),
        "JDU without any context should not be detected.\nDetections: {:?}",
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
    lines.push("JDU   last row".to_string());
    let input = lines.join("\n");
    let (result, dets) = a.anonymize_text(&input);
    assert!(
        dets.iter()
            .any(|d| d.entity_type == "CREW_CODE" && d.original == "JDU"),
        "JDU should be detected with 'Crew' header 17 lines above.\nDetections: {:?}\nResult: {}",
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
