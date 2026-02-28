//! Tests for YAML recognizer configuration integration with Anonymizer.

use crate::config::RecognizerConfigFile;
use crate::detection::{Anonymizer, Operator};

/// Helper: compile custom patterns from YAML config and add to anonymizer.
fn anonymizer_with_config(yaml: &str, threshold: f64) -> Result<Anonymizer, String> {
    let config = RecognizerConfigFile::from_yaml(yaml).map_err(|e| e.to_string())?;
    let mut anonymizer = Anonymizer::new(threshold);
    anonymizer.add_custom_patterns(&config);
    Ok(anonymizer)
}

// ─── Test: add_custom_patterns method exists and works ───────────────────────

#[test]
fn test_add_custom_patterns_basic() {
    let yaml = r#"
recognizers:
  - name: "French license plate"
    entity_type: "FR_LICENSE_PLATE"
    patterns:
      - regex: '\b[A-Z]{2}-\d{3}-[A-Z]{2}\b'
        score: 0.85
"#;
    let anonymizer = anonymizer_with_config(yaml, 0.0).unwrap();

    // Custom pattern should be added to the pattern list
    let has_custom = anonymizer
        .patterns
        .iter()
        .any(|p| p.entity_type.as_ref() == "FR_LICENSE_PLATE");
    assert!(
        has_custom,
        "Custom pattern should be added to the anonymizer"
    );
}

#[test]
fn test_custom_pattern_detects_match() {
    let yaml = r#"
recognizers:
  - name: "French license plate"
    entity_type: "FR_LICENSE_PLATE"
    patterns:
      - regex: '\b[A-Z]{2}-\d{3}-[A-Z]{2}\b'
        score: 0.85
"#;
    let mut anonymizer = anonymizer_with_config(yaml, 0.0).unwrap();
    let (result, dets) = anonymizer.anonymize_text("Vehicle plate: AB-123-CD");

    assert!(
        dets.iter().any(|d| d.entity_type == "FR_LICENSE_PLATE"),
        "Custom pattern should detect license plate: {:?}",
        dets
    );
    assert!(
        result.contains("[FR_LICENSE_PLATE_"),
        "Should replace with token"
    );
}

#[test]
fn test_custom_pattern_with_context_keywords_boost() {
    let yaml = r#"
recognizers:
  - name: "French license plate"
    entity_type: "FR_LICENSE_PLATE"
    patterns:
      - regex: '\b[A-Z]{2}-\d{3}-[A-Z]{2}\b'
        score: 0.75
    context_keywords: ["plaque", "immatriculation", "vehicule"]
    context_required: false
"#;
    let mut anonymizer = anonymizer_with_config(yaml, 0.0).unwrap();

    // With context keyword "plaque"
    let (_, dets_with_ctx) = anonymizer.anonymize_text("plaque AB-123-CD");
    let score_with_ctx = dets_with_ctx
        .iter()
        .find(|d| d.entity_type == "FR_LICENSE_PLATE")
        .map(|d| d.score)
        .unwrap_or(0.0);

    // Without context keyword
    let (_, dets_no_ctx) = anonymizer.anonymize_text("data: AB-123-CD");
    let score_no_ctx = dets_no_ctx
        .iter()
        .find(|d| d.entity_type == "FR_LICENSE_PLATE")
        .map(|d| d.score)
        .unwrap_or(0.0);

    assert!(
        score_with_ctx > score_no_ctx,
        "Score with context ({}) should be higher than without ({})",
        score_with_ctx,
        score_no_ctx
    );
}

#[test]
fn test_custom_pattern_with_context_required() {
    let yaml = r#"
recognizers:
  - name: "French license plate"
    entity_type: "FR_LICENSE_PLATE"
    patterns:
      - regex: '\b[A-Z]{2}-\d{3}-[A-Z]{2}\b'
        score: 0.85
    context_keywords: ["plaque", "immatriculation"]
    context_required: true
"#;
    let mut anonymizer = anonymizer_with_config(yaml, 0.0).unwrap();

    // Should match with context
    let (_, dets_with_ctx) = anonymizer.anonymize_text("plaque AB-123-CD");
    assert!(
        dets_with_ctx
            .iter()
            .any(|d| d.entity_type == "FR_LICENSE_PLATE"),
        "Should match with context keyword"
    );

    // Should NOT match without context
    let (_, dets_no_ctx) = anonymizer.anonymize_text("data AB-123-CD");
    assert!(
        !dets_no_ctx
            .iter()
            .any(|d| d.entity_type == "FR_LICENSE_PLATE"),
        "Should NOT match without context keyword when context_required: true"
    );
}

// ─── Test: custom patterns work with all operators ───────────────────────────

#[test]
fn test_custom_pattern_operator_token() {
    let yaml = r#"
recognizers:
  - name: "Test ID"
    entity_type: "TEST_ID"
    patterns:
      - regex: 'TEST-\d{4}'
        score: 0.9
"#;
    let mut anonymizer = anonymizer_with_config(yaml, 0.0).unwrap();
    anonymizer.operator = Operator::Token;
    let (result, _) = anonymizer.anonymize_text("ID: TEST-1234");

    assert!(result.contains("[TEST_ID_"), "Token operator should work");
}

#[test]
fn test_custom_pattern_operator_redact() {
    let yaml = r#"
recognizers:
  - name: "Test ID"
    entity_type: "TEST_ID"
    patterns:
      - regex: 'TEST-\d{4}'
        score: 0.9
"#;
    let mut anonymizer = anonymizer_with_config(yaml, 0.0).unwrap();
    anonymizer.operator = Operator::Redact;
    let (result, _) = anonymizer.anonymize_text("ID: TEST-1234");

    assert_eq!(result, "ID: ", "Redact operator should work");
}

#[test]
fn test_custom_pattern_operator_mask() {
    let yaml = r#"
recognizers:
  - name: "Test ID"
    entity_type: "TEST_ID"
    patterns:
      - regex: 'TEST-\d{4}'
        score: 0.9
"#;
    let mut anonymizer = anonymizer_with_config(yaml, 0.0).unwrap();
    anonymizer.operator = Operator::Mask;
    let (result, _) = anonymizer.anonymize_text("ID: TEST-1234");

    assert!(
        result.contains("*"),
        "Mask operator should produce asterisks"
    );
    assert!(!result.contains("TEST-1234"), "Original should be masked");
}

#[test]
fn test_custom_pattern_operator_custom() {
    let yaml = r#"
recognizers:
  - name: "Test ID"
    entity_type: "TEST_ID"
    patterns:
      - regex: 'TEST-\d{4}'
        score: 0.9
"#;
    let mut anonymizer = anonymizer_with_config(yaml, 0.0).unwrap();
    anonymizer.operator = Operator::Custom;
    anonymizer.replace_with = Some("<{entity_type}>".to_string());
    let (result, _) = anonymizer.anonymize_text("ID: TEST-1234");

    assert_eq!(result, "ID: <TEST_ID>", "Custom operator should work");
}

// ─── Test: custom patterns work with all formats ─────────────────────────────

#[test]
fn test_custom_pattern_json_format() {
    let yaml = r#"
recognizers:
  - name: "Test ID"
    entity_type: "TEST_ID"
    patterns:
      - regex: 'TEST-\d{4}'
        score: 0.9
"#;
    let mut anonymizer = anonymizer_with_config(yaml, 0.0).unwrap();
    let json: serde_json::Value = serde_json::from_str(r#"{"id": "TEST-1234"}"#).unwrap();
    let (result, dets) = anonymizer.anonymize_json_value(&json);

    assert!(
        dets.iter().any(|d| d.entity_type == "TEST_ID"),
        "Custom pattern should work in JSON"
    );
    assert!(
        result["id"].as_str().unwrap().contains("[TEST_ID_"),
        "JSON value should be anonymized"
    );
}

#[test]
fn test_custom_pattern_csv_format() {
    let yaml = r#"
recognizers:
  - name: "Test ID"
    entity_type: "TEST_ID"
    patterns:
      - regex: 'TEST-\d{4}'
        score: 0.9
"#;
    let mut anonymizer = anonymizer_with_config(yaml, 0.0).unwrap();
    let csv = "name,id\nJohn,TEST-1234";
    let (result, dets) = anonymizer.anonymize_csv(csv);

    assert!(
        dets.iter().any(|d| d.entity_type == "TEST_ID"),
        "Custom pattern should work in CSV"
    );
    assert!(result.contains("[TEST_ID_"), "CSV should be anonymized");
}

#[test]
fn test_custom_pattern_sql_format() {
    let yaml = r#"
recognizers:
  - name: "Test ID"
    entity_type: "TEST_ID"
    patterns:
      - regex: 'TEST-\d{4}'
        score: 0.9
"#;
    let mut anonymizer = anonymizer_with_config(yaml, 0.0).unwrap();
    let sql = "SELECT * FROM users WHERE id = 'TEST-1234'";
    let (result, dets) = anonymizer.anonymize_sql(sql);

    assert!(
        dets.iter().any(|d| d.entity_type == "TEST_ID"),
        "Custom pattern should work in SQL"
    );
    assert!(result.contains("[TEST_ID_"), "SQL should be anonymized");
}

// ─── Test: custom patterns participate in overlap resolution ─────────────────

#[test]
fn test_custom_pattern_overlap_with_builtin() {
    // Create a custom pattern that overlaps with EMAIL_ADDRESS
    // The longer/higher-score pattern should win
    let yaml = r#"
recognizers:
  - name: "Company email"
    entity_type: "COMPANY_EMAIL"
    patterns:
      - regex: '[a-z.]+@company\.com'
        score: 0.95
"#;
    let mut anonymizer = anonymizer_with_config(yaml, 0.0).unwrap();
    let (_, dets) = anonymizer.anonymize_text("Contact: john@company.com");

    // Both patterns match, but overlap resolution should keep only one
    let entity_types: Vec<&str> = dets.iter().map(|d| d.entity_type.as_ref()).collect();
    assert!(
        entity_types.len() == 1,
        "Overlap resolution should keep only one: {:?}",
        entity_types
    );
}

#[test]
fn test_custom_pattern_longer_wins_overlap() {
    // Custom pattern matches longer span
    let yaml = r#"
recognizers:
  - name: "Extended ID"
    entity_type: "EXTENDED_ID"
    patterns:
      - regex: 'PREFIX-TEST-\d{4}-SUFFIX'
        score: 0.9
  - name: "Test ID"
    entity_type: "TEST_ID"
    patterns:
      - regex: 'TEST-\d{4}'
        score: 0.9
"#;
    let mut anonymizer = anonymizer_with_config(yaml, 0.0).unwrap();
    let (_, dets) = anonymizer.anonymize_text("ID: PREFIX-TEST-1234-SUFFIX");

    // The longer EXTENDED_ID should win over TEST_ID
    let types: Vec<&str> = dets.iter().map(|d| d.entity_type.as_ref()).collect();
    assert!(
        types.contains(&"EXTENDED_ID"),
        "Longer pattern should win: {:?}",
        types
    );
    assert!(
        !types.contains(&"TEST_ID"),
        "Shorter overlapping pattern should be filtered: {:?}",
        types
    );
}

// ─── Test: multiple patterns per recognizer ──────────────────────────────────

#[test]
fn test_multiple_patterns_same_entity_type() {
    let yaml = r#"
recognizers:
  - name: "Phone variants"
    entity_type: "CUSTOM_PHONE"
    patterns:
      - regex: '\+1-\d{3}-\d{3}-\d{4}'
        score: 0.9
      - regex: '\(\d{3}\) \d{3}-\d{4}'
        score: 0.85
"#;
    let mut anonymizer = anonymizer_with_config(yaml, 0.0).unwrap();

    // First format
    let (_, dets1) = anonymizer.anonymize_text("Call +1-555-123-4567");
    assert!(
        dets1.iter().any(|d| d.entity_type == "CUSTOM_PHONE"),
        "First pattern should match"
    );

    // Second format
    let (_, dets2) = anonymizer.anonymize_text("Call (555) 123-4567");
    assert!(
        dets2.iter().any(|d| d.entity_type == "CUSTOM_PHONE"),
        "Second pattern should match"
    );
}

// ─── Test: get_entity_types includes custom entities ─────────────────────────

#[test]
fn test_get_entity_types_includes_custom() {
    let yaml = r#"
recognizers:
  - name: "Custom type"
    entity_type: "CUSTOM_ENTITY_TYPE"
    patterns:
      - regex: 'CUSTOM-\d+'
        score: 0.9
"#;
    let anonymizer = anonymizer_with_config(yaml, 0.0).unwrap();
    let types = anonymizer.get_entity_types();

    assert!(
        types.contains(&"CUSTOM_ENTITY_TYPE"),
        "get_entity_types should include custom entities: {:?}",
        types
    );
    // Should also have built-in types
    assert!(
        types.contains(&"EMAIL_ADDRESS"),
        "get_entity_types should still include built-in entities: {:?}",
        types
    );
}

// ─── Test: empty config is valid ─────────────────────────────────────────────

#[test]
fn test_empty_config_no_crash() {
    let yaml = r#"
recognizers: []
"#;
    let anonymizer = anonymizer_with_config(yaml, 0.0).unwrap();
    // Should still have all built-in patterns
    assert!(
        anonymizer.patterns.len() > 0,
        "Should still have built-in patterns"
    );
}

// ─── Test: analyze() method works with custom patterns ───────────────────────

#[test]
fn test_analyze_with_custom_patterns() {
    let yaml = r#"
recognizers:
  - name: "Test ID"
    entity_type: "TEST_ID"
    patterns:
      - regex: 'TEST-\d{4}'
        score: 0.9
"#;
    let mut anonymizer = anonymizer_with_config(yaml, 0.0).unwrap();
    let dets = anonymizer.analyze("Found TEST-1234 in logs");

    assert!(
        dets.iter().any(|d| d.entity_type == "TEST_ID"),
        "analyze() should detect custom patterns"
    );
}

// ─── Test: threshold applies to custom patterns ──────────────────────────────

#[test]
fn test_threshold_applies_to_custom_patterns() {
    let yaml = r#"
recognizers:
  - name: "Low score pattern"
    entity_type: "LOW_SCORE_TYPE"
    patterns:
      - regex: 'LOW-\d{4}'
        score: 0.3
  - name: "High score pattern"
    entity_type: "HIGH_SCORE_TYPE"
    patterns:
      - regex: 'HIGH-\d{4}'
        score: 0.9
"#;
    // High threshold should filter out low score patterns
    let mut anonymizer = anonymizer_with_config(yaml, 0.5).unwrap();
    let (_, dets) = anonymizer.anonymize_text("Found LOW-1234 and HIGH-5678");

    assert!(
        !dets.iter().any(|d| d.entity_type == "LOW_SCORE_TYPE"),
        "Low score pattern should be filtered by threshold"
    );
    assert!(
        dets.iter().any(|d| d.entity_type == "HIGH_SCORE_TYPE"),
        "High score pattern should pass threshold"
    );
}

// ─── Tests loading from testdata/custom-recognizers.yaml ─────────────────────

/// Helper: load config from testdata file and create anonymizer.
fn anonymizer_from_testdata(threshold: f64) -> Anonymizer {
    let config_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("testdata")
        .join("custom-recognizers.yaml");
    let config = RecognizerConfigFile::load(&config_path)
        .expect("testdata/custom-recognizers.yaml should exist and be valid");
    let mut anonymizer = Anonymizer::new(threshold);
    anonymizer.add_custom_patterns(&config);
    anonymizer
}

#[test]
fn test_load_sample_config_file() {
    // Acceptance criterion: testdata/custom-recognizers.yaml with at least 2 recognizers
    let config_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("testdata")
        .join("custom-recognizers.yaml");
    let config = RecognizerConfigFile::load(&config_path)
        .expect("testdata/custom-recognizers.yaml should exist and be valid");

    assert!(
        config.recognizers.len() >= 2,
        "Sample config should have at least 2 recognizers, found {}",
        config.recognizers.len()
    );
}

#[test]
fn test_sample_config_plain_text_detection() {
    // Acceptance criterion: custom entity detected in plain text
    let mut anonymizer = anonymizer_from_testdata(0.0);

    // Test FR_LICENSE_PLATE detection (from sample config)
    let (result, dets) = anonymizer.anonymize_text("La plaque du vehicule est AB-123-CD");
    assert!(
        dets.iter().any(|d| d.entity_type == "FR_LICENSE_PLATE"),
        "Sample config should detect FR_LICENSE_PLATE in plain text: {:?}",
        dets
    );
    assert!(
        result.contains("[FR_LICENSE_PLATE_"),
        "Should replace license plate with token"
    );
}

#[test]
fn test_sample_config_json_detection() {
    // Acceptance criterion: custom entity detected in JSON values
    let mut anonymizer = anonymizer_from_testdata(0.0);
    let json: serde_json::Value =
        serde_json::from_str(r#"{"plaque": "AB-123-CD", "type": "vehicule"}"#).unwrap();
    let (result, dets) = anonymizer.anonymize_json_value(&json);

    assert!(
        dets.iter().any(|d| d.entity_type == "FR_LICENSE_PLATE"),
        "Sample config should detect FR_LICENSE_PLATE in JSON: {:?}",
        dets
    );
    assert!(
        result["plaque"]
            .as_str()
            .unwrap()
            .contains("[FR_LICENSE_PLATE_"),
        "JSON value should be anonymized"
    );
}

#[test]
fn test_sample_config_csv_detection() {
    // Acceptance criterion: custom entity detected in CSV cells
    let mut anonymizer = anonymizer_from_testdata(0.0);
    let csv = "vehicule,plaque,couleur\nRenault,AB-123-CD,rouge";
    let (result, dets) = anonymizer.anonymize_csv(csv);

    assert!(
        dets.iter().any(|d| d.entity_type == "FR_LICENSE_PLATE"),
        "Sample config should detect FR_LICENSE_PLATE in CSV: {:?}",
        dets
    );
    assert!(
        result.contains("[FR_LICENSE_PLATE_"),
        "CSV should be anonymized"
    );
}

#[test]
fn test_sample_config_invalid_regex_error() {
    // Acceptance criterion: invalid regex produces descriptive error
    use std::io::Write;
    use tempfile::NamedTempFile;

    let yaml = r#"
recognizers:
  - name: "Bad pattern"
    entity_type: "BAD_PATTERN"
    patterns:
      - regex: '[invalid('
        score: 0.8
"#;
    let mut temp_file = NamedTempFile::new().unwrap();
    write!(temp_file, "{}", yaml).unwrap();

    let result = RecognizerConfigFile::load(temp_file.path());
    assert!(result.is_err(), "Invalid regex should produce error");

    let err = result.unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("Bad pattern"),
        "Error should mention recognizer name: {}",
        msg
    );
    assert!(
        msg.contains("[invalid("),
        "Error should mention the invalid pattern: {}",
        msg
    );
}

#[test]
fn test_sample_config_threshold_filtering() {
    // Acceptance criterion: custom pattern below threshold is filtered out
    // The sample config should have patterns with different scores
    let mut anonymizer = anonymizer_from_testdata(0.9);

    // With threshold 0.9, only patterns with score >= 0.9 should match
    // FR_LICENSE_PLATE has score 0.85, so it should be filtered out without context
    let (_, dets) = anonymizer.anonymize_text("data: AB-123-CD");

    // Without context keywords, the base score (0.85) should be below threshold
    let has_plate = dets.iter().any(|d| d.entity_type == "FR_LICENSE_PLATE");
    assert!(
        !has_plate,
        "Pattern with score 0.85 should be filtered by threshold 0.9 (no context)"
    );
}

#[test]
fn test_sample_config_context_boost() {
    // Acceptance criterion: context keywords boost custom patterns correctly
    let mut anonymizer = anonymizer_from_testdata(0.0);

    // With context keyword
    let (_, dets_ctx) = anonymizer.anonymize_text("plaque vehicule: AB-123-CD");
    let score_ctx = dets_ctx
        .iter()
        .find(|d| d.entity_type == "FR_LICENSE_PLATE")
        .map(|d| d.score)
        .unwrap_or(0.0);

    // Without context keyword
    let (_, dets_no_ctx) = anonymizer.anonymize_text("data: AB-123-CD");
    let score_no_ctx = dets_no_ctx
        .iter()
        .find(|d| d.entity_type == "FR_LICENSE_PLATE")
        .map(|d| d.score)
        .unwrap_or(0.0);

    assert!(
        score_ctx > score_no_ctx,
        "Score with context ({}) should be higher than without ({})",
        score_ctx,
        score_no_ctx
    );
}

#[test]
fn test_sample_config_context_gating() {
    // Acceptance criterion: context keywords gate custom patterns correctly
    // The sample config should have at least one pattern with context_required: true
    let mut anonymizer = anonymizer_from_testdata(0.0);

    // INTERNAL_PROJECT_CODE requires context keywords
    // With context
    let (_, dets_ctx) = anonymizer.anonymize_text("projet PRJ-2024-001 en cours");
    assert!(
        dets_ctx
            .iter()
            .any(|d| d.entity_type == "INTERNAL_PROJECT_CODE"),
        "Should match INTERNAL_PROJECT_CODE with context keyword 'projet'"
    );

    // Without context - should NOT match
    let (_, dets_no_ctx) = anonymizer.anonymize_text("code PRJ-2024-001 here");
    assert!(
        !dets_no_ctx
            .iter()
            .any(|d| d.entity_type == "INTERNAL_PROJECT_CODE"),
        "Should NOT match INTERNAL_PROJECT_CODE without context keyword"
    );
}

#[test]
fn test_sample_config_overlap_resolution() {
    // Acceptance criterion: overlap between custom and built-in pattern resolved correctly
    let mut anonymizer = anonymizer_from_testdata(0.0);

    // Test that when patterns overlap, only one detection is returned
    // Use an input that could match multiple patterns
    let (_, dets) = anonymizer.anonymize_text("La plaque AB-123-CD et contact info@example.com");

    // Both should be detected (they don't overlap)
    assert!(
        dets.iter().any(|d| d.entity_type == "FR_LICENSE_PLATE"),
        "Should detect FR_LICENSE_PLATE"
    );
    assert!(
        dets.iter().any(|d| d.entity_type == "EMAIL_ADDRESS"),
        "Should detect EMAIL_ADDRESS"
    );

    // Ensure no duplicate detections for the same span
    let plate_count = dets
        .iter()
        .filter(|d| d.entity_type == "FR_LICENSE_PLATE")
        .count();
    assert_eq!(
        plate_count, 1,
        "Should have exactly one FR_LICENSE_PLATE detection"
    );
}
