use super::super::*;

// -- JSON tests --

#[test]
fn test_json_processing() {
    let mut a = Anonymizer::new(0.0);
    let json = serde_json::json!({
        "email": "john@example.com",
        "count": 42,
        "active": true,
        "nested": {
            "phone": "+33 6 12 34 56 78"
        }
    });
    let (result, dets) = a.anonymize_json_value(&json);
    assert_eq!(dets.len(), 2);
    assert_eq!(result["count"], 42);
    assert_eq!(result["active"], true);
    assert!(
        result["email"]
            .as_str()
            .unwrap()
            .contains("[EMAIL_ADDRESS_")
    );
    assert!(
        result["nested"]["phone"]
            .as_str()
            .unwrap()
            .contains("[FR_PHONE_NUMBER_")
    );
}

#[test]
fn test_walk_json_depth_limit_no_crash() {
    // Build a JSON value nested beyond MAX_JSON_DEPTH (128).
    // Without the depth limit this would stack overflow.
    let mut value = serde_json::json!("leaf@example.com");
    for _ in 0..200 {
        value = serde_json::json!({ "n": value });
    }

    let mut a = Anonymizer::new(0.0);
    let (result, _) = a.anonymize_json_value(&value);

    // Structure should be preserved — no crash
    assert!(result.is_object());

    // Values within the depth limit should be anonymized
    // Navigate to depth 50 (well within limit)
    let mut cursor = &result;
    for _ in 0..50 {
        cursor = &cursor["n"];
    }
    assert!(cursor.is_object() || cursor.is_string());
}

#[test]
fn test_walk_json_within_limit_anonymized() {
    // Nesting within the limit — PII should be anonymized
    let value = serde_json::json!({
        "a": { "b": { "c": "john@example.com" } }
    });
    let mut a = Anonymizer::new(0.0);
    let (result, dets) = a.anonymize_json_value(&value);

    assert_eq!(dets.len(), 1);
    assert!(
        result["a"]["b"]["c"]
            .as_str()
            .unwrap()
            .starts_with("[EMAIL_ADDRESS_")
    );
}

#[test]
fn test_walk_json_beyond_limit_not_anonymized() {
    // Build nesting at exactly MAX_JSON_DEPTH (128) — the leaf should
    // be returned as-is (cloned, not anonymized).
    let mut value = serde_json::json!("deep@example.com");
    for _ in 0..130 {
        value = serde_json::json!({ "n": value });
    }

    let mut a = Anonymizer::new(0.0);
    let (result, _) = a.anonymize_json_value(&value);

    // Navigate to the deepest leaf
    let mut cursor = &result;
    for _ in 0..130 {
        cursor = &cursor["n"];
    }
    // Beyond depth 128, the value is cloned as-is (not anonymized)
    assert_eq!(cursor.as_str().unwrap(), "deep@example.com");
}

#[test]
fn test_json_with_phase1_entities() {
    let mut a = Anonymizer::new(0.0);
    let json = serde_json::json!({
        "timestamp": "2024-01-15T14:30:00Z",
        "device_mac": "AB:CD:EF:01:23:45",
        "client_ip": "192.168.1.100",
        "iban": "iban DE89370400440532013000",
        "contact": "tel +44 20 7946 0958"
    });
    let (result, dets) = a.anonymize_json_value(&json);
    assert!(
        dets.iter().any(|d| d.entity_type == "DATE_TIME"),
        "JSON timestamp not detected: {dets:?}"
    );
    assert!(
        dets.iter().any(|d| d.entity_type == "MAC_ADDRESS"),
        "JSON MAC not detected: {dets:?}"
    );
    assert!(
        dets.iter().any(|d| d.entity_type == "IP_ADDRESS"),
        "JSON IP not detected: {dets:?}"
    );
    assert!(
        result["device_mac"]
            .as_str()
            .unwrap()
            .contains("[MAC_ADDRESS_")
    );
}
