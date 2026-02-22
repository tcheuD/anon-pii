use super::super::*;

// -- MAC_ADDRESS tests --

#[test]
fn test_mac_address_colon() {
    let mut a = Anonymizer::new(0.0);
    let (result, dets) = a.anonymize_text("device mac 00:1A:2B:3C:4D:5E");
    assert!(
        dets.iter().any(|d| d.entity_type == "MAC_ADDRESS"),
        "colon MAC not detected: {dets:?}"
    );
    assert!(result.contains("[MAC_ADDRESS_"));
}

#[test]
fn test_mac_address_hyphen() {
    let mut a = Anonymizer::new(0.0);
    let (result, dets) = a.anonymize_text("mac address 00-1A-2B-3C-4D-5E");
    assert!(
        dets.iter().any(|d| d.entity_type == "MAC_ADDRESS"),
        "hyphen MAC not detected: {dets:?}"
    );
    assert!(result.contains("[MAC_ADDRESS_"));
}

#[test]
fn test_mac_address_cisco_dot() {
    let mut a = Anonymizer::new(0.0);
    let (result, dets) = a.anonymize_text("interface mac 001a.2b3c.4d5e");
    assert!(
        dets.iter().any(|d| d.entity_type == "MAC_ADDRESS"),
        "Cisco dot MAC not detected: {dets:?}"
    );
    assert!(result.contains("[MAC_ADDRESS_"));
}

#[test]
fn test_mac_address_broadcast_rejected() {
    let mut a = Anonymizer::new(0.0);
    let (_, dets) = a.anonymize_text("mac ff:ff:ff:ff:ff:ff");
    assert!(
        !dets.iter().any(|d| d.entity_type == "MAC_ADDRESS"),
        "broadcast MAC should be rejected: {dets:?}"
    );
}

#[test]
fn test_mac_address_null_rejected() {
    let mut a = Anonymizer::new(0.0);
    let (_, dets) = a.anonymize_text("mac 00:00:00:00:00:00");
    assert!(
        !dets.iter().any(|d| d.entity_type == "MAC_ADDRESS"),
        "null MAC should be rejected: {dets:?}"
    );
}

#[test]
fn test_mac_address_lowercase() {
    let mut a = Anonymizer::new(0.0);
    let (result, dets) = a.anonymize_text("device mac aa:bb:cc:dd:ee:11");
    assert!(
        dets.iter().any(|d| d.entity_type == "MAC_ADDRESS"),
        "lowercase MAC not detected: {dets:?}"
    );
    assert!(result.contains("[MAC_ADDRESS_"));
}

#[test]
fn test_mac_address_mixed_case() {
    let mut a = Anonymizer::new(0.0);
    let (result, dets) = a.anonymize_text("device 0A:1b:2C:3d:4E:5f online");
    assert!(
        dets.iter().any(|d| d.entity_type == "MAC_ADDRESS"),
        "mixed-case MAC not detected: {dets:?}"
    );
    assert!(result.contains("[MAC_ADDRESS_"));
}

#[test]
fn test_mac_address_cisco_uppercase() {
    let mut a = Anonymizer::new(0.0);
    let (result, dets) = a.anonymize_text("interface AABB.CCDD.EEFF");
    assert!(
        dets.iter().any(|d| d.entity_type == "MAC_ADDRESS"),
        "uppercase Cisco MAC not detected: {dets:?}"
    );
    assert!(result.contains("[MAC_ADDRESS_"));
}

#[test]
fn test_mac_address_near_broadcast_still_detected() {
    let mut a = Anonymizer::new(0.0);
    // ff:ff:ff:ff:ff:fe — one bit off from broadcast, should be valid
    let (result, dets) = a.anonymize_text("device ff:ff:ff:ff:ff:fe connected");
    assert!(
        dets.iter().any(|d| d.entity_type == "MAC_ADDRESS"),
        "near-broadcast MAC should be valid: {dets:?}"
    );
    assert!(result.contains("[MAC_ADDRESS_"));
}

#[test]
fn test_mac_address_broadcast_cisco_rejected() {
    let mut a = Anonymizer::new(0.0);
    let (_, dets) = a.anonymize_text("broadcast ffff.ffff.ffff");
    assert!(
        !dets.iter().any(|d| d.entity_type == "MAC_ADDRESS"),
        "Cisco broadcast MAC should be rejected: {dets:?}"
    );
}

#[test]
fn test_mac_address_null_hyphen_rejected() {
    let mut a = Anonymizer::new(0.0);
    let (_, dets) = a.anonymize_text("empty 00-00-00-00-00-00 address");
    assert!(
        !dets.iter().any(|d| d.entity_type == "MAC_ADDRESS"),
        "null hyphen MAC should be rejected: {dets:?}"
    );
}

#[test]
fn test_mac_address_null_cisco_rejected() {
    let mut a = Anonymizer::new(0.0);
    let (_, dets) = a.anonymize_text("default 0000.0000.0000");
    assert!(
        !dets.iter().any(|d| d.entity_type == "MAC_ADDRESS"),
        "null Cisco MAC should be rejected: {dets:?}"
    );
}

#[test]
fn test_mac_address_in_json_log() {
    let mut a = Anonymizer::new(0.0);
    let input = r#"{"device_mac": "AB:CD:EF:01:23:45", "status": "online"}"#;
    let (result, dets) = a.anonymize_text(input);
    assert!(
        dets.iter().any(|d| d.entity_type == "MAC_ADDRESS"),
        "MAC in JSON should be detected: {dets:?}"
    );
    assert!(!result.contains("AB:CD:EF:01:23:45"));
}

#[test]
fn test_mac_address_consistency() {
    let mut a = Anonymizer::new(0.0);
    let (_result, _) = a.anonymize_text("device 0A:1B:2C:3D:4E:5F and again 0A:1B:2C:3D:4E:5F");
    let tokens: Vec<_> = a
        .mapping
        .mappings
        .keys()
        .filter(|k| k.starts_with("[MAC_ADDRESS_"))
        .collect();
    assert_eq!(tokens.len(), 1, "same MAC should map to one token");
}

#[test]
fn test_mac_address_not_confused_with_ipv6() {
    let mut a = Anonymizer::new(0.0);
    // Full IPv6 should be IP_ADDRESS, not MAC_ADDRESS
    let (_, dets) = a.anonymize_text("host 2001:0db8:85a3:0000:0000:8a2e:0370:7334");
    let mac_dets: Vec<_> = dets
        .iter()
        .filter(|d| d.entity_type == "MAC_ADDRESS")
        .collect();
    assert!(
        mac_dets.is_empty(),
        "IPv6 address should not be detected as MAC: {mac_dets:?}"
    );
}
