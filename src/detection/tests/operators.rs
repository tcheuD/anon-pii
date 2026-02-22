use super::super::*;
use serde_json::Value;

// -- Operator tests --

#[test]
fn test_operator_token_default() {
    let mut a = Anonymizer::new(0.0);
    assert_eq!(a.operator, Operator::Token);
    let (result, dets) = a.anonymize_text("contact john@example.com");
    assert!(!result.contains("john@example.com"));
    assert!(result.contains("[EMAIL_ADDRESS_"));
    assert_eq!(dets.len(), 1);
}

#[test]
fn test_operator_redact_removes_pii() {
    let mut a = Anonymizer::new(0.0);
    a.operator = Operator::Redact;
    let (result, dets) = a.anonymize_text("contact john@example.com now");
    assert_eq!(result, "contact  now");
    assert!(!result.contains("john@example.com"));
    assert!(!result.contains("[EMAIL_ADDRESS"));
    assert_eq!(dets.len(), 1);
    assert_eq!(dets[0].entity_type, "EMAIL_ADDRESS");
}

#[test]
fn test_operator_keep_preserves_original() {
    let mut a = Anonymizer::new(0.0);
    a.operator = Operator::Keep;
    let input = "contact john@example.com now";
    let (result, dets) = a.anonymize_text(input);
    assert_eq!(result, input);
    assert_eq!(dets.len(), 1);
    assert_eq!(dets[0].entity_type, "EMAIL_ADDRESS");
}

#[test]
fn test_operator_redact_multiple_entities() {
    let mut a = Anonymizer::new(0.0);
    a.operator = Operator::Redact;
    let (result, dets) = a.anonymize_text("email: john@example.com, ip: 192.168.1.1");
    assert!(!result.contains("john@example.com"));
    assert!(!result.contains("192.168.1.1"));
    assert_eq!(result, "email: , ip: ");
    assert_eq!(dets.len(), 2);
}

#[test]
fn test_operator_keep_still_detects() {
    let mut a = Anonymizer::new(0.0);
    a.operator = Operator::Keep;
    let (_, dets) = a.anonymize_text("email: john@example.com, ip: 192.168.1.1");
    assert_eq!(dets.len(), 2);
    let types: Vec<&str> = dets.iter().map(|d| d.entity_type).collect();
    assert!(types.contains(&"EMAIL_ADDRESS"));
    assert!(types.contains(&"IP_ADDRESS"));
}

#[test]
fn test_operator_redact_no_mapping_entries() {
    let mut a = Anonymizer::new(0.0);
    a.operator = Operator::Redact;
    let _ = a.anonymize_text("john@example.com");
    assert!(a.mapping.mappings.is_empty());
}

#[test]
fn test_operator_keep_no_mapping_entries() {
    let mut a = Anonymizer::new(0.0);
    a.operator = Operator::Keep;
    let _ = a.anonymize_text("john@example.com");
    assert!(a.mapping.mappings.is_empty());
}

#[test]
fn test_operator_redact_json() {
    let mut a = Anonymizer::new(0.0);
    a.operator = Operator::Redact;
    let json: Value = serde_json::from_str(r#"{"email": "john@example.com"}"#).unwrap();
    let (result, dets) = a.anonymize_json_value(&json);
    assert_eq!(result["email"], "");
    assert_eq!(dets.len(), 1);
}

#[test]
fn test_operator_keep_json() {
    let mut a = Anonymizer::new(0.0);
    a.operator = Operator::Keep;
    let json: Value = serde_json::from_str(r#"{"email": "john@example.com"}"#).unwrap();
    let (result, dets) = a.anonymize_json_value(&json);
    assert_eq!(result["email"], "john@example.com");
    assert_eq!(dets.len(), 1);
}

#[test]
fn test_operator_mask_default() {
    let mut a = Anonymizer::new(0.0);
    a.operator = Operator::Mask;
    let (result, dets) = a.anonymize_text("contact john@example.com now");
    // "john@example.com" = 16 chars → 16 asterisks
    assert_eq!(result, "contact **************** now");
    assert_eq!(dets.len(), 1);
    assert_eq!(dets[0].entity_type, "EMAIL_ADDRESS");
}

#[test]
fn test_operator_mask_custom_char() {
    let mut a = Anonymizer::new(0.0);
    a.operator = Operator::Mask;
    a.mask_config.mask_char = '#';
    let (result, _) = a.anonymize_text("contact john@example.com now");
    assert_eq!(result, "contact ################ now");
}

#[test]
fn test_operator_mask_fixed_count() {
    let mut a = Anonymizer::new(0.0);
    a.operator = Operator::Mask;
    a.mask_config.fixed_count = Some(5);
    // "john@example.com" is 16 chars, mask 5 from start → 11 visible at end
    let (result, _) = a.anonymize_text("contact john@example.com now");
    assert_eq!(result, "contact *****example.com now");
}

#[test]
fn test_operator_mask_from_end() {
    let mut a = Anonymizer::new(0.0);
    a.operator = Operator::Mask;
    a.mask_config.fixed_count = Some(5);
    a.mask_config.from_end = true;
    // "john@example.com" is 16 chars, mask 5 from end → 11 visible at start
    let (result, _) = a.anonymize_text("contact john@example.com now");
    assert_eq!(result, "contact john@exampl***** now");
}

#[test]
fn test_operator_mask_full_length_default() {
    let mut a = Anonymizer::new(0.0);
    a.operator = Operator::Mask;
    let (result, _) = a.anonymize_text("192.168.1.1");
    assert_eq!(result, "***********");
    assert_eq!(result.len(), "192.168.1.1".len());
}

#[test]
fn test_operator_mask_no_mapping_entries() {
    let mut a = Anonymizer::new(0.0);
    a.operator = Operator::Mask;
    let _ = a.anonymize_text("john@example.com");
    assert!(a.mapping.mappings.is_empty());
}

#[test]
fn test_operator_mask_json() {
    let mut a = Anonymizer::new(0.0);
    a.operator = Operator::Mask;
    let json: Value = serde_json::from_str(r#"{"ip": "192.168.1.1"}"#).unwrap();
    let (result, dets) = a.anonymize_json_value(&json);
    assert_eq!(result["ip"], "***********");
    assert_eq!(dets.len(), 1);
}

#[test]
fn test_operator_mask_multiple_entities() {
    let mut a = Anonymizer::new(0.0);
    a.operator = Operator::Mask;
    let (result, dets) = a.anonymize_text("email: john@example.com, ip: 192.168.1.1");
    assert!(!result.contains("john@example.com"));
    assert!(!result.contains("192.168.1.1"));
    assert!(result.contains("****************")); // 16-char email mask
    assert!(result.contains("***********")); // 11-char IP mask
    assert_eq!(dets.len(), 2);
}

#[test]
fn test_apply_mask_fixed_count_exceeds_length() {
    let masked = apply_mask(
        "abc",
        &MaskConfig {
            mask_char: '*',
            fixed_count: Some(10),
            from_end: false,
        },
    );
    assert_eq!(masked, "***");
}

#[test]
fn test_apply_mask_zero_count() {
    let masked = apply_mask(
        "hello",
        &MaskConfig {
            mask_char: '*',
            fixed_count: Some(0),
            from_end: false,
        },
    );
    assert_eq!(masked, "hello");
}

// -- Hash operator tests --

#[test]
fn test_operator_hash_sha256() {
    let mut a = Anonymizer::new(0.0);
    a.operator = Operator::Hash;
    let (result, dets) = a.anonymize_text("contact john@example.com now");
    assert!(!result.contains("john@example.com"));
    assert!(!result.contains("[EMAIL_ADDRESS"));
    assert_eq!(dets.len(), 1);
    assert_eq!(dets[0].entity_type, "EMAIL_ADDRESS");
    // SHA-256 produces a 64-char hex string
    let hash_part = result.strip_prefix("contact ").unwrap();
    let hash_part = hash_part.strip_suffix(" now").unwrap();
    assert_eq!(hash_part.len(), 64);
    assert!(hash_part.chars().all(|c| c.is_ascii_hexdigit()));
}

#[test]
fn test_operator_hash_sha512() {
    let mut a = Anonymizer::new(0.0);
    a.operator = Operator::Hash;
    a.hash_algo = HashAlgo::Sha512;
    let (result, dets) = a.anonymize_text("contact john@example.com now");
    assert!(!result.contains("john@example.com"));
    assert_eq!(dets.len(), 1);
    let hash_part = result.strip_prefix("contact ").unwrap();
    let hash_part = hash_part.strip_suffix(" now").unwrap();
    // SHA-512 produces a 128-char hex string
    assert_eq!(hash_part.len(), 128);
    assert!(hash_part.chars().all(|c| c.is_ascii_hexdigit()));
}

#[test]
fn test_operator_hash_md5() {
    let mut a = Anonymizer::new(0.0);
    a.operator = Operator::Hash;
    a.hash_algo = HashAlgo::Md5;
    let (result, dets) = a.anonymize_text("contact john@example.com now");
    assert!(!result.contains("john@example.com"));
    assert_eq!(dets.len(), 1);
    let hash_part = result.strip_prefix("contact ").unwrap();
    let hash_part = hash_part.strip_suffix(" now").unwrap();
    // MD5 produces a 32-char hex string
    assert_eq!(hash_part.len(), 32);
    assert!(hash_part.chars().all(|c| c.is_ascii_hexdigit()));
}

#[test]
fn test_operator_hash_deterministic() {
    let mut a1 = Anonymizer::new(0.0);
    a1.operator = Operator::Hash;
    let (r1, _) = a1.anonymize_text("john@example.com");

    let mut a2 = Anonymizer::new(0.0);
    a2.operator = Operator::Hash;
    let (r2, _) = a2.anonymize_text("john@example.com");

    assert_eq!(r1, r2, "same input should produce same hash");
}

#[test]
fn test_operator_hash_different_inputs_differ() {
    let mut a = Anonymizer::new(0.0);
    a.operator = Operator::Hash;
    let (r1, _) = a.anonymize_text("john@example.com");
    let (r2, _) = a.anonymize_text("jane@example.com");
    assert_ne!(r1, r2);
}

#[test]
fn test_operator_hash_no_mapping_entries() {
    let mut a = Anonymizer::new(0.0);
    a.operator = Operator::Hash;
    let _ = a.anonymize_text("john@example.com");
    assert!(a.mapping.mappings.is_empty());
}

#[test]
fn test_operator_hash_json() {
    let mut a = Anonymizer::new(0.0);
    a.operator = Operator::Hash;
    let json: Value = serde_json::from_str(r#"{"email": "john@example.com"}"#).unwrap();
    let (result, dets) = a.anonymize_json_value(&json);
    let hashed = result["email"].as_str().unwrap();
    assert_eq!(hashed.len(), 64);
    assert!(hashed.chars().all(|c| c.is_ascii_hexdigit()));
    assert_eq!(dets.len(), 1);
}

#[test]
fn test_operator_hash_multiple_entities() {
    let mut a = Anonymizer::new(0.0);
    a.operator = Operator::Hash;
    let (result, dets) = a.anonymize_text("email: john@example.com, ip: 192.168.1.1");
    assert!(!result.contains("john@example.com"));
    assert!(!result.contains("192.168.1.1"));
    assert_eq!(dets.len(), 2);
}

#[test]
fn test_apply_hash_known_vectors() {
    // Verify against known SHA-256 hash of "test"
    let hash = apply_hash("test", HashAlgo::Sha256);
    assert_eq!(
        hash,
        "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
    );

    let hash = apply_hash("test", HashAlgo::Md5);
    assert_eq!(hash, "098f6bcd4621d373cade4e832627b4f6");
}

// -- Encrypt operator tests --

#[test]
fn test_operator_encrypt_replaces_pii() {
    let mut a = Anonymizer::new(0.0);
    a.operator = Operator::Encrypt;
    a.encrypt_key = Some(vec![0u8; 16]); // 128-bit zero key for testing
    let (result, dets) = a.anonymize_text("contact john@example.com now");
    assert!(!result.contains("john@example.com"));
    assert_eq!(dets.len(), 1);
    assert_eq!(dets[0].entity_type, "EMAIL_ADDRESS");
}

#[test]
fn test_operator_encrypt_output_format() {
    let mut a = Anonymizer::new(0.0);
    a.operator = Operator::Encrypt;
    a.encrypt_key = Some(vec![0u8; 16]);
    let (result, _) = a.anonymize_text("contact john@example.com now");
    assert!(result.starts_with("contact ENC["));
    assert!(result.ends_with("] now"));
    let inner = result
        .strip_prefix("contact ENC[")
        .unwrap()
        .strip_suffix("] now")
        .unwrap();
    assert!(inner.chars().all(|c| c.is_ascii_hexdigit()));
    assert!(inner.len() >= 64);
}

#[test]
fn test_operator_encrypt_roundtrip_aes128() {
    let key = vec![0x42u8; 16];
    let mut a = Anonymizer::new(0.0);
    a.operator = Operator::Encrypt;
    a.encrypt_key = Some(key.clone());
    let (encrypted, _) = a.anonymize_text("contact john@example.com now");
    let restored = decrypt_encrypted(&encrypted, &key);
    assert_eq!(restored, "contact john@example.com now");
}

#[test]
fn test_operator_encrypt_roundtrip_aes256() {
    let key = vec![0xABu8; 32];
    let mut a = Anonymizer::new(0.0);
    a.operator = Operator::Encrypt;
    a.encrypt_key = Some(key.clone());
    let (encrypted, _) = a.anonymize_text("192.168.1.1");
    let restored = decrypt_encrypted(&encrypted, &key);
    assert_eq!(restored, "192.168.1.1");
}

#[test]
fn test_operator_encrypt_nondeterministic() {
    let key = vec![0u8; 16];
    let mut a1 = Anonymizer::new(0.0);
    a1.operator = Operator::Encrypt;
    a1.encrypt_key = Some(key.clone());
    let (r1, _) = a1.anonymize_text("john@example.com");

    let mut a2 = Anonymizer::new(0.0);
    a2.operator = Operator::Encrypt;
    a2.encrypt_key = Some(key);
    let (r2, _) = a2.anonymize_text("john@example.com");

    assert_ne!(r1, r2);
}

#[test]
fn test_operator_encrypt_no_mapping_entries() {
    let mut a = Anonymizer::new(0.0);
    a.operator = Operator::Encrypt;
    a.encrypt_key = Some(vec![0u8; 16]);
    let _ = a.anonymize_text("john@example.com");
    assert!(a.mapping.mappings.is_empty());
}

#[test]
fn test_operator_encrypt_json() {
    let mut a = Anonymizer::new(0.0);
    a.operator = Operator::Encrypt;
    a.encrypt_key = Some(vec![0u8; 16]);
    let json: Value = serde_json::from_str(r#"{"email": "john@example.com"}"#).unwrap();
    let (result, dets) = a.anonymize_json_value(&json);
    assert!(!result.to_string().contains("john@example.com"));
    assert_eq!(dets.len(), 1);
}

#[test]
fn test_operator_encrypt_multiple_entities() {
    let mut a = Anonymizer::new(0.0);
    a.operator = Operator::Encrypt;
    a.encrypt_key = Some(vec![0u8; 32]);
    let (result, dets) = a.anonymize_text("email: john@example.com, ip: 192.168.1.1");
    assert!(!result.contains("john@example.com"));
    assert!(!result.contains("192.168.1.1"));
    assert_eq!(dets.len(), 2);
}

#[test]
fn test_operator_encrypt_roundtrip_aes192() {
    let key = vec![0x55u8; 24];
    let mut a = Anonymizer::new(0.0);
    a.operator = Operator::Encrypt;
    a.encrypt_key = Some(key.clone());
    let (encrypted, _) = a.anonymize_text("contact john@example.com now");
    let restored = decrypt_encrypted(&encrypted, &key);
    assert_eq!(restored, "contact john@example.com now");
}

// -- Decrypt tests --

#[test]
fn test_decrypt_encrypted_roundtrip() {
    let key = vec![0u8; 16];
    let mut a = Anonymizer::new(0.0);
    a.operator = Operator::Encrypt;
    a.encrypt_key = Some(key.clone());
    let (encrypted, _) = a.anonymize_text("email: john@example.com, ip: 192.168.1.1");
    let restored = decrypt_encrypted(&encrypted, &key);
    assert_eq!(restored, "email: john@example.com, ip: 192.168.1.1");
}

#[test]
fn test_decrypt_encrypted_preserves_non_encrypted_text() {
    let key = vec![0u8; 16];
    let input = "hello world, no encrypted data here";
    let result = decrypt_encrypted(input, &key);
    assert_eq!(result, input);
}

#[test]
fn test_decrypt_encrypted_wrong_key_preserves_token() {
    let key = vec![0u8; 16];
    let wrong_key = vec![0xFFu8; 16];
    let mut a = Anonymizer::new(0.0);
    a.operator = Operator::Encrypt;
    a.encrypt_key = Some(key);
    let (encrypted, _) = a.anonymize_text("john@example.com");
    let result = decrypt_encrypted(&encrypted, &wrong_key);
    // Wrong key → decryption fails → ENC[...] token preserved as-is
    assert!(result.starts_with("ENC["));
}

#[test]
fn test_decrypt_encrypted_json_roundtrip() {
    let key = vec![0u8; 32];
    let mut a = Anonymizer::new(0.0);
    a.operator = Operator::Encrypt;
    a.encrypt_key = Some(key.clone());
    let json: Value =
        serde_json::from_str(r#"{"email": "john@example.com", "ip": "10.0.0.1"}"#).unwrap();
    let (encrypted_json, _) = a.anonymize_json_value(&json);
    let encrypted_str = serde_json::to_string(&encrypted_json).unwrap();
    let restored = decrypt_encrypted(&encrypted_str, &key);
    assert!(restored.contains("john@example.com"));
    assert!(restored.contains("10.0.0.1"));
}

#[test]
fn test_parse_encrypt_key_valid_128() {
    let key = parse_encrypt_key("00112233445566778899aabbccddeeff").unwrap();
    assert_eq!(key.len(), 16);
    assert_eq!(key[0], 0x00);
    assert_eq!(key[15], 0xff);
}

#[test]
fn test_parse_encrypt_key_valid_256() {
    let hex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    let key = parse_encrypt_key(hex).unwrap();
    assert_eq!(key.len(), 32);
}

#[test]
fn test_parse_encrypt_key_invalid_length() {
    assert!(parse_encrypt_key("0011").is_err());
    assert!(parse_encrypt_key("").is_err());
}

#[test]
fn test_parse_encrypt_key_invalid_hex() {
    assert!(parse_encrypt_key("gghhiijjkkllmmnnooppqqrrssttuuvv").is_err());
}
