use super::super::*;

// -- CRYPTO tests --

#[test]
fn test_crypto_ethereum() {
    let mut a = Anonymizer::new(0.0);
    let (result, dets) = a.anonymize_text("wallet: 0x742d35Cc6634C0532925a3b844Bc9e7595f2bD18");
    assert!(dets.iter().any(|d| d.entity_type == "CRYPTO"));
    assert!(result.contains("[CRYPTO_"));
}

// -- UUID tests --

#[test]
fn test_uuid() {
    let mut a = Anonymizer::new(0.0);
    let (result, _) = a.anonymize_text("id: 550e8400-e29b-41d4-a716-446655440000");
    assert!(result.contains("[UUID_"));
}
