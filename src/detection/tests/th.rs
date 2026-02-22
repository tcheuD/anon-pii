use super::super::*;

// -- TH_TNIN tests --
// Note: test values start with 3+ to avoid FR_SSN pattern overlap ([12]...)

#[test]
fn test_th_tnin_with_context() {
    let mut a = Anonymizer::new(0.0);
    let (result, dets) = a.anonymize_text("Thai national ID: 3100912345997");
    assert!(
        dets.iter().any(|d| d.entity_type == "TH_TNIN"),
        "TH_TNIN not detected with context: {dets:?}"
    );
    assert!(!result.contains("3100912345997"));
    assert!(result.contains("[TH_TNIN_"));
}

#[test]
fn test_th_tnin_no_context_rejected() {
    let mut a = Anonymizer::new(0.0);
    let (_, dets) = a.anonymize_text("3100912345997");
    assert!(
        !dets.iter().any(|d| d.entity_type == "TH_TNIN"),
        "TH_TNIN should not match without context: {dets:?}"
    );
}

#[test]
fn test_th_tnin_bad_checksum_rejected() {
    let mut a = Anonymizer::new(0.0);
    let (_, dets) = a.anonymize_text("Thai citizen id: 3100912345990");
    assert!(
        !dets.iter().any(|d| d.entity_type == "TH_TNIN"),
        "TH_TNIN with bad checksum should be rejected: {dets:?}"
    );
}

#[test]
fn test_th_tnin_various_contexts() {
    let mut a = Anonymizer::new(0.0);
    let contexts = [
        "Thailand identification number 3100912345997",
        "TNIN: 3100912345997",
        "citizen id 3100912345997 for thai resident",
        "บัตรประชาชน 3100912345997",
    ];
    for ctx in &contexts {
        let (_, dets) = a.anonymize_text(ctx);
        assert!(
            dets.iter().any(|d| d.entity_type == "TH_TNIN"),
            "TH_TNIN not detected with context '{ctx}': {dets:?}"
        );
    }
}

#[test]
fn test_th_tnin_roundtrip() {
    let mut a = Anonymizer::new(0.0);
    let (result, _) = a.anonymize_text("Thai national ID: 3100912345997");
    assert!(!result.contains("3100912345997"));
    assert!(result.contains("[TH_TNIN_"));
}
