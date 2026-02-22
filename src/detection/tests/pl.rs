use super::super::*;

// -- PL_PESEL tests --

#[test]
fn test_pl_pesel_with_context() {
    let mut a = Anonymizer::new(0.0);
    let (result, dets) = a.anonymize_text("PESEL: 44051401359");
    assert!(
        dets.iter().any(|d| d.entity_type == "PL_PESEL"),
        "PL_PESEL not detected with context: {dets:?}"
    );
    assert!(!result.contains("44051401359"));
    assert!(result.contains("[PL_PESEL_"));
}

#[test]
fn test_pl_pesel_no_context_rejected() {
    let mut a = Anonymizer::new(0.0);
    let (_, dets) = a.anonymize_text("44051401359");
    assert!(
        !dets.iter().any(|d| d.entity_type == "PL_PESEL"),
        "PL_PESEL should not match without context: {dets:?}"
    );
}

#[test]
fn test_pl_pesel_bad_checksum_rejected() {
    let mut a = Anonymizer::new(0.0);
    let (_, dets) = a.anonymize_text("PESEL: 44051401358");
    assert!(
        !dets.iter().any(|d| d.entity_type == "PL_PESEL"),
        "PL_PESEL with bad checksum should be rejected: {dets:?}"
    );
}

#[test]
fn test_pl_pesel_various_contexts() {
    let mut a = Anonymizer::new(0.0);
    let contexts = [
        "Nr PESEL: 44051401359",
        "Numer PESEL: 44051401359",
        "Polish ID: 44051401359",
        "identyfikator: 44051401359",
    ];
    for ctx in &contexts {
        let (_, dets) = a.anonymize_text(ctx);
        assert!(
            dets.iter().any(|d| d.entity_type == "PL_PESEL"),
            "PL_PESEL not detected with context '{ctx}': {dets:?}"
        );
    }
}

#[test]
fn test_pl_pesel_roundtrip() {
    let mut a = Anonymizer::new(0.0);
    let (result, _) = a.anonymize_text("PESEL: 44051401359");
    assert!(!result.contains("44051401359"));
    assert!(result.contains("[PL_PESEL_"));
}

#[test]
fn test_pl_pesel_2000s_century() {
    let mut a = Anonymizer::new(0.0);
    // Born 2002-01-13 (month 21 = January 2000s)
    let (_, dets) = a.anonymize_text("PESEL: 02211307589");
    assert!(
        dets.iter().any(|d| d.entity_type == "PL_PESEL"),
        "PL_PESEL with 2000s century encoding not detected: {dets:?}"
    );
}
