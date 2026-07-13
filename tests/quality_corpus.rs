#[path = "../examples/support/quality.rs"]
mod quality;

use std::path::PathBuf;

fn quality_paths() -> (PathBuf, PathBuf) {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    (
        root.join("testdata/quality/v1.json"),
        root.join("testdata/quality/v1-baseline.json"),
    )
}

#[test]
fn versioned_quality_corpus_meets_contract_and_ratcheted_baseline() {
    let (corpus_path, baseline_path) = quality_paths();
    let (corpus, corpus_sha256) = quality::load_corpus(&corpus_path).unwrap();
    quality::validate_corpus(&corpus).unwrap();

    let report = quality::evaluate(&corpus, corpus_sha256);
    quality::check_contract(&report).unwrap();
    assert_eq!(
        report.metrics.fp, 0,
        "quality-v1 must keep zero false positives across both tiers"
    );

    let baseline = quality::load_baseline(&baseline_path).unwrap();
    quality::check_baseline(&report, &baseline).unwrap();
}

#[test]
fn quality_corpus_is_large_and_balanced_enough_to_be_a_gate() {
    let (corpus_path, _) = quality_paths();
    let (corpus, _) = quality::load_corpus(&corpus_path).unwrap();
    quality::validate_corpus(&corpus).unwrap();

    let contract_cases = corpus
        .cases
        .iter()
        .filter(|case| case.tier == quality::Tier::Contract)
        .count();
    let challenge_cases = corpus
        .cases
        .iter()
        .filter(|case| case.tier == quality::Tier::Challenge)
        .count();
    let negative_cases = corpus
        .cases
        .iter()
        .filter(|case| case.expected.is_empty())
        .count();
    let categories: std::collections::BTreeSet<&str> = corpus
        .cases
        .iter()
        .map(|case| case.category.as_str())
        .collect();

    assert!(
        corpus.cases.len() >= 60,
        "quality-v1 needs at least 60 cases"
    );
    assert!(
        contract_cases >= 40,
        "quality-v1 needs at least 40 contract cases"
    );
    assert!(
        challenge_cases >= 15,
        "quality-v1 needs at least 15 challenge cases"
    );
    assert!(
        negative_cases >= 15,
        "quality-v1 needs adversarial negatives"
    );
    assert!(
        categories.len() >= 8,
        "quality-v1 needs broad debug-data coverage"
    );
}
