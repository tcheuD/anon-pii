#[path = "../examples/support/quality.rs"]
mod quality;

use std::fs;
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
    let expected_span_count: usize = corpus.cases.iter().map(|case| case.expected.len()).sum();
    let expected_entity_types: std::collections::BTreeSet<&str> = corpus
        .cases
        .iter()
        .flat_map(|case| case.expected.iter())
        .map(|span| span.entity_type.as_str())
        .collect();

    assert!(
        corpus.cases.len() >= 62,
        "quality-v1 needs at least 62 cases"
    );
    assert!(
        contract_cases >= 46,
        "quality-v1 needs at least 46 contract cases"
    );
    assert!(
        challenge_cases >= 15,
        "quality-v1 needs at least 15 challenge cases"
    );
    assert!(
        negative_cases >= 18,
        "quality-v1 needs adversarial negatives"
    );
    assert!(
        categories.len() >= 8,
        "quality-v1 needs broad debug-data coverage"
    );

    assert!(
        expected_span_count >= 46,
        "quality-v1 needs at least 46 explicitly annotated spans"
    );
    assert!(
        expected_entity_types.len() >= 16,
        "quality-v1 needs broad entity-type coverage"
    );
}

#[test]
fn published_quality_claim_matches_the_generated_report() {
    let (corpus_path, _) = quality_paths();
    let (corpus, corpus_sha256) = quality::load_corpus(&corpus_path).unwrap();
    quality::validate_corpus(&corpus).unwrap();
    let report = quality::evaluate(&corpus, corpus_sha256.clone());
    let quality_doc =
        fs::read_to_string(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("docs/quality.md"))
            .unwrap();

    assert!(quality_doc.contains(&corpus_sha256));
    assert!(quality_doc.contains(&format!(
        "contains {} fictional cases, {} annotated exact spans",
        report.case_count, report.expected_span_count
    )));
    assert!(quality_doc.contains(&format!(
        "{} TP, {} FP, and {} FN",
        report.metrics.tp, report.metrics.fp, report.metrics.fn_count
    )));
    assert!(quality_doc.contains(&format!(
        "{:.4}% measured precision and {:.4}% measured recall",
        report.metrics.precision_ppm.unwrap() as f64 / 10_000.0,
        report.metrics.recall_ppm.unwrap() as f64 / 10_000.0
    )));
    assert!(quality_doc.contains("1a22680e43b29c80e141a39b0a66eb3dcafb7522"));
}
