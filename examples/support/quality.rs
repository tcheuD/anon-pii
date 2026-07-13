use anon_pii::detection::Anonymizer;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

pub const SCORE_SCALE: u64 = 1_000_000;

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum Tier {
    Contract,
    Challenge,
}

impl Tier {
    fn label(self) -> &'static str {
        match self {
            Self::Contract => "contract",
            Self::Challenge => "challenge",
        }
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Profile {
    pub features: String,
    pub threshold: f64,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Corpus {
    pub schema_version: u32,
    pub corpus_version: String,
    pub profile: Profile,
    pub cases: Vec<Case>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Case {
    pub id: String,
    pub tier: Tier,
    pub category: String,
    pub input: String,
    pub expected: Vec<Span>,
    pub provenance: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(deny_unknown_fields)]
pub struct Span {
    pub entity_type: String,
    pub start: usize,
    pub end: usize,
    pub raw: String,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Metrics {
    pub tp: u64,
    pub fp: u64,
    #[serde(rename = "fn")]
    pub fn_count: u64,
    pub precision_ppm: Option<u64>,
    pub recall_ppm: Option<u64>,
}

impl Metrics {
    fn from_counts(tp: u64, fp: u64, fn_count: u64) -> Self {
        let precision_ppm = ratio_ppm(tp, tp + fp);
        let recall_ppm = ratio_ppm(tp, tp + fn_count);
        Self {
            tp,
            fp,
            fn_count,
            precision_ppm,
            recall_ppm,
        }
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct CaseReport {
    pub id: String,
    pub tier: Tier,
    pub category: String,
    pub expected: Vec<Span>,
    pub predicted: Vec<Span>,
    pub metrics: Metrics,
}

#[derive(Clone, Debug, Serialize)]
pub struct QualityReport {
    pub schema_version: u32,
    pub corpus_version: String,
    pub corpus_sha256: String,
    pub profile_features: String,
    pub threshold_ppm: u64,
    pub case_count: usize,
    pub expected_span_count: usize,
    pub metrics: Metrics,
    pub tiers: BTreeMap<String, Metrics>,
    pub categories: BTreeMap<String, Metrics>,
    pub entity_types: BTreeMap<String, Metrics>,
    pub cases: Vec<CaseReport>,
}

#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Gate {
    pub min_tp: u64,
    pub max_fp: u64,
    pub max_fn: u64,
    pub min_precision_ppm: Option<u64>,
    pub min_recall_ppm: Option<u64>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Baseline {
    pub schema_version: u32,
    pub corpus_version: String,
    pub corpus_sha256: String,
    pub metrics: Gate,
    pub tiers: BTreeMap<String, Gate>,
    pub categories: BTreeMap<String, Gate>,
    pub entity_types: BTreeMap<String, Gate>,
    pub case_exceptions: BTreeMap<String, Gate>,
}

pub fn load_corpus(path: &Path) -> Result<(Corpus, String), String> {
    let source = fs::read_to_string(path)
        .map_err(|error| format!("failed to read {}: {error}", path.display()))?;
    let corpus = serde_json::from_str(&source)
        .map_err(|error| format!("failed to parse {}: {error}", path.display()))?;
    Ok((corpus, sha256_hex(source.as_bytes())))
}

pub fn load_baseline(path: &Path) -> Result<Baseline, String> {
    let source = fs::read_to_string(path)
        .map_err(|error| format!("failed to read {}: {error}", path.display()))?;
    serde_json::from_str(&source)
        .map_err(|error| format!("failed to parse {}: {error}", path.display()))
}

pub fn validate_corpus(corpus: &Corpus) -> Result<(), String> {
    if corpus.schema_version != 1 {
        return Err(format!(
            "unsupported corpus schema version {}",
            corpus.schema_version
        ));
    }
    if corpus.corpus_version.trim().is_empty() {
        return Err("corpus_version must not be empty".to_string());
    }
    if corpus.profile.features != "default" {
        return Err(format!(
            "quality-v1 must use deterministic default features, found {:?}",
            corpus.profile.features
        ));
    }
    if !(0.0..=1.0).contains(&corpus.profile.threshold) {
        return Err("profile threshold must be between 0 and 1".to_string());
    }
    if corpus.cases.is_empty() {
        return Err("quality corpus must contain cases".to_string());
    }

    let mut ids = BTreeSet::new();
    let mut tiers = BTreeSet::new();
    for case in &corpus.cases {
        if !ids.insert(case.id.as_str()) {
            return Err(format!("duplicate case id {:?}", case.id));
        }
        if case.id.trim().is_empty()
            || case.category.trim().is_empty()
            || case.provenance.trim().is_empty()
        {
            return Err(format!(
                "case {:?} must have non-empty id, category, and provenance",
                case.id
            ));
        }
        tiers.insert(case.tier);

        let mut spans = BTreeSet::new();
        for expected in &case.expected {
            if expected.entity_type.trim().is_empty() || expected.start >= expected.end {
                return Err(format!(
                    "case {:?} has an invalid expected span: {expected:?}",
                    case.id
                ));
            }
            let actual = case
                .input
                .get(expected.start..expected.end)
                .ok_or_else(|| {
                    format!(
                        "case {:?} span {}..{} is out of bounds or not on UTF-8 boundaries",
                        case.id, expected.start, expected.end
                    )
                })?;
            if actual != expected.raw {
                return Err(format!(
                    "case {:?} labels {}..{} as {:?}, but the input contains {:?}",
                    case.id, expected.start, expected.end, expected.raw, actual
                ));
            }
            if !spans.insert(expected.clone()) {
                return Err(format!(
                    "case {:?} contains a duplicate expected span: {expected:?}",
                    case.id
                ));
            }
        }
    }

    if !tiers.contains(&Tier::Contract) || !tiers.contains(&Tier::Challenge) {
        return Err("quality corpus must contain contract and challenge tiers".to_string());
    }
    Ok(())
}

pub fn evaluate(corpus: &Corpus, corpus_sha256: String) -> QualityReport {
    let mut cases = Vec::with_capacity(corpus.cases.len());
    let mut total = Counts::default();
    let mut tiers: BTreeMap<String, Counts> = BTreeMap::new();
    let mut categories: BTreeMap<String, Counts> = BTreeMap::new();
    let mut entity_types: BTreeMap<String, Counts> = BTreeMap::new();

    for case in &corpus.cases {
        let mut anonymizer = Anonymizer::new(corpus.profile.threshold);
        let mut predicted: Vec<Span> = anonymizer
            .analyze(&case.input)
            .into_iter()
            .map(|detection| Span {
                entity_type: detection.entity_type.into_owned(),
                start: detection.start,
                end: detection.end,
                raw: detection.original,
            })
            .collect();
        predicted.sort();

        let mut expected = case.expected.clone();
        expected.sort();
        let counts = compare_multisets(&expected, &predicted);
        total.add(counts);
        tiers
            .entry(case.tier.label().to_string())
            .or_default()
            .add(counts);
        categories
            .entry(case.category.clone())
            .or_default()
            .add(counts);
        let case_entity_types: BTreeSet<&str> = expected
            .iter()
            .chain(&predicted)
            .map(|span| span.entity_type.as_str())
            .collect();
        for entity_type in case_entity_types {
            let expected_for_type: Vec<Span> = expected
                .iter()
                .filter(|span| span.entity_type == entity_type)
                .cloned()
                .collect();
            let predicted_for_type: Vec<Span> = predicted
                .iter()
                .filter(|span| span.entity_type == entity_type)
                .cloned()
                .collect();
            entity_types
                .entry(entity_type.to_string())
                .or_default()
                .add(compare_multisets(&expected_for_type, &predicted_for_type));
        }
        cases.push(CaseReport {
            id: case.id.clone(),
            tier: case.tier,
            category: case.category.clone(),
            expected,
            predicted,
            metrics: counts.metrics(),
        });
    }

    let expected_span_count = corpus.cases.iter().map(|case| case.expected.len()).sum();
    QualityReport {
        schema_version: corpus.schema_version,
        corpus_version: corpus.corpus_version.clone(),
        corpus_sha256,
        profile_features: corpus.profile.features.clone(),
        threshold_ppm: (corpus.profile.threshold * SCORE_SCALE as f64).round() as u64,
        case_count: corpus.cases.len(),
        expected_span_count,
        metrics: total.metrics(),
        tiers: tiers
            .into_iter()
            .map(|(key, value)| (key, value.metrics()))
            .collect(),
        categories: categories
            .into_iter()
            .map(|(key, value)| (key, value.metrics()))
            .collect(),
        entity_types: entity_types
            .into_iter()
            .map(|(key, value)| (key, value.metrics()))
            .collect(),
        cases,
    }
}

pub fn check_contract(report: &QualityReport) -> Result<(), String> {
    let contract = report
        .tiers
        .get("contract")
        .ok_or_else(|| "quality report has no contract tier".to_string())?;
    if contract.fp != 0 || contract.fn_count != 0 {
        let failing: Vec<&str> = report
            .cases
            .iter()
            .filter(|case| {
                case.tier == Tier::Contract && (case.metrics.fp != 0 || case.metrics.fn_count != 0)
            })
            .map(|case| case.id.as_str())
            .collect();
        return Err(format!(
            "contract tier must be exact; fp={}, fn={}, failing cases={failing:?}",
            contract.fp, contract.fn_count
        ));
    }
    Ok(())
}

pub fn check_baseline(report: &QualityReport, baseline: &Baseline) -> Result<(), String> {
    if baseline.schema_version != report.schema_version {
        return Err(format!(
            "baseline schema {} does not match report schema {}",
            baseline.schema_version, report.schema_version
        ));
    }
    if baseline.corpus_version != report.corpus_version {
        return Err(format!(
            "baseline corpus {:?} does not match report corpus {:?}",
            baseline.corpus_version, report.corpus_version
        ));
    }
    if baseline.corpus_sha256 != report.corpus_sha256 {
        return Err(format!(
            "baseline corpus hash {} does not match current corpus hash {}",
            baseline.corpus_sha256, report.corpus_sha256
        ));
    }

    check_gate("overall", report.metrics, baseline.metrics)?;
    check_group_gates("tier", &report.tiers, &baseline.tiers)?;
    check_group_gates("category", &report.categories, &baseline.categories)?;
    check_group_gates("entity type", &report.entity_types, &baseline.entity_types)?;
    check_case_gates(&report.cases, &baseline.case_exceptions)?;
    Ok(())
}

fn check_case_gates(
    cases: &[CaseReport],
    exceptions: &BTreeMap<String, Gate>,
) -> Result<(), String> {
    let case_ids: BTreeSet<&str> = cases.iter().map(|case| case.id.as_str()).collect();
    let exception_ids: BTreeSet<&str> = exceptions.keys().map(String::as_str).collect();
    if !exception_ids.is_subset(&case_ids) {
        return Err(format!(
            "case exception ids {exception_ids:?} are not a subset of report ids {case_ids:?}"
        ));
    }

    for case in cases {
        if let Some(gate) = exceptions.get(&case.id) {
            check_gate(&format!("case {:?}", case.id), case.metrics, *gate)?;
        } else if case.metrics.fp != 0 || case.metrics.fn_count != 0 {
            return Err(format!(
                "case {:?} regressed outside the reviewed exception list: {:?}",
                case.id, case.metrics
            ));
        }
    }
    Ok(())
}

fn check_group_gates(
    kind: &str,
    actual: &BTreeMap<String, Metrics>,
    gates: &BTreeMap<String, Gate>,
) -> Result<(), String> {
    let actual_names: BTreeSet<&str> = actual.keys().map(String::as_str).collect();
    let gate_names: BTreeSet<&str> = gates.keys().map(String::as_str).collect();
    if actual_names != gate_names {
        return Err(format!(
            "{kind} baseline keys {gate_names:?} do not match report keys {actual_names:?}"
        ));
    }
    for (name, gate) in gates {
        check_gate(
            &format!("{kind} {name:?}"),
            *actual.get(name).expect("checked identical key sets"),
            *gate,
        )?;
    }
    Ok(())
}

fn check_gate(label: &str, actual: Metrics, gate: Gate) -> Result<(), String> {
    let precision_regressed = gate
        .min_precision_ppm
        .is_some_and(|minimum| actual.precision_ppm.is_none_or(|value| value < minimum));
    let recall_regressed = gate
        .min_recall_ppm
        .is_some_and(|minimum| actual.recall_ppm.is_none_or(|value| value < minimum));
    if actual.tp < gate.min_tp
        || actual.fp > gate.max_fp
        || actual.fn_count > gate.max_fn
        || precision_regressed
        || recall_regressed
    {
        return Err(format!(
            "{label} regressed: actual={actual:?}, required={gate:?}"
        ));
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Default)]
struct Counts {
    tp: u64,
    fp: u64,
    fn_count: u64,
}

impl Counts {
    fn add(&mut self, other: Self) {
        self.tp += other.tp;
        self.fp += other.fp;
        self.fn_count += other.fn_count;
    }

    fn metrics(self) -> Metrics {
        Metrics::from_counts(self.tp, self.fp, self.fn_count)
    }
}

fn compare_multisets(expected: &[Span], predicted: &[Span]) -> Counts {
    let expected = frequencies(expected);
    let predicted = frequencies(predicted);
    let keys: BTreeSet<&Span> = expected.keys().chain(predicted.keys()).collect();
    let mut counts = Counts::default();
    for key in keys {
        let expected_count = expected.get(key).copied().unwrap_or(0);
        let predicted_count = predicted.get(key).copied().unwrap_or(0);
        counts.tp += expected_count.min(predicted_count);
        counts.fp += predicted_count.saturating_sub(expected_count);
        counts.fn_count += expected_count.saturating_sub(predicted_count);
    }
    counts
}

fn frequencies(spans: &[Span]) -> BTreeMap<Span, u64> {
    let mut frequencies = BTreeMap::new();
    for span in spans {
        *frequencies.entry(span.clone()).or_insert(0) += 1;
    }
    frequencies
}

fn ratio_ppm(numerator: u64, denominator: u64) -> Option<u64> {
    if denominator == 0 {
        None
    } else {
        Some(numerator.saturating_mul(SCORE_SCALE) / denominator)
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn span(entity_type: &str, start: usize, end: usize, raw: &str) -> Span {
        Span {
            entity_type: entity_type.to_string(),
            start,
            end,
            raw: raw.to_string(),
        }
    }

    #[test]
    fn multiset_comparison_counts_duplicate_predictions_as_false_positives() {
        let expected = vec![span("EMAIL_ADDRESS", 0, 15, "ada@example.com")];
        let predicted = vec![expected[0].clone(), expected[0].clone()];

        let metrics = compare_multisets(&expected, &predicted).metrics();

        assert_eq!(metrics.tp, 1);
        assert_eq!(metrics.fp, 1);
        assert_eq!(metrics.fn_count, 0);
    }

    #[test]
    fn exact_span_or_type_mismatches_count_as_both_fp_and_fn() {
        let expected = vec![span("EMAIL_ADDRESS", 0, 15, "ada@example.com")];
        let predicted = vec![span("URL", 0, 15, "ada@example.com")];

        let metrics = compare_multisets(&expected, &predicted).metrics();

        assert_eq!(metrics.tp, 0);
        assert_eq!(metrics.fp, 1);
        assert_eq!(metrics.fn_count, 1);
    }

    #[test]
    fn empty_expected_and_predicted_sets_have_undefined_rates() {
        let metrics = compare_multisets(&[], &[]).metrics();

        assert_eq!(metrics.precision_ppm, None);
        assert_eq!(metrics.recall_ppm, None);
    }

    #[test]
    fn corpus_schema_rejects_a_misspelled_expected_field() {
        let source = r#"{
            "schema_version": 1,
            "corpus_version": "typo-test",
            "profile": {"features": "default", "threshold": 0.5},
            "cases": [{
                "id": "email",
                "tier": "contract",
                "category": "contact",
                "input": "ada@example.com",
                "expectd": [],
                "provenance": "synthetic"
            }]
        }"#;

        let error = serde_json::from_str::<Corpus>(source).unwrap_err();
        assert!(error.to_string().contains("expectd"));
    }

    #[test]
    fn unreviewed_case_misses_cannot_hide_behind_an_exception_improvement() {
        let exact = Metrics::from_counts(1, 0, 0);
        let missed = Metrics::from_counts(0, 0, 1);
        let cases = vec![
            CaseReport {
                id: "reviewed-miss".to_string(),
                tier: Tier::Challenge,
                category: "contact".to_string(),
                expected: Vec::new(),
                predicted: Vec::new(),
                metrics: exact,
            },
            CaseReport {
                id: "previously-exact".to_string(),
                tier: Tier::Challenge,
                category: "contact".to_string(),
                expected: Vec::new(),
                predicted: Vec::new(),
                metrics: missed,
            },
        ];
        let exceptions = BTreeMap::from([(
            "reviewed-miss".to_string(),
            Gate {
                min_tp: 0,
                max_fp: 0,
                max_fn: 1,
                min_precision_ppm: None,
                min_recall_ppm: Some(0),
            },
        )]);

        let error = check_case_gates(&cases, &exceptions).unwrap_err();
        assert!(error.contains("previously-exact"));
    }
}
