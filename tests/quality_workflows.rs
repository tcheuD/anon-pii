use anon_pii::detection::{Anonymizer, Detection};
use anon_pii::mapping::Mapping;
use serde::Deserialize;
use serde_json::Value;
use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

#[derive(Debug, Deserialize)]
struct WorkflowCorpus {
    schema_version: u32,
    corpus_version: String,
    threshold: f64,
    cases: Vec<WorkflowCase>,
}

#[derive(Debug, Deserialize)]
struct WorkflowCase {
    id: String,
    format: WorkflowFormat,
    input: String,
    expected_entity_types: Vec<String>,
    expected_mapping_entries: usize,
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
enum WorkflowFormat {
    Text,
    Json,
    Csv,
    Sql,
    Restore,
}

fn load_workflows() -> WorkflowCorpus {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("testdata/quality/workflows-v1.json");
    let source = fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("failed to read {}: {error}", path.display()));
    serde_json::from_str(&source)
        .unwrap_or_else(|error| panic!("failed to parse {}: {error}", path.display()))
}

#[test]
fn versioned_workflows_roundtrip_without_structural_loss() {
    let corpus = load_workflows();
    assert_eq!(corpus.schema_version, 1);
    assert_eq!(corpus.corpus_version, "debug-workflows-v1");
    assert!((0.0..=1.0).contains(&corpus.threshold));

    for case in &corpus.cases {
        if case.format == WorkflowFormat::Restore {
            let mapping = Mapping::new();
            let (restored, count) = mapping.restore_bracketed_with_count(&case.input);
            assert_eq!(restored, case.input, "{} changed unknown tokens", case.id);
            assert_eq!(count, 0, "{} reported a false restoration", case.id);
            assert!(case.expected_entity_types.is_empty());
            assert_eq!(case.expected_mapping_entries, 0);
            continue;
        }

        let mut anonymizer = Anonymizer::new(corpus.threshold);
        let detections = match case.format {
            WorkflowFormat::Text => {
                let (anonymized, detections) = anonymizer.anonymize_text(&case.input);
                assert_eq!(
                    anonymizer.mapping.restore_bracketed(&anonymized),
                    case.input,
                    "{} did not restore byte-exact text",
                    case.id
                );
                detections
            }
            WorkflowFormat::Csv => {
                let (anonymized, detections) = anonymizer.anonymize_csv(&case.input);
                assert_eq!(
                    anonymizer.mapping.restore_bracketed(&anonymized),
                    case.input,
                    "{} did not restore byte-exact CSV",
                    case.id
                );
                detections
            }
            WorkflowFormat::Sql => {
                let (anonymized, detections) = anonymizer.anonymize_sql(&case.input);
                assert_eq!(
                    anonymizer.mapping.restore_bracketed(&anonymized),
                    case.input,
                    "{} did not restore byte-exact SQL",
                    case.id
                );
                detections
            }
            WorkflowFormat::Json => {
                let original: Value = serde_json::from_str(&case.input)
                    .unwrap_or_else(|error| panic!("{} has invalid JSON: {error}", case.id));
                let original_keys = json_keys(&original);
                let original_non_strings = json_non_string_leaves(&original);
                let (anonymized, detections) = anonymizer.anonymize_json_value(&original);

                assert_eq!(
                    json_keys(&anonymized),
                    original_keys,
                    "{} changed JSON object keys",
                    case.id
                );
                assert_eq!(
                    json_non_string_leaves(&anonymized),
                    original_non_strings,
                    "{} changed JSON non-string values",
                    case.id
                );
                assert_eq!(
                    restore_json_strings(&anonymized, &anonymizer.mapping),
                    original,
                    "{} did not restore semantically equivalent JSON",
                    case.id
                );
                detections
            }
            WorkflowFormat::Restore => unreachable!("restore handled before anonymizer setup"),
        };

        let mut actual_types = detection_types(&detections);
        let mut expected_types = case.expected_entity_types.clone();
        actual_types.sort();
        expected_types.sort();
        assert_eq!(
            actual_types, expected_types,
            "{} reported the wrong detection multiset",
            case.id
        );
        assert_eq!(
            anonymizer.mapping.mappings.len(),
            case.expected_mapping_entries,
            "{} produced an unexpected mapping cardinality",
            case.id
        );
        assert_eq!(
            anonymizer.mapping.evicted_count(),
            0,
            "{} lost a mapping entry",
            case.id
        );
    }
}

#[test]
fn workflow_schema_covers_each_supported_debug_format() {
    let corpus = load_workflows();
    let ids: BTreeSet<&str> = corpus.cases.iter().map(|case| case.id.as_str()).collect();
    let formats: BTreeSet<WorkflowFormat> = corpus.cases.iter().map(|case| case.format).collect();

    assert_eq!(ids.len(), corpus.cases.len(), "workflow ids must be unique");
    assert!(
        corpus.cases.len() >= 8,
        "workflow-v1 needs at least eight cases"
    );
    assert_eq!(
        formats,
        BTreeSet::from([
            WorkflowFormat::Text,
            WorkflowFormat::Json,
            WorkflowFormat::Csv,
            WorkflowFormat::Sql,
            WorkflowFormat::Restore,
        ])
    );
}

#[test]
fn known_tokens_restore_without_touching_unknown_or_malformed_tokens() {
    let mut mapping = Mapping::new();
    let known = mapping.add("EMAIL_ADDRESS", "ada@example.com");
    let response =
        format!("Known {known}; unknown [EMAIL_ADDRESS_deadbeef]; malformed [EMAIL_ADDRESS_open");
    let (restored, count) = mapping.restore_bracketed_with_count(&response);

    assert_eq!(
        restored,
        "Known ada@example.com; unknown [EMAIL_ADDRESS_deadbeef]; malformed [EMAIL_ADDRESS_open"
    );
    assert_eq!(count, 1);
}

fn detection_types(detections: &[Detection]) -> Vec<String> {
    detections
        .iter()
        .map(|detection| detection.entity_type.to_string())
        .collect()
}

fn restore_json_strings(value: &Value, mapping: &Mapping) -> Value {
    match value {
        Value::String(value) => Value::String(mapping.restore_bracketed(value)),
        Value::Array(values) => Value::Array(
            values
                .iter()
                .map(|value| restore_json_strings(value, mapping))
                .collect(),
        ),
        Value::Object(values) => Value::Object(
            values
                .iter()
                .map(|(key, value)| (key.clone(), restore_json_strings(value, mapping)))
                .collect(),
        ),
        other => other.clone(),
    }
}

fn json_keys(value: &Value) -> BTreeSet<String> {
    fn walk(value: &Value, path: &str, output: &mut BTreeSet<String>) {
        match value {
            Value::Object(values) => {
                for (key, value) in values {
                    let child = format!("{path}/{key}");
                    output.insert(child.clone());
                    walk(value, &child, output);
                }
            }
            Value::Array(values) => {
                for (index, value) in values.iter().enumerate() {
                    walk(value, &format!("{path}/{index}"), output);
                }
            }
            _ => {}
        }
    }

    let mut output = BTreeSet::new();
    walk(value, "", &mut output);
    output
}

fn json_non_string_leaves(value: &Value) -> BTreeSet<(String, String)> {
    fn walk(value: &Value, path: &str, output: &mut BTreeSet<(String, String)>) {
        match value {
            Value::Object(values) => {
                for (key, value) in values {
                    walk(value, &format!("{path}/{key}"), output);
                }
            }
            Value::Array(values) => {
                for (index, value) in values.iter().enumerate() {
                    walk(value, &format!("{path}/{index}"), output);
                }
            }
            Value::String(_) => {}
            other => {
                output.insert((path.to_string(), other.to_string()));
            }
        }
    }

    let mut output = BTreeSet::new();
    walk(value, "", &mut output);
    output
}
