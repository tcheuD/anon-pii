use anon_pii::mapping::Mapping;
use std::fs;
use std::process::Command;

const LEGACY_MAPPING_JSON: &str = r#"{
  "session_id": "test-session",
  "created_at": "2026-05-01T00:00:00+00:00",
  "mappings": {
    "[EMAIL_ADDRESS_deadbeef]": "alice@example.com"
  }
}"#;

fn write_legacy_mapping(dir: &std::path::Path) -> std::path::PathBuf {
    let path = dir.join("restore-map-legacy.json");
    fs::write(&path, LEGACY_MAPPING_JSON).unwrap();
    path
}

fn write_mapping(dir: &std::path::Path) -> std::path::PathBuf {
    let path = dir.join("restore-map.json");
    let (mapping, _) = Mapping::from_persisted_json_allow_legacy(LEGACY_MAPPING_JSON).unwrap();
    fs::write(&path, mapping.to_persisted_json_pretty().unwrap()).unwrap();
    path
}

#[test]
fn restore_defaults_to_bracketed_tokens_only() {
    let dir = tempfile::tempdir().unwrap();
    let mapping = write_mapping(dir.path());
    let input = dir.path().join("response.txt");
    fs::write(
        &input,
        "Contact [EMAIL_ADDRESS_deadbeef]; ignore EMAIL_ADDRESS_deadbeef",
    )
    .unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_anon-pii"))
        .arg("restore")
        .arg("--mapping")
        .arg(mapping)
        .arg(&input)
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "restore failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        "Contact alice@example.com; ignore EMAIL_ADDRESS_deadbeef\n"
    );
    assert!(String::from_utf8_lossy(&output.stderr).contains("Restored 1 token replacement"));
}

#[test]
fn restore_bare_flag_enables_legacy_bare_token_restore() {
    let dir = tempfile::tempdir().unwrap();
    let mapping = write_mapping(dir.path());
    let input = dir.path().join("response.txt");
    fs::write(
        &input,
        "Contact [EMAIL_ADDRESS_deadbeef]; legacy EMAIL_ADDRESS_deadbeef",
    )
    .unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_anon-pii"))
        .arg("restore")
        .arg("--restore-bare")
        .arg("--mapping")
        .arg(mapping)
        .arg(&input)
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "restore failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        "Contact alice@example.com; legacy alice@example.com\n"
    );
    assert!(String::from_utf8_lossy(&output.stderr).contains("Restored 2 token replacements"));
}

#[test]
fn restore_reports_zero_for_unused_mapping_entries() {
    let dir = tempfile::tempdir().unwrap();
    let mapping = write_mapping(dir.path());
    let input = dir.path().join("response.txt");
    fs::write(&input, "No known token appears here").unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_anon-pii"))
        .arg("restore")
        .arg("--mapping")
        .arg(mapping)
        .arg(&input)
        .output()
        .unwrap();

    assert!(output.status.success());
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        "No known token appears here\n"
    );
    assert!(String::from_utf8_lossy(&output.stderr).contains("Restored 0 token replacements"));
}

#[test]
fn restore_counts_each_repeated_token_occurrence() {
    let dir = tempfile::tempdir().unwrap();
    let mapping = write_mapping(dir.path());
    let input = dir.path().join("response.txt");
    fs::write(
        &input,
        "[EMAIL_ADDRESS_deadbeef] and [EMAIL_ADDRESS_deadbeef]",
    )
    .unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_anon-pii"))
        .arg("restore")
        .arg("--mapping")
        .arg(mapping)
        .arg(&input)
        .output()
        .unwrap();

    assert!(output.status.success());
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        "alice@example.com and alice@example.com\n"
    );
    assert!(String::from_utf8_lossy(&output.stderr).contains("Restored 2 token replacements"));
}

#[test]
fn restore_unsigned_mapping_requires_explicit_opt_in() {
    let dir = tempfile::tempdir().unwrap();
    let mapping = write_legacy_mapping(dir.path());
    let input = dir.path().join("response.txt");
    fs::write(&input, "Contact [EMAIL_ADDRESS_deadbeef]").unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_anon-pii"))
        .arg("restore")
        .arg("--mapping")
        .arg(mapping)
        .arg(&input)
        .output()
        .unwrap();

    assert!(
        !output.status.success(),
        "restore should reject unsigned mapping"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("--allow-unsigned-mapping"),
        "stderr should explain the opt-in flag:\n{stderr}"
    );
}

#[test]
fn restore_allow_unsigned_mapping_restores_legacy_map() {
    let dir = tempfile::tempdir().unwrap();
    let mapping = write_legacy_mapping(dir.path());
    let input = dir.path().join("response.txt");
    fs::write(&input, "Contact [EMAIL_ADDRESS_deadbeef]").unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_anon-pii"))
        .arg("restore")
        .arg("--allow-unsigned-mapping")
        .arg("--mapping")
        .arg(mapping)
        .arg(&input)
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "restore failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        "Contact alice@example.com\n"
    );
}

#[test]
fn restore_help_documents_bare_token_risk() {
    let output = Command::new(env!("CARGO_BIN_EXE_anon-pii"))
        .arg("restore")
        .arg("--help")
        .output()
        .unwrap();

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("--restore-bare"), "help was:\n{stdout}");
    assert!(
        stdout.contains("untrusted model output"),
        "help should warn about untrusted model output:\n{stdout}"
    );
}
