use std::fs;
use std::process::Command;

fn write_mapping(dir: &std::path::Path) -> std::path::PathBuf {
    let path = dir.join("restore-map.json");
    fs::write(
        &path,
        r#"{
  "session_id": "test-session",
  "created_at": "2026-05-01T00:00:00+00:00",
  "mappings": {
    "[EMAIL_ADDRESS_deadbeef]": "alice@example.com"
  }
}"#,
    )
    .unwrap();
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
