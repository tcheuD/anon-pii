#![cfg(unix)]

use anon_pii::mapping::Mapping;
use std::fs;
use std::io::Write;
use std::os::unix::fs as unix_fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::path::PathBuf;
use std::process::{Command, Output, Stdio};

fn sample_value() -> String {
    ["john", "@", "example", ".com"].concat()
}

fn sample_input() -> String {
    format!("Contact {}\n", sample_value())
}

fn run_anonymize_with_input(mut cmd: Command, input: &str) -> Output {
    cmd.arg("--format")
        .arg("text")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let mut child = cmd.spawn().expect("failed to spawn anon-pii");
    child
        .stdin
        .as_mut()
        .expect("stdin should be piped")
        .write_all(input.as_bytes())
        .expect("failed to write stdin");
    child
        .wait_with_output()
        .expect("failed to wait for anon-pii")
}

fn run_anonymize(cmd: Command) -> Output {
    run_anonymize_with_input(cmd, &sample_input())
}

fn anon_command() -> Command {
    Command::new(env!("CARGO_BIN_EXE_anon-pii"))
}

fn assert_success(output: &Output) {
    assert!(
        output.status.success(),
        "anon-pii failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn mode(path: &Path) -> u32 {
    fs::metadata(path).unwrap().permissions().mode() & 0o777
}

fn mapping_file(parent: &Path) -> PathBuf {
    parent.join(["mapping", "json"].join("."))
}

fn legacy_tmp_file(parent: &Path) -> PathBuf {
    parent.join([".mapping", "json", "tmp"].join("."))
}

fn persisted_mapping() -> String {
    let mut mapping = Mapping::new();
    mapping.add("EMAIL_ADDRESS", "saved@example.com");
    mapping.to_persisted_json_pretty().unwrap()
}

#[test]
fn default_mapping_parent_is_created_private() {
    let home = tempfile::tempdir().unwrap();
    let mut cmd = anon_command();
    cmd.env("HOME", home.path());

    let output = run_anonymize(cmd);

    assert_success(&output);
    let dir_name = [".", "anon-pii"].concat();
    assert_eq!(
        mode(&home.path().join(dir_name)),
        0o700,
        "default mapping parent should be owner-only"
    );
}

#[test]
fn custom_existing_mapping_parent_permissions_are_preserved() {
    let temp = tempfile::tempdir().unwrap();
    let parent = temp.path().join("shared");
    fs::create_dir(&parent).unwrap();
    fs::set_permissions(&parent, fs::Permissions::from_mode(0o755)).unwrap();

    let mut cmd = anon_command();
    cmd.arg("--mapping").arg(mapping_file(&parent));

    let output = run_anonymize(cmd);

    assert_success(&output);
    assert_eq!(
        mode(&parent),
        0o755,
        "custom mapping parent permissions should not be changed"
    );
}

#[test]
fn custom_mapping_parent_symlink_is_rejected() {
    let temp = tempfile::tempdir().unwrap();
    let real_parent = temp.path().join("real-parent");
    fs::create_dir(&real_parent).unwrap();
    let linked_parent = temp.path().join("linked-parent");
    unix_fs::symlink(&real_parent, &linked_parent).unwrap();

    let mut cmd = anon_command();
    cmd.arg("--mapping").arg(mapping_file(&linked_parent));

    let output = run_anonymize(cmd);

    assert!(
        !output.status.success(),
        "custom symlink parent should be rejected"
    );
    assert!(
        output.stdout.is_empty(),
        "tokenized stdout must not be emitted before mapping persistence succeeds"
    );
    assert!(
        !mapping_file(&real_parent).exists(),
        "mapping should not be written through a symlinked parent"
    );
}

#[test]
fn mapping_failure_leaves_output_file_untouched() {
    let temp = tempfile::tempdir().unwrap();
    let real_parent = temp.path().join("real-parent");
    fs::create_dir(&real_parent).unwrap();
    let linked_parent = temp.path().join("linked-parent");
    unix_fs::symlink(&real_parent, &linked_parent).unwrap();

    let output_path = temp.path().join("output.txt");
    fs::write(&output_path, "sentinel").unwrap();

    let mut cmd = anon_command();
    cmd.arg("--mapping")
        .arg(mapping_file(&linked_parent))
        .arg("--output")
        .arg(&output_path);

    let output = run_anonymize(cmd);
    assert!(!output.status.success());
    assert_eq!(fs::read_to_string(output_path).unwrap(), "sentinel");
}

#[test]
fn zero_detection_run_preserves_existing_mapping() {
    let temp = tempfile::tempdir().unwrap();
    let path = mapping_file(temp.path());
    let original_mapping = persisted_mapping();
    fs::write(&path, &original_mapping).unwrap();

    let mut cmd = anon_command();
    cmd.arg("--mapping").arg(&path);
    let output = run_anonymize_with_input(cmd, "Nothing sensitive in this line.\n");

    assert_success(&output);
    assert_eq!(fs::read_to_string(path).unwrap(), original_mapping);
}

#[test]
fn non_token_operators_preserve_existing_mapping() {
    let operators: [(&str, &[&str]); 6] = [
        ("keep", &[]),
        ("redact", &[]),
        ("mask", &[]),
        ("hash", &[]),
        ("custom", &["--replace-with", "REDACTED"]),
        (
            "encrypt",
            &["--encrypt-key", "00000000000000000000000000000000"],
        ),
    ];

    for (operator, extra_args) in operators {
        let temp = tempfile::tempdir().unwrap();
        let path = mapping_file(temp.path());
        let original_mapping = persisted_mapping();
        fs::write(&path, &original_mapping).unwrap();

        let mut cmd = anon_command();
        cmd.arg("--mapping")
            .arg(&path)
            .arg("--operator")
            .arg(operator)
            .args(extra_args);
        let output = run_anonymize(cmd);

        assert_success(&output);
        assert_eq!(
            fs::read_to_string(path).unwrap(),
            original_mapping,
            "{operator} must not replace a reversible token mapping"
        );
    }
}

#[test]
fn preexisting_fixed_temp_symlink_is_not_followed_or_consumed() {
    let temp = tempfile::tempdir().unwrap();
    let parent = temp.path().join("shared");
    fs::create_dir(&parent).unwrap();

    let external_target = parent.join("external-target.txt");
    fs::write(&external_target, "external file").unwrap();
    let legacy_tmp_path = legacy_tmp_file(&parent);
    unix_fs::symlink(&external_target, &legacy_tmp_path).unwrap();

    let path = mapping_file(&parent);
    let mut cmd = anon_command();
    cmd.arg("--mapping").arg(&path);

    let output = run_anonymize(cmd);

    assert_success(&output);
    assert!(
        fs::symlink_metadata(&legacy_tmp_path)
            .unwrap()
            .file_type()
            .is_symlink(),
        "pre-existing fixed temp symlink should not be consumed"
    );
    assert_eq!(
        fs::read_to_string(&external_target).unwrap(),
        "external file"
    );
    assert!(
        !fs::symlink_metadata(&path)
            .unwrap()
            .file_type()
            .is_symlink(),
        "mapping file should be a regular file"
    );
    assert!(
        fs::read_to_string(&path).unwrap().contains(&sample_value()),
        "mapping file should contain the persisted mapping"
    );
}
