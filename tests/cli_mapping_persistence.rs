#![cfg(unix)]

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

fn run_anonymize(mut cmd: Command) -> Output {
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
        .write_all(sample_input().as_bytes())
        .expect("failed to write stdin");
    child
        .wait_with_output()
        .expect("failed to wait for anon-pii")
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
        !mapping_file(&real_parent).exists(),
        "mapping should not be written through a symlinked parent"
    );
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
