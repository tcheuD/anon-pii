#![cfg(unix)]

use std::fs;
use std::io::Write;
use std::path::Path;
use std::process::{Command, Output, Stdio};

fn run_with_input(home: &Path, arguments: &[&str], input: &[u8]) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_anon-pii"));
    command.args(arguments);
    command.envs([(String::from("HOME"), home.as_os_str().to_owned())]);
    let mut child = command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn anon-pii");
    child
        .stdin
        .as_mut()
        .expect("piped stdin")
        .write_all(input)
        .expect("write anon-pii stdin");
    child.wait_with_output().expect("wait for anon-pii")
}

#[test]
fn run_anonymizes_child_stdin_restores_stdout_and_writes_no_mapping() {
    let home = tempfile::tempdir().unwrap();
    let child_input = home.path().join("child-input.txt");
    let child_input_arg = child_input.to_str().unwrap();

    let output = run_with_input(
        home.path(),
        &["run", "--", "sh", "-c", "tee \"$1\"", "_", child_input_arg],
        b"Contact john@example.com\n",
    );

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(output.stdout, b"Contact john@example.com\n");
    let child_saw = fs::read_to_string(child_input).unwrap();
    assert!(!child_saw.contains("john@example.com"));
    assert!(child_saw.contains("[EMAIL_ADDRESS_"));
    let default_map = home
        .path()
        .join(".anon-pii")
        .join(["mapping", "json"].join("."));
    assert!(!default_map.exists());
}

#[test]
fn run_preserves_child_stderr_and_nonzero_exit_status() {
    let home = tempfile::tempdir().unwrap();
    let output = run_with_input(
        home.path(),
        &[
            "run",
            "--",
            "sh",
            "-c",
            "cat >/dev/null; printf child-error >&2; exit 7",
        ],
        b"john@example.com",
    );

    assert_eq!(output.status.code(), Some(7));
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).contains("child-error"));
}

#[test]
fn run_passes_no_detection_input_through_exactly() {
    let home = tempfile::tempdir().unwrap();
    let input = b"ordinary text without sensitive values\n";
    let output = run_with_input(home.path(), &["run", "--", "sh", "-c", "cat"], input);

    assert!(output.status.success());
    assert_eq!(output.stdout, input);
}

#[test]
fn run_preserves_unknown_malformed_and_non_utf8_child_output() {
    let home = tempfile::tempdir().unwrap();
    let output = run_with_input(
        home.path(),
        &[
            "run",
            "--",
            "sh",
            "-c",
            "cat >/dev/null; printf 'unknown [EMAIL_ADDRESS_cafebabe] partial [EMAIL_'; printf '\\377'",
        ],
        b"john@example.com",
    );

    assert!(output.status.success());
    let mut expected = b"unknown [EMAIL_ADDRESS_cafebabe] partial [EMAIL_".to_vec();
    expected.push(0xff);
    assert_eq!(output.stdout, expected);
}

#[test]
fn run_passes_program_arguments_without_shell_interpretation() {
    let home = tempfile::tempdir().unwrap();
    let output = run_with_input(
        home.path(),
        &["run", "--", "/usr/bin/printf", "%s", "$HOME;*"],
        b"",
    );

    assert!(output.status.success());
    assert_eq!(output.stdout, b"$HOME;*");
}

#[test]
fn run_rejects_persistent_mapping_and_output_options() {
    let home = tempfile::tempdir().unwrap();
    let mapping = home.path().join(["map", "json"].join("."));
    let mapping_arg = mapping.to_str().unwrap();
    let output = run_with_input(
        home.path(),
        &["--mapping", mapping_arg, "run", "--", "cat"],
        b"john@example.com",
    );

    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("unsupported option(s): --mapping"));
    assert!(!stderr.contains("Custom {"), "stderr: {stderr}");
    assert!(!mapping.exists());
}

#[test]
fn run_avoids_pipe_deadlock_when_child_writes_before_reading() {
    let home = tempfile::tempdir().unwrap();
    let input = vec![b'a'; 1024 * 1024];
    let output = run_with_input(
        home.path(),
        &[
            "run",
            "--",
            "sh",
            "-c",
            "dd if=/dev/zero bs=65536 count=16 2>/dev/null; cat >/dev/null",
        ],
        &input,
    );

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(output.stdout.len(), 1024 * 1024);
    assert!(output.stdout.iter().all(|byte| *byte == 0));
}

#[test]
fn run_uses_shell_compatible_code_for_signaled_child() {
    let home = tempfile::tempdir().unwrap();
    let output = run_with_input(
        home.path(),
        &["run", "--", "sh", "-c", "cat >/dev/null; kill -TERM $$"],
        b"input",
    );

    assert_eq!(output.status.code(), Some(143));
}

#[test]
fn run_help_explains_transaction_owned_roundtrip() {
    let output = Command::new(env!("CARGO_BIN_EXE_anon-pii"))
        .args(["run", "--help"])
        .output()
        .unwrap();

    assert!(output.status.success());
    let help = String::from_utf8_lossy(&output.stdout);
    assert!(help.contains("Anonymize stdin"));
    assert!(help.contains("COMMAND"));
}
