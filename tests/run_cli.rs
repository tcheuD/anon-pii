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
    if let Err(error) = child.stdin.as_mut().expect("piped stdin").write_all(input) {
        // Invalid CLI options can be rejected before stdin is read. The caller
        // still checks the exit status and output; other I/O failures are errors.
        assert_eq!(error.kind(), std::io::ErrorKind::BrokenPipe);
    }
    child.wait_with_output().expect("wait for anon-pii")
}

#[test]
fn run_anonymizes_child_stdin_restores_stdout_and_writes_no_mapping() {
    let home = tempfile::tempdir().unwrap();
    let child_input = home.path().join("child-input.txt");
    let child_input_arg = child_input.to_str().unwrap();
    // Base64 of debug:example-password, a synthetic credential.
    let input =
        b"Contact john@example.com\nAuthorization: Basic ZGVidWc6ZXhhbXBsZS1wYXNzd29yZA==\n";

    let output = run_with_input(
        home.path(),
        &["run", "--", "sh", "-c", "tee \"$1\"", "_", child_input_arg],
        input,
    );

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(output.stdout, input);
    let child_saw = fs::read_to_string(child_input).unwrap();
    assert!(!child_saw.contains("john@example.com"));
    assert!(child_saw.contains("[EMAIL_ADDRESS_"));
    assert!(!child_saw.contains("ZGVidWc6ZXhhbXBsZS1wYXNzd29yZA=="));
    assert!(child_saw.contains("Authorization: Basic [AUTH_TOKEN_"));
    let default_map = home
        .path()
        .join(".anon-pii")
        .join(["mapping", "json"].join("."));
    assert!(!default_map.exists());
}

#[cfg(feature = "ner-lite")]
#[test]
fn support_ticket_starter_hides_four_values_and_restores_reply_references() {
    let home = tempfile::tempdir().unwrap();
    let input = include_bytes!("../demo/samples/support-ticket-fr.txt");
    let script = Path::new(env!("CARGO_MANIFEST_DIR")).join("demo/ticket-reply.py");
    let output = run_with_input(
        home.path(),
        &["--ner", "run", "--", "python3", script.to_str().unwrap()],
        input,
    );
    let child_saw = String::from_utf8(output.stderr).unwrap();
    assert!(output.status.success(), "{child_saw}");
    for original in [
        "Camille verneuil",
        "camille.verneuil@example.invalid",
        "24 rue des Nuages 75016 ville-exemple",
        "ZGVidWc6ZXhhbXBsZS1wYXNzd29yZA==",
    ] {
        assert!(!child_saw.contains(original), "child received {original}");
    }
    for entity in ["PERSON", "EMAIL_ADDRESS", "FR_ADDRESS", "AUTH_TOKEN"] {
        assert!(child_saw.contains(&format!("[{entity}_")), "{child_saw}");
    }
    assert!(child_saw.contains("CASE-2042"));
    let reply = String::from_utf8(output.stdout).unwrap();
    assert!(reply.contains("For Camille verneuil, contact camille.verneuil@example.invalid."));
    assert!(reply.contains("Confirm the delivery address: 24 rue des Nuages 75016 ville-exemple."));
    assert!(reply.contains("compare the request IDs and retry timestamps"));
    assert!(!reply.contains("ZGVidWc6ZXhhbXBsZS1wYXNzd29yZA=="));
    assert!(!home.path().join(".anon-pii/mapping.json").exists());
}

#[test]
fn wrapped_email_preview_and_child_input_mask_exactly_then_restore() {
    let ticket_home = tempfile::tempdir().unwrap();
    let child_input = ticket_home.path().join("child-input.txt");
    for address in ["ada@\nexample.com", "iñes@\r\n\texample.org"] {
        let prefix = "Réponse 😀 — contact ";
        let suffix = "; please investigate.\n";
        let input = format!("{prefix}{address}{suffix}");
        let preview = run_with_input(ticket_home.path(), &["run", "--dry-run"], input.as_bytes());
        assert!(preview.status.success());
        let prepared = String::from_utf8(preview.stdout).unwrap();
        let token = prepared
            .strip_prefix(prefix)
            .unwrap()
            .strip_suffix(suffix)
            .unwrap();
        assert!(token.starts_with("[EMAIL_ADDRESS_") && token.ends_with(']'));
        assert!(!prepared.contains(address));

        let output = run_with_input(
            ticket_home.path(),
            &["run", "--", "tee", child_input.to_str().unwrap()],
            input.as_bytes(),
        );
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(output.stdout, input.as_bytes());
        let child_saw = fs::read_to_string(&child_input).unwrap();
        let token = child_saw
            .strip_prefix(prefix)
            .unwrap()
            .strip_suffix(suffix)
            .unwrap();
        assert!(token.starts_with("[EMAIL_ADDRESS_") && token.ends_with(']'));
        assert!(!child_saw.contains(address));
        assert!(!ticket_home.path().join(".anon-pii/mapping.json").exists());
    }
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
    assert!(help.contains("--dry-run"));
}

#[test]
fn dry_run_previews_payload_without_starting_child_or_touching_mapping() {
    let home = tempfile::tempdir().unwrap();
    let mapping_dir = home.path().join(".anon-pii");
    fs::create_dir(&mapping_dir).unwrap();
    let mapping = mapping_dir.join("mapping.json");
    fs::write(&mapping, b"existing detached workflow mapping").unwrap();
    let marker = home.path().join("child-started");

    let output = run_with_input(
        home.path(),
        &[
            "--verbose",
            "run",
            "--dry-run",
            "--",
            "sh",
            "-c",
            "touch \"$1\"; cat",
            "_",
            marker.to_str().unwrap(),
        ],
        b"Contact john@example.com or john@example.com",
    );

    assert!(output.status.success());
    assert!(!marker.exists(), "dry run must not execute the child");
    assert_eq!(
        fs::read(mapping).unwrap(),
        b"existing detached workflow mapping"
    );
    assert_eq!(fs::read_dir(mapping_dir).unwrap().count(), 1);
    let preview = String::from_utf8(output.stdout).unwrap();
    assert!(!preview.contains("john@example.com"));
    let email_token = regex::Regex::new(r"\[EMAIL_ADDRESS_[0-9a-f]{8}\]").unwrap();
    let tokens: Vec<_> = email_token
        .find_iter(&preview)
        .map(|m| m.as_str())
        .collect();
    assert_eq!(tokens.len(), 2);
    assert_eq!(tokens[0], tokens[1]);
    assert_eq!(preview, format!("Contact {} or {}", tokens[0], tokens[1]));

    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains("no command was started; no mapping was saved"));
    assert!(stderr.contains("Unique entities detected: 1"));
    assert!(stderr.contains("EMAIL_ADDRESS: 1"));
    assert!(stderr.contains("Review the preview for missed sensitive values"));
    assert!(!stderr.contains("john@example.com"));
    assert!(
        !stderr.contains("j***m"),
        "summary must not print masked originals"
    );
}

#[test]
fn dry_run_needs_no_command_and_keeps_no_detection_input_byte_exact() {
    let home = tempfile::tempdir().unwrap();
    for input in [b"".as_slice(), b"ordinary text", b"ordinary text\n"] {
        let output = run_with_input(home.path(), &["run", "--dry-run"], input);
        assert!(output.status.success());
        assert_eq!(output.stdout, input);
        let stderr = String::from_utf8(output.stderr).unwrap();
        assert!(stderr.contains("Unique entities detected: 0"));
        assert!(stderr.contains("Review the preview"));
    }
    assert_eq!(fs::read_dir(home.path()).unwrap().count(), 0);
}

#[test]
fn dry_run_uses_the_run_format_and_detection_options() {
    let home = tempfile::tempdir().unwrap();
    for (format, input) in [
        ("json", "{\"email\":\"john@example.com\",\"count\":42}"),
        ("csv", "email,count\r\njohn@example.com,42\r\n"),
        (
            "sql",
            "INSERT INTO users (email) VALUES ('john@example.com');",
        ),
    ] {
        let output = run_with_input(
            home.path(),
            &["--format", format, "run", "--dry-run"],
            input.as_bytes(),
        );
        assert!(output.status.success());
        let preview = String::from_utf8(output.stdout).unwrap();
        assert!(!preview.contains("john@example.com"));
        let token = regex::Regex::new(r"\[EMAIL_ADDRESS_[0-9a-f]{8}\]").unwrap();
        assert_eq!(token.find_iter(&preview).count(), 1);
        let restored = token.replace_all(&preview, "john@example.com");
        if format == "json" {
            assert_eq!(
                serde_json::from_str::<serde_json::Value>(&restored).unwrap(),
                serde_json::from_str::<serde_json::Value>(input).unwrap()
            );
        } else {
            assert_eq!(restored, input);
        }
        assert!(String::from_utf8_lossy(&output.stderr).contains(&format!("format: {format}")));
    }

    let config = home.path().join("recognizers.yaml");
    fs::write(
        &config,
        "recognizers:\n  - name: Synthetic ID\n    entity_type: CUSTOMER_ID\n    patterns:\n      - regex: 'SYNTHETIC-[A-Z]{4}'\n        score: 0.8\n",
    )
    .unwrap();
    for (threshold, expected) in [("0.5", true), ("0.9", false)] {
        let output = run_with_input(
            home.path(),
            &[
                "--config",
                config.to_str().unwrap(),
                "--threshold",
                threshold,
                "run",
                "--dry-run",
            ],
            b"Customer SYNTHETIC-ABCD",
        );
        assert!(output.status.success(), "{:?}", output.stderr);
        let preview = String::from_utf8(output.stdout).unwrap();
        assert_eq!(preview.contains("[CUSTOMER_ID_"), expected);
        assert_eq!(preview.contains("SYNTHETIC-ABCD"), !expected);
    }
}

#[test]
fn dry_run_rejects_invalid_input_before_output_or_child_spawn() {
    let home = tempfile::tempdir().unwrap();
    let marker = home.path().join("child-started");
    for (format, input) in [("json", b"{invalid json".as_slice()), ("text", b"\xff")] {
        let output = run_with_input(
            home.path(),
            &[
                "--format",
                format,
                "run",
                "--dry-run",
                "--",
                "touch",
                marker.to_str().unwrap(),
            ],
            input,
        );
        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
        assert!(!marker.exists());
    }
    assert_eq!(fs::read_dir(home.path()).unwrap().count(), 0);
}

#[test]
fn dry_run_rejects_options_that_persist_or_expose_mapping() {
    let home = tempfile::tempdir().unwrap();
    for option in ["--mapping-stderr", "--include-mapping", "--share"] {
        let output = run_with_input(
            home.path(),
            &[option, "run", "--dry-run"],
            b"john@example.com",
        );
        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
        assert!(String::from_utf8_lossy(&output.stderr).contains("unsupported option(s)"));
        assert!(!String::from_utf8_lossy(&output.stderr).contains("john@example.com"));
    }
    assert_eq!(fs::read_dir(home.path()).unwrap().count(), 0);
}

#[test]
fn run_still_requires_a_command_without_dry_run() {
    let home = tempfile::tempdir().unwrap();
    let output = run_with_input(home.path(), &["run"], b"");
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).contains("COMMAND"));
}

#[test]
fn run_forwards_dry_run_after_separator_to_child() {
    let home = tempfile::tempdir().unwrap();
    let output = run_with_input(
        home.path(),
        &["run", "--", "/usr/bin/printf", "%s", "--dry-run"],
        b"",
    );
    assert!(output.status.success());
    assert_eq!(output.stdout, b"--dry-run");
    assert!(output.stderr.is_empty());
}
