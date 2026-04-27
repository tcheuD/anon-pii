use regex::Regex;
use std::fs;
use std::path::Path;

fn read_doc(path: &str) -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(path);
    fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", path.display()))
}

fn public_doc_paths() -> &'static [&'static str] {
    &[
        "README.md",
        "PROXY-MODE.md",
        "docs/proxy.md",
        "docs/ner.md",
        "docs/image-redaction.md",
        "docs/youtrack.md",
        "docs/openapi.yaml",
    ]
}

fn user_facing_source_paths() -> &'static [&'static str] {
    &[
        "src/main.rs",
        "src/ner/ml.rs",
        "src/proxy/mod.rs",
        "src/ui/mod.rs",
    ]
}

#[test]
fn public_docs_do_not_show_sequential_token_examples() {
    let sequential_token = Regex::new(r"\[[A-Z][A-Z0-9_]+_[0-9]+\]").unwrap();
    let mut offenders = Vec::new();

    for path in public_doc_paths() {
        let doc = read_doc(path);
        for mat in sequential_token.find_iter(&doc) {
            offenders.push(format!("{path}: {}", mat.as_str()));
        }
    }

    assert!(
        offenders.is_empty(),
        "public docs still show sequential token examples:\n{}",
        offenders.join("\n")
    );
}

#[test]
fn public_docs_use_current_binary_name_in_commands() {
    let stale_command = Regex::new(
        r"\banon (?:--ner|download-model|image|pdf|proxy|api|restore|list-entities|sessions)\b",
    )
    .unwrap();
    let mut offenders = Vec::new();

    for path in public_doc_paths() {
        let doc = read_doc(path);
        for mat in stale_command.find_iter(&doc) {
            offenders.push(format!("{path}: {}", mat.as_str()));
        }
    }

    assert!(
        offenders.is_empty(),
        "public docs still use the old `anon` command name:\n{}",
        offenders.join("\n")
    );
}

#[test]
fn user_facing_source_messages_use_current_binary_name() {
    let stale_command = Regex::new(r"\banon (?:download-model|proxy)\b").unwrap();
    let mut offenders = Vec::new();

    for path in user_facing_source_paths() {
        let source = read_doc(path);
        for mat in stale_command.find_iter(&source) {
            offenders.push(format!("{path}: {}", mat.as_str()));
        }
    }

    assert!(
        offenders.is_empty(),
        "user-facing source messages still use the old `anon` command name:\n{}",
        offenders.join("\n")
    );
}

#[test]
fn readme_links_all_feature_guides_and_verification_commands() {
    let readme = read_doc("README.md");

    for guide in [
        "docs/proxy.md",
        "docs/api.md",
        "docs/ner.md",
        "docs/image-redaction.md",
        "docs/pdf-redaction.md",
        "docs/xlsx.md",
        "docs/openapi.yaml",
    ] {
        assert!(readme.contains(guide), "README should link {guide}");
        let full_path = Path::new(env!("CARGO_MANIFEST_DIR")).join(guide);
        assert!(full_path.exists(), "{guide} should exist");
    }

    for command in [
        "cargo test",
        "cargo fmt --all --check",
        "cargo clippy -- -D warnings",
        "cargo clippy --features ner-lite,proxy -- -D warnings",
        "cargo test --features ner-lite,proxy",
        "cargo test --features image",
        "cargo test --features pdf",
        "cargo test --features xlsx",
        "cargo run --features ner-lite,proxy,image,pdf,xlsx --example update_readme",
    ] {
        assert!(
            readme.contains(command),
            "README should document `{command}`"
        );
    }
}

#[test]
fn readme_explains_mapping_persistence_and_risk() {
    let readme = read_doc("README.md");

    for snippet in [
        "Default token mode persists a reversible mapping",
        concat!("`~/.anon-pii/", "mapping", ".json`"),
        "`--mapping`",
        "`--mapping-stderr`",
        "`--include-mapping`",
        "owner-only permissions",
        "Proxy sessions write a separate mapping file",
    ] {
        assert!(readme.contains(snippet), "README should mention {snippet}");
    }
}
