use regex::Regex;
use std::fs;
use std::path::Path;
use std::process::Command;

fn read_doc(path: &str) -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(path);
    fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", path.display()))
}

fn read_workflow(path: &str) -> String {
    read_doc(path)
}

fn public_doc_paths() -> &'static [&'static str] {
    &[
        "README.md",
        "PROXY-MODE.md",
        "docs/proxy.md",
        "docs/ner.md",
        "docs/image-redaction.md",
        "docs/pdf-redaction.md",
        "docs/youtrack.md",
        "docs/openapi.yaml",
    ]
}

fn public_demo_text_paths() -> &'static [&'static str] {
    &[
        "demo/README.md",
        "demo/record.sh",
        "demo/hero.tape",
        "demo/samples/support-ticket.txt",
        "demo/samples/incident-log.txt",
        "demo/samples/queries.sql",
        "demo/samples/passengers.csv",
        "testdata/api-error.json",
        "testdata/crew-roster.csv",
        "testdata/custom-recognizers.yaml",
        "testdata/debug-log.txt",
        "testdata/queries.sql",
    ]
}

fn git_tracks_path(repo: &Path, path: &str) -> Option<bool> {
    let output = Command::new("git")
        .args(["ls-files", "--error-unmatch", path])
        .current_dir(repo)
        .output()
        .ok()?;

    Some(output.status.success())
}

#[test]
fn ci_covers_documented_public_feature_set() {
    let ci = read_workflow(".github/workflows/ci.yml");

    assert!(
        ci.contains("features: ['', 'ner-lite,proxy']"),
        "CI should include the default and ner-lite,proxy test matrix"
    );

    for command in [
        "cargo test",
        "cargo test --features xlsx",
        "cargo test --features pdf",
        "cargo test --features image",
        "cargo test --features image -- --ignored",
    ] {
        assert!(ci.contains(command), "CI should run `{command}`");
    }

    for phrase in [
        "requires Tesseract",
        "requires ONNX Runtime",
        "not part of the required PR gate",
    ] {
        assert!(
            ci.contains(phrase),
            "CI should document feature-gate exclusion: {phrase}"
        );
    }
}

#[test]
fn public_demo_assets_are_portable_and_fictional() {
    let repo = Path::new(env!("CARGO_MANIFEST_DIR"));

    for path in public_demo_text_paths() {
        assert!(repo.join(path).exists(), "{path} should exist");
    }

    for generated in ["demo/hero.cast", "demo/hero.gif"] {
        if let Some(is_tracked) = git_tracks_path(repo, generated) {
            assert!(
                !is_tracked,
                "{generated} is generated output and should not be committed"
            );
        }
    }

    let gitignore = read_doc(".gitignore");
    for pattern in ["demo/*.cast", "demo/*.gif", "demo/tmp/"] {
        assert!(
            gitignore.contains(pattern),
            ".gitignore should ignore generated demo artifact pattern {pattern}"
        );
    }

    let record_script = read_doc("demo/record.sh");
    assert!(
        !record_script.contains("target/debug/anon-pii"),
        "demo/record.sh should not assume Cargo's default target directory"
    );

    let local_path = Regex::new(r"(?i)(/Users/|/home/[^[:space:]]+)").unwrap();
    let private_fixture = Regex::new(
        r"(?i)(fly[a]melia|reg[o]urd|jean\.dupont|marie\.martin|pierre\.bernard|sophie\.lambert)",
    )
    .unwrap();
    let stale_anon_command = Regex::new(r#"(^|[\s'"|])anon($|[\s|;&'"<>])"#).unwrap();
    let external_llm_command = Regex::new(r#"(^|[\s'"|])claude($|[\s|;&'"<>])"#).unwrap();
    let stale_testdata_demo = Regex::new(r"testdata/queries\.sql").unwrap();
    let mut offenders = Vec::new();

    for path in public_demo_text_paths() {
        let doc = read_doc(path);
        for (name, re) in [
            ("local path", &local_path),
            ("private fixture", &private_fixture),
            ("old anon command", &stale_anon_command),
            ("external LLM command", &external_llm_command),
            ("testdata-backed demo", &stale_testdata_demo),
        ] {
            for mat in re.find_iter(&doc) {
                offenders.push(format!("{path}: {name}: {}", mat.as_str()));
            }
        }
    }

    assert!(
        offenders.is_empty(),
        "public demo assets are not portable/generic:\n{}",
        offenders.join("\n")
    );
}

#[test]
fn manual_ci_runs_release_readiness_jobs() {
    let ci = read_workflow(".github/workflows/ci.yml");
    let release_doc = read_doc("docs/release.md");

    assert!(
        release_doc.contains("Main branch or manual checks additionally run"),
        "release checklist should describe main/manual release-readiness checks"
    );

    for snippet in [
        "if: github.event_name == 'workflow_dispatch' || (github.event_name == 'push' && github.ref == 'refs/heads/main')",
        "rust-test-macos:",
        "security-deny:",
        "security-audit:",
    ] {
        assert!(
            ci.contains(snippet),
            "manual CI should run release-readiness job condition `{snippet}`"
        );
    }
}

#[test]
fn release_workflow_packages_current_binary_name() {
    let release = read_workflow(".github/workflows/release.yml");
    let benchmark = read_workflow(".github/workflows/bench.yml");

    for workflow in [release.as_str(), benchmark.as_str()] {
        assert!(
            !workflow.contains("target/release/anon ")
                && !workflow.contains("release/anon dist/")
                && !workflow.contains("artifact: anon-linux")
                && !workflow.contains("artifact: anon-macos"),
            "workflows should not package or benchmark the old `anon` binary name"
        );
    }

    for snippet in [
        "artifact: anon-pii-linux-x86_64",
        "artifact: anon-pii-macos-x86_64",
        "artifact: anon-pii-macos-aarch64",
        "target/${{ matrix.target }}/release/anon-pii",
    ] {
        assert!(
            release.contains(snippet),
            "release workflow should contain `{snippet}`"
        );
    }
}

#[test]
fn first_release_checklist_is_documented() {
    let readme = read_doc("README.md");
    let contributing = read_doc("CONTRIBUTING.md");
    let release_doc_path = Path::new(env!("CARGO_MANIFEST_DIR")).join("docs/release.md");

    assert!(
        readme.contains("docs/release.md"),
        "README should link the release checklist"
    );
    assert!(
        contributing.contains("docs/release.md"),
        "CONTRIBUTING should link the release checklist"
    );
    assert!(release_doc_path.exists(), "docs/release.md should exist");

    let release_doc = read_doc("docs/release.md");
    for phrase in [
        "First Release Checklist",
        "cargo package --allow-dirty --no-verify",
        "cargo audit",
        "cargo deny check",
        "Linux x86_64",
        "macOS x86_64",
        "macOS aarch64",
        "Windows",
        "Linux aarch64",
        "changelog",
        "release notes",
    ] {
        assert!(
            release_doc.contains(phrase),
            "release checklist should mention {phrase}"
        );
    }
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
fn public_pdf_docs_describe_destructive_redaction_default() {
    let readme = read_doc("README.md");
    let pdf_guide = read_doc("docs/pdf-redaction.md");

    for (path, doc) in [
        ("README.md", readme.as_str()),
        ("docs/pdf-redaction.md", pdf_guide.as_str()),
    ] {
        let lower = doc.to_lowercase();
        assert!(
            lower.contains("pdf redaction"),
            "{path} should label the default PDF mode as redaction"
        );
        assert!(
            doc.contains("destructive") || doc.contains("rewrites supported text"),
            "{path} should describe destructive PDF text rewriting"
        );
        assert!(
            doc.contains("--visual-mask-only"),
            "{path} should document the explicit visual masking option"
        );
    }

    assert!(
        pdf_guide.contains("underlying PDF text/content may remain extractable"),
        "PDF guide should warn that visual masking remains extractable"
    );

    for required_limit in ["OCR layers", "raster images", "fail closed"] {
        assert!(
            pdf_guide.contains(required_limit),
            "PDF guide should explicitly document limitation: {required_limit}"
        );
    }

    for required_scrub in [
        "Document info metadata",
        "XMP metadata",
        "Embedded files",
        "file attachment annotations",
        "Form fields",
        "Outlines/bookmarks",
        "named destinations",
        "interactive actions",
        "All page annotations",
    ] {
        assert!(
            pdf_guide.contains(required_scrub),
            "PDF guide should explicitly document hidden PDF scrub: {required_scrub}"
        );
    }

    let misleading_phrases = [
        "current overlay-only PDF mode",
        "This mode is not destructive",
    ];
    let mut offenders = Vec::new();

    for (path, doc) in [
        ("README.md", readme.as_str()),
        ("docs/pdf-redaction.md", pdf_guide.as_str()),
    ] {
        for phrase in misleading_phrases {
            if doc.contains(phrase) {
                offenders.push(format!("{path}: {phrase}"));
            }
        }
    }

    assert!(
        offenders.is_empty(),
        "public PDF docs still imply PDF is overlay-only by default:\n{}",
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
        "`--restore-bare`",
        "Bare tokens remain unchanged unless explicitly enabled",
        "`--mapping-stderr`",
        "`--include-mapping`",
        "owner-only permissions",
        "Proxy and UI modes keep mappings in memory by default",
        "`--persist-mapping`",
    ] {
        assert!(readme.contains(snippet), "README should mention {snippet}");
    }
}
