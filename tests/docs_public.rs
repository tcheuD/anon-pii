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
        "docs/api.md",
        "docs/dependency-policy.md",
        "docs/entities.md",
        "docs/index.html",
        "docs/proxy.md",
        "docs/ner.md",
        "docs/image-redaction.md",
        "docs/pdf-redaction.md",
        "docs/quality.md",
        "docs/comparison-redact.md",
        "docs/release.md",
        "docs/threat-model.md",
        "docs/xlsx.md",
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
        !ci.contains("paths-ignore:"),
        "CI must validate documentation-only changes because docs carry product claims"
    );

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
fn quality_contract_is_a_required_ci_and_release_gate() {
    let ci = read_workflow(".github/workflows/ci.yml");
    let release = read_workflow(".github/workflows/release.yml");

    for snippet in [
        "quality-contract:",
        "name: Quality Contract",
        "- quality-contract",
        "needs.quality-contract.result",
        "cargo test --locked --test quality_corpus",
        "cargo test --locked --test quality_workflows",
        "cargo run --locked --example quality_report -- --check",
    ] {
        assert!(ci.contains(snippet), "CI should require `{snippet}`");
    }

    for command in [
        "cargo test --locked --test quality_corpus",
        "cargo test --locked --test quality_workflows",
        "cargo run --locked --example quality_report -- --check",
    ] {
        assert!(
            release.contains(command),
            "release verification should run `{command}`"
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
fn release_workflow_is_gated_before_build_and_publish() {
    let release = read_workflow(".github/workflows/release.yml");

    for snippet in [
        "preflight:",
        "./scripts/release-preflight.sh",
        "verify:",
        "msrv:",
        "needs: [verify, msrv]",
        "cargo clippy --locked -- -D warnings",
        "cargo clippy --locked --features ner-lite,proxy -- -D warnings",
        "cargo test --locked",
        "cargo test --locked --features ner-lite,proxy",
        "cargo test --locked --features xlsx",
        "cargo test --locked --features pdf",
        "cargo test --locked --test quality_corpus",
        "cargo test --locked --test quality_workflows",
        "cargo run --locked --example quality_report -- --check",
        "cargo package --locked",
        "cargo build --locked --release",
    ] {
        assert!(
            release.contains(snippet),
            "release workflow should contain gate `{snippet}`"
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

#[test]
fn product_positioning_is_pinned_and_quality_scoped() {
    let readme = read_doc("README.md");
    let quality = read_doc("docs/quality.md");
    let comparison = read_doc("docs/comparison-redact.md");

    for guide in ["docs/quality.md", "docs/comparison-redact.md"] {
        assert!(readme.contains(guide), "README should link {guide}");
        assert!(
            Path::new(env!("CARGO_MANIFEST_DIR")).join(guide).exists(),
            "{guide} should exist"
        );
    }

    for tier in ["**Core**", "**Secondary**", "**Experimental**"] {
        assert!(readme.contains(tier), "README should define {tier} scope");
        assert!(
            quality.contains(tier),
            "quality policy should define {tier} scope"
        );
    }

    let headline = readme
        .split("## Security & Privacy Notice")
        .next()
        .expect("README should have a security notice");
    for (claim, regex) in [
        (
            "headline recognizer count",
            Regex::new(r"(?i)\b[0-9]+\s+entity types\s*/\s*[0-9]+\s+patterns\b").unwrap(),
        ),
        (
            "unscoped headline throughput",
            Regex::new(r"(?i)~?[0-9]+(?:\.[0-9]+)?k?\s+lines/sec\b").unwrap(),
        ),
    ] {
        assert!(
            !regex.is_match(headline),
            "README should not make a {claim} claim without measurement context"
        );
    }

    for phrase in [
        "complete, finite UTF-8 payload",
        "buffered rather than streamed",
        "Child stdout is streamed",
        "Child stderr is inherited unchanged",
        "not a sandbox",
        "recognized values only",
        "not a compliance control",
    ] {
        assert!(
            readme.contains(phrase),
            "README should state run limitation: {phrase}"
        );
    }

    for pin in [
        "1a22680e43b29c80e141a39b0a66eb3dcafb7522",
        "123e1a955d43797d65fa9c4f342131a68d8af6d6",
    ] {
        assert!(comparison.contains(pin), "comparison should pin {pin}");
    }

    for phrase in [
        "does not declare a winner",
        "not an accuracy or performance benchmark",
        "repository revision and corpus revision",
        "true-positive, false-positive, and false-negative counts",
    ] {
        assert!(
            quality.contains(phrase) || comparison.contains(phrase),
            "quality docs should require evidence: {phrase}"
        );
    }
}

#[test]
fn comparison_evidence_is_pinned_and_matches_public_summary() {
    let report_source = read_doc("testdata/quality/comparison-redact-v1-report.json");
    let report: serde_json::Value = serde_json::from_str(&report_source).unwrap();
    let comparison = read_doc("docs/comparison-redact.md");

    assert_eq!(report["scope"]["case_count"], 50);
    assert_eq!(
        report["tools"]["anon_pii"]["revision"],
        "1a22680e43b29c80e141a39b0a66eb3dcafb7522"
    );
    assert_eq!(
        report["tools"]["censgate_redact"]["revision"],
        "123e1a955d43797d65fa9c4f342131a68d8af6d6"
    );
    assert_eq!(
        report["inputs"]["corpus"]["sha256"],
        "866c2292a7c0b5b06fb26b9bab32228dac64b5bb0c6b389ef4102194da3f03e7"
    );
    assert_eq!(
        report["metrics"]["anon_pii"]["overall"],
        serde_json::json!({
            "fn": 4,
            "fp": 0,
            "precision_ppm": 1_000_000,
            "recall_ppm": 882_352,
            "tp": 30
        })
    );
    assert_eq!(
        report["metrics"]["censgate_redact"]["overall"],
        serde_json::json!({
            "fn": 19,
            "fp": 14,
            "precision_ppm": 517_241,
            "recall_ppm": 441_176,
            "tp": 15
        })
    );

    for evidence in [
        "comparison-redact-v1-report.json",
        "| `anon-pii` | 30 | 0 | 4 | 100.0000% | 88.2352% |",
        "| `censgate/redact` | 15 | 14 | 19 | 51.7241% | 44.1176% |",
        "not an independent holdout",
    ] {
        assert!(
            comparison.contains(evidence),
            "comparison should publish evidence: {evidence}"
        );
    }
}

#[test]
fn public_positioning_rejects_absolute_or_unqualified_claims() {
    let forbidden = [
        (
            "absolute locality",
            Regex::new(
                r"(?i)\b(?:PII|nothing)\s+(?:ever\s+|never\s+)?leaves\s+(?:your|the)\s+machine\b",
            )
            .unwrap(),
        ),
        (
            "project superiority",
            Regex::new(
                r"(?i)\bbetter\s+than\b|\bsuperior\s+(?:to|than)\b|\bmore\s+(?:accurate|complete|capable)\s+than\b|\boutperforms?\b|\bfaster\s+than\b|\b[0-9]+(?:\.[0-9]+)?x\s+faster\b|\bbest[- ]in[- ]class\b",
            )
            .unwrap(),
        ),
        (
            "production suitability",
            Regex::new(
                r"(?i)\bproduction[- ]ready\b|\bready for production\b|\bproduction[- ]grade\b|\b(?:safe|suitable) for production\b",
            )
            .unwrap(),
        ),
        (
            "compliance certification",
            Regex::new(
                r"(?i)\b(?:GDPR|HIPAA|CCPA)[ -]compliant\b|\bcompliant\s+with\s+(?:GDPR|HIPAA|CCPA)\b|\bcompliance[- ](?:ready|certified)\b|\b(?:guarantees?|ensures?)\s+compliance\b",
            )
            .unwrap(),
        ),
    ];

    let mut offenders = Vec::new();
    for path in public_doc_paths() {
        let doc = read_doc(path);
        for (claim, regex) in &forbidden {
            for mat in regex.find_iter(&doc) {
                offenders.push(format!("{path}: {claim}: {}", mat.as_str()));
            }
        }
    }

    assert!(
        offenders.is_empty(),
        "public docs contain absolute or unqualified product claims:\n{}",
        offenders.join("\n")
    );
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
        "cargo test --locked --test quality_corpus",
        "cargo test --locked --test quality_workflows",
        "cargo run --locked --example quality_report -- --check",
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

#[test]
fn no_known_real_identifiers_in_public_text() {
    // Identifiers confirmed real during the 2026-07 PII audit. Constructed from
    // fragments so this guard file itself never contains them verbatim.
    let forbidden: Vec<String> = vec![
        format!("F-GRH{}", "K"),
        format!("F-HOP{}", "A"),
        format!("JD{}", "U"),
        format!("jdupon{}", "t@"),
        format!("mmartine{}", "z@"),
        format!("brunea{}", "u@"),
    ];
    let mut scan: Vec<std::path::PathBuf> = vec!["README.md".into()];
    for dir in ["docs", "src/detection/tests", "demo"] {
        if let Ok(rd) = std::fs::read_dir(dir) {
            for e in rd.flatten() {
                if e.path().is_file() {
                    scan.push(e.path());
                }
            }
        }
    }
    for path in scan {
        let Ok(text) = std::fs::read_to_string(&path) else {
            continue;
        };
        for f in &forbidden {
            assert!(
                !text.contains(f.as_str()),
                "forbidden real identifier {f:?} found in {path:?}"
            );
        }
    }
}
