# Release Process

This checklist is the source of truth for the first public release and for
repeatable follow-up releases.

## Support Matrix

The first release supports these installation paths:

- crates.io source installs with `cargo install anon-pii`
- Linux x86_64 release archive from GitHub Releases
- macOS x86_64 release archive from GitHub Releases
- macOS aarch64 release archive from GitHub Releases

Windows and Linux aarch64 archives are deferred until the project has regular
test coverage on those targets. Users on those platforms can still install from
crates.io if their local Rust and system dependencies support the selected
features.

## CI Coverage

Every pull request must pass:

- `cargo fmt --all --check`
- `cargo clippy -- -D warnings`
- `cargo clippy --features ner-lite,proxy -- -D warnings`
- `cargo test`
- `cargo test --features ner-lite,proxy`
- `cargo test --features xlsx`
- `cargo test --features pdf`
- `cargo test --locked --test quality_corpus`
- `cargo test --locked --test quality_workflows`
- `cargo run --locked --example quality_report -- --check`
- `cargo build --release`

Main branch or manual checks additionally run:

- macOS default and `ner-lite,proxy` tests
- image/OCR tests with Tesseract, including ignored end-to-end OCR tests
- `cargo audit`
- `cargo deny check`

The ML `ner` feature requires ONNX Runtime and `ORT_DYLIB_PATH`; it is not part
of the required PR gate. Validate it manually before a release when NER model
or ONNX Runtime integration changes.

## Automated Tag Gates

The release workflow fails before starting builds unless all of these are true:

- the tag is a `v`-prefixed semantic version and exactly matches
  `package.version` in `Cargo.toml` at the tagged commit
- the tag resolves to the commit that triggered the workflow
- the tagged commit is contained in `main`

Containment is deliberate rather than requiring the tag to equal the latest
`main` commit. It rejects tags created from side branches while allowing `main`
to advance after a valid tag is pushed. The workflow then re-runs the portable
format, Clippy, test, package, and MSRV gates at the tagged commit before any
release binary is built or published.

To check a proposed tag locally after fetching `main` and creating the tag:

```bash
./scripts/release-preflight.sh vX.Y.Z <tag-commit> origin/main
```

## First Release Checklist

- Confirm `Cargo.toml` package metadata, repository URL, license, README, and
  included files are correct.
- Run `cargo fmt --all --check`.
- Run `cargo clippy -- -D warnings`.
- Run `cargo clippy --features ner-lite,proxy -- -D warnings`.
- Run `cargo test`.
- Run `cargo test --features ner-lite,proxy`.
- Run `cargo test --features xlsx`.
- Run `cargo test --features pdf`.
- Run `cargo test --locked --test quality_corpus`.
- Run `cargo test --locked --test quality_workflows`.
- Run `cargo run --locked --example quality_report -- --check` and inspect the
  version, corpus hash, and integer metrics.
- Run image checks on a host with Tesseract: `cargo test --features image` and
  `cargo test --features image -- --ignored`.
- Run `cargo audit`.
- Run `cargo deny check`.
- Dry-run the crate package with `cargo package --allow-dirty --no-verify`.
- Inspect the package contents and confirm no mappings, fixtures with real PII,
  credentials, or local runtime artifacts are included.
- Draft the changelog from Conventional Commit history.
- Draft release notes that include supported artifacts, feature flags, known
  limitations, and security/privacy caveats.
- Run the local release preflight against the proposed tag and commit.
- Tag the release as `vX.Y.Z` only after the checklist is complete.
- After the GitHub release workflow finishes, confirm each archive contains the
  `anon-pii` binary plus README and LICENSE.

## Release Notes

Release notes should include:

- headline changes and migration notes
- public feature flags and their system requirements
- artifact list for Linux x86_64, macOS x86_64, and macOS aarch64
- dependency advisory status from `docs/dependency-policy.md`
- known exclusions, including Windows and Linux aarch64 prebuilt archives
