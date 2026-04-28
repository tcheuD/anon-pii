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
- `cargo build --release`

Main branch or manual checks additionally run:

- macOS default and `ner-lite,proxy` tests
- image/OCR tests with Tesseract, including ignored end-to-end OCR tests
- `cargo audit`
- `cargo deny check`

The ML `ner` feature requires ONNX Runtime and `ORT_DYLIB_PATH`; it is not part
of the required PR gate. Validate it manually before a release when NER model
or ONNX Runtime integration changes.

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
