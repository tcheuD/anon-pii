# Release Process

This checklist is the source of truth for repeatable releases. GitHub Releases
is the supported binary distribution channel; v0.2.0 has already
been published. The next release is v0.3.0.

## Support Matrix

Supported installation paths:

- source installs from the repository with `cargo install --locked --path .`
- Linux x86_64 release archive from GitHub Releases
- macOS x86_64 release archive from GitHub Releases
- macOS aarch64 release archive from GitHub Releases

The crate is not published on crates.io. Do not advertise `cargo install
anon-pii` until registry publication has been separately completed and verified.
Windows and Linux aarch64 archives are deferred until the project has regular
test coverage on those targets. Users on those platforms can build from source
if their local Rust and system dependencies support the selected features.

Archives include `ner-lite,proxy,pdf`, the `anon-pii` binary, README, and MIT
LICENSE. Heuristic name detection still requires `--ner`. ML NER, OCR, and XLSX
are not compiled into these archives. Source builds require Rust 1.88 or newer.
The Linux GNU binary is built on Ubuntu 24.04; macOS binaries are built and
smoke-tested on macOS 15 runners matching each architecture. These are the
tested environments, not a promise of compatibility with every older OS.

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
- `node scripts/test-ticket-workspace.mjs` against the checked-in WASM (Playwright
  1.62.1 with Chromium; CI installs the driver separately and uses Google Chrome)

Main branch or manual checks additionally run:

- macOS default and `ner-lite,proxy` tests
- image/OCR tests with Tesseract, including ignored end-to-end OCR tests
- `cargo audit`
- `cargo deny check`

The ML `ner` feature requires ONNX Runtime and `ORT_DYLIB_PATH`; it is not part
of the required PR gate. Validate it manually before a release when NER model
or ONNX Runtime integration changes.

Wait for every main-branch CI job, including the additional jobs above, to pass
at the intended release commit before pushing its tag. Tag verification reruns
the portable gates; it does not replace the macOS, OCR, or dependency checks.

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
release binary is built or published. Each archive is then extracted on its
target runner and checked with `scripts/release-smoke.py`. This verifies the
version, preview without a child process, actual tokenized child stdin, exact
`run -- cat` restoration, the support-ticket name/address roundtrip with `--ner`,
and absence of a persisted transaction mapping.

Packaging fails if README or LICENSE is missing. Release assets include
`SHA256SUMS`, whose entries use archive basenames so downloads can be checked
in the same directory:

```bash
# Linux, after downloading the archives and SHA256SUMS
sha256sum --check --ignore-missing SHA256SUMS

# macOS, after downloading the archives and SHA256SUMS
shasum -a 256 --check --ignore-missing SHA256SUMS
```

Checksums detect incomplete or changed downloads. They are not independent
signatures or artifact attestations.

To check a proposed tag locally after fetching `main` and creating the tag:

```bash
./scripts/release-preflight.sh vX.Y.Z <tag-commit> origin/main
```

## First Release Checklist and Follow-up Releases

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
- Rebuild the browser engine with `scripts/build-wasm.sh` after detector changes.
- Run `node scripts/test-ticket-workspace.mjs` with Playwright available through
  `NODE_PATH`; set `CHROMIUM_PATH` if Chromium is not in a standard location.
- Run `cargo audit`.
- Run `cargo deny check`.
- Confirm all main-branch CI jobs passed on the commit to be tagged, including
  macOS and OCR checks.
- Dry-run the crate package with `cargo package --allow-dirty --no-verify`.
- Inspect the package contents and confirm no mappings, fixtures with real PII,
  credentials, or local runtime artifacts are included.
- Draft the changelog from Conventional Commit history.
- Draft release notes that include supported artifacts, feature flags, known
  limitations, and security/privacy caveats.
- Save curated notes as `docs/releases/vX.Y.Z.md`. The release workflow uses
  that file when present; later tags without one fall back to the generated
  changelog and GitHub release notes.
- Update `package.version` and the root package entry in `Cargo.lock` together.
  Never move an existing published tag to new code.
- Run the local release preflight against the proposed tag and commit.
- Tag the release as `vX.Y.Z` only after the checklist is complete.
- After the GitHub release workflow finishes, confirm each archive contains the
  `anon-pii` binary plus README and LICENSE, and the release contains
  `SHA256SUMS` plus both SBOM formats. Download and verify at least the archive
  for the local platform, then run the smoke script against its extracted
  binary:

  ```bash
  python3 scripts/release-smoke.py --binary ./anon-pii --version X.Y.Z
  ```

## Release Notes

Release notes should include:

- headline changes and migration notes
- public feature flags and their system requirements
- artifact list for Linux x86_64, macOS x86_64, and macOS aarch64
- dependency advisory status from `docs/dependency-policy.md`
- known exclusions, including Windows and Linux aarch64 prebuilt archives

The generated SBOMs describe the Cargo dependency graph, including optional
dependencies. They are not a list of only the code linked into each binary.
