# Dependency Policy

This project treats dependency advisories as release blockers for the public launch.

## Security Checks

- `cargo audit` must exit successfully. Vulnerabilities require a dependency update or a documented RustSec ignore with a launch-risk justification.
- Informational `cargo audit` warnings may remain only when this file documents the dependency path, impact, and follow-up.
- `cargo deny check` must exit successfully. Warnings are acceptable only when they are reviewed and noted here.
- Lockfile-only updates are acceptable when they move a transitive dependency to a patched version inside the existing semver range.

## Current Advisory Status

- `rustls-webpki` was updated from `0.103.9` to `0.103.13`, which satisfies the fixed range for RUSTSEC-2026-0049, RUSTSEC-2026-0098, RUSTSEC-2026-0099, and RUSTSEC-2026-0104.
- `rand` was updated from `0.9.2` to `0.9.3`, which satisfies the fixed range for RUSTSEC-2026-0097. It remains a transitive dependency through the optional `tokenizers` and `lopdf` graphs, and it can also appear in the `reqwest` lockfile graph.
- `paste 1.0.15` remains as an informational unmaintained warning, RUSTSEC-2024-0436, through `tokenizers 0.22.2` and `macro_rules_attribute 0.2.2`. `tokenizers 0.22.2` is the current crates.io release as of 2026-04-24, and the project does not depend on `paste` directly. Keep this warning under review when updating `tokenizers`.

## Current cargo-deny Warnings

- `cargo deny check` still reports duplicate `getrandom` versions. The duplicate comes from legacy transitive support dependencies alongside the direct `getrandom 0.4` dependency. This is acceptable for launch while it remains a warning and has no active advisory.

## Verification Snapshot

Recorded on 2026-04-24:

- `cargo audit` exits 0 with one allowed informational warning: RUSTSEC-2024-0436 for `paste 1.0.15`.
- `cargo deny check` exits 0 with one reviewed warning: duplicate `getrandom` versions.
- `cargo test`, `cargo test --features ner-lite,proxy`, and `cargo test --features xlsx` pass.
- `cargo check --features pdf` and `cargo check --features ner` pass.
