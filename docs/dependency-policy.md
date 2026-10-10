# Dependency Policy

This project treats dependency advisories as release blockers.

## Security Checks

- `cargo audit` must exit successfully. Vulnerabilities require a dependency update or a documented RustSec ignore with a launch-risk justification.
- Informational `cargo audit` warnings may remain only when this file documents the dependency path, impact, and follow-up.
- `cargo deny check` must exit successfully. Warnings are acceptable only when they are reviewed and noted here.
- Lockfile-only updates are acceptable when they move a transitive dependency to a patched version inside the existing semver range.

## Current Advisory Status

- `rustls` was updated from `0.23.41` to `0.23.45` for RUSTSEC-2026-0285 (TLS 1.3 handshake messages accepted across encryption levels). It is used by the optional proxy's `reqwest` stack and the ML NER `ureq` stack. No advisory ignore was added.
- `rustls-webpki` is now `0.103.15`; this retains the prior fixes for RUSTSEC-2026-0049, RUSTSEC-2026-0098, RUSTSEC-2026-0099, and RUSTSEC-2026-0104.
- `rand` was updated from `0.9.2` to `0.9.3`, which satisfies the fixed range for RUSTSEC-2026-0097. It remains a transitive dependency through the optional `tokenizers` and `lopdf` graphs, and it can also appear in the `reqwest` lockfile graph.
- The yanked `chacha20 0.10.1` was replaced with `0.10.2` in the transitive `rand 0.10.2` graph used by PDF and optional networking dependencies.
- `paste 1.0.15` remains as an informational unmaintained warning, RUSTSEC-2024-0436, through optional ML NER's `tokenizers 0.23.1` and `macro_rules_attribute 0.2.2`. It is a build-time macro dependency, is not enabled in the default core or release archive features, and has no reported vulnerability in the audit snapshot. Keep this warning under review when updating `tokenizers`.

## Current cargo-deny Warnings

- `cargo deny check` still reports duplicate `getrandom` versions. The duplicate comes from legacy transitive support dependencies alongside the direct `getrandom 0.4` dependency. This is acceptable for launch while it remains a warning and has no active advisory.

## Verification Snapshot

Recorded on 2026-10-10 after the v0.2.0 lockfile updates:

- `cargo-audit 0.22.1 audit --json` exits 0 with zero vulnerabilities and one allowed informational warning: RUSTSEC-2024-0436 for `paste 1.0.15`.
- Advisory database: 1,296 advisories at revision `7eebec69c352c7191b1f13eb95dd510eeca5d1de` (updated 2026-10-09).
- Main-branch CI must rerun both advisory checks on the final release commit before tagging; a prior successful scan is not a future guarantee.
