# Threat Model: anon

Date: 2026-04-27
Method: STRIDE-lite (repo-evidence based)

## Scope
- In scope: Rust CLI anonymization flow, mapping persistence/restoration, proxy mode, local UI mode, optional NER model download/loading.
- Out of scope: Anthropic infrastructure internals, OS compromise, user workstation hardening, third-party service account policies.

## Security objectives
- Prevent leakage of raw PII to external systems.
- Preserve integrity of anonymization and restoration mappings.
- Keep local proxy/UI usage constrained to trusted callers.
- Maintain service availability under malformed or abusive input.

## Assets
- Raw input content with PII.
- `~/.anon-pii/mapping.json` and proxy session mapping files.
- API credentials forwarded by proxy headers.
- Anonymized output sent to upstream services.
- NER model/runtime artifacts (`model.onnx`, tokenizer/config, ORT dylib).

## Trust boundaries
- Boundary A: local caller process -> `anon-pii` CLI/proxy/UI.
- Boundary B: in-memory anonymization state -> persisted mapping files.
- Boundary C: local process -> external network (`upstream` API, model download).
- Boundary D: browser/client -> localhost UI and proxy HTTP endpoints.

## Data flow (high-level)
1. Input arrives via stdin/file (`src/main.rs`) or HTTP (`src/proxy/handler.rs`, `src/ui/mod.rs`).
2. Detection pipeline normalizes input, scans patterns, optional NER, then replaces spans with generated tokens (`src/detection.rs`).
3. CLI token-mode mappings are persisted locally for restore; proxy/UI mappings are memory-only unless explicit persistence is enabled (`src/main.rs`, `src/proxy/mod.rs`, `src/ui/mod.rs`).
4. Proxy forwards anonymized requests upstream and restores bracketed tokens in responses (`src/proxy/anthropic.rs`, `src/proxy/sse.rs`); UI `/api/restore` also restores bracketed tokens by default (`src/ui/mod.rs`).

## Threat scenarios

| ID | STRIDE | Scenario | Impact | Current controls (repo evidence) | Residual risk | Priority |
|---|---|---|---|---|---|---|
| T1 | Information Disclosure | Local attacker or malware reads mapping files containing original PII. | High confidentiality loss. | Private dir/file permissions + atomic writes in CLI, plus proxy/UI memory-only defaults unless `--persist-mapping` is supplied. | CLI mappings and any explicitly persisted proxy/UI mappings are still plaintext at rest. Backups/indexers can expose them. Mapping-at-rest encryption is out of scope for first public release until key management is designed. | Medium |
| T2 | Spoofing / Elevation | Any local process can call proxy/UI endpoints (no auth layer), potentially using forwarded API credentials. | Unauthorized local usage, cost exposure, potential data misuse. | Loopback bind + host validation (`src/proxy/mod.rs`, `src/ui/mod.rs`). Launch docs explicitly prohibit tunnels, container port exposure, and shared-host use without external controls. | Same-host adversary remains in trust zone. Bearer-token or socket ACL auth is a post-launch hardening item because proxy auth must not collide with upstream provider credentials. | High |
| T3 | Tampering | Maliciously modified mapping file causes incorrect or malicious restoration behavior. | Data integrity loss, accidental disclosure/corruption. | Proxy and UI restore paths use bracketed-only restoration (`src/proxy/handler.rs`, `src/proxy/anthropic.rs`, `src/ui/mod.rs`). | CLI restore can still use broad restore logic on untrusted mapping content (`src/main.rs`, `src/mapping.rs`). | Medium |
| T4 | Denial of Service | Large payloads, long streams, or heavy detection/NER workloads exhaust CPU/memory. | Service slowdown/outage. | Input/body/SSE limits: 50 MB core max (`src/patterns.rs:331`), 10 MB proxy body (`src/proxy/handler.rs:15`), SSE caps/timeouts (`src/proxy/handler.rs:18`, `src/proxy/handler.rs:21`, `src/proxy/handler.rs:286`), UI max input (`src/ui/mod.rs:250`). | 50 MB text plus regex/NER remains expensive; no adaptive rate limit in UI/CLI path. | Medium |
| T5 | Information Disclosure | Redaction misses (false negatives) send sensitive data upstream unmasked. | High confidentiality loss. | Normalization + decoding + validators + overlap handling, format-aware paths, and prominent README/proxy documentation caveats. | Pattern/NER-based detection is inherently incomplete for novel formats, domain-specific entities, split secrets, non-Latin text, and ambiguous names. | High |
| T6 | Tampering / Supply Chain | Compromised model/runtime artifacts lead to malicious inference code or poisoned outputs. | Integrity compromise and possible code-execution vector. | SHA-256-pinned model downloads (`src/ner/download.rs:12`, `src/ner/download.rs:80`) and ORT path allowlist validation (`src/ner/ml.rs:6`, `src/ner/ml.rs:19`, `src/ner/ml.rs:79`). | Trust still anchored to pinned hashes and allowed filesystem prefixes; no signature/attestation workflow. | Medium |
| T7 | Repudiation | No structured audit trail linking anonymize/restore/proxy actions to a caller or request id. | Weak forensic traceability and incident response. | Minimal stderr logging only (multiple modules). | Hard to reconstruct misuse on shared machines. | Low |

## Existing strengths
- Proxy header forwarding is allowlisted to reduce credential/header leakage (`src/proxy/handler.rs:23`, `src/proxy/handler.rs:37`).
- Proxy/UI restore paths use bracketed-token mode to reduce token-injection restoration risk (`src/proxy/handler.rs`, `src/proxy/anthropic.rs`, `src/ui/mod.rs`).
- Proxy/UI mapping persistence is disabled by default; explicit persistence is required before reversible mappings are written by those HTTP modes.
- Host header checks and loopback binding reduce network-exposed attack surface (`src/proxy/mod.rs:114`, `src/ui/mod.rs:372`).

## Recommended mitigations (next iteration)
1. Protect mapping at rest: optional encryption with OS keychain key for CLI and explicitly persisted HTTP-mode mappings.
2. Add local auth for HTTP surfaces: random bearer token using a header that cannot be confused with upstream provider credentials, or Unix domain socket mode with filesystem ACLs.
3. Add mapping integrity checks: HMAC/signature on mapping files; consider strict mode or explicit opt-in for bare-token restoration in CLI workflows.
4. Add abuse controls: configurable request timeout, lower default size ceilings for proxy/UI, and optional per-minute rate limiting.
5. Improve redaction assurance: corpus-based coverage tests and custom pattern packs per organization/domain.
6. Add structured security audit logs: request id, mode, counts only (never raw PII), with optional local retention policy.
