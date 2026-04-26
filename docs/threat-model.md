# Threat Model: anon

Date: 2026-02-04
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
- `~/.anon/mapping.json` and proxy session mapping files.
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
3. Mapping is persisted locally for restore (`src/main.rs`, `src/proxy/mod.rs`, `src/ui/mod.rs`).
4. Proxy forwards anonymized requests upstream and restores bracketed tokens in responses (`src/proxy/anthropic.rs`, `src/proxy/sse.rs`).

## Threat scenarios

| ID | STRIDE | Scenario | Impact | Current controls (repo evidence) | Residual risk | Priority |
|---|---|---|---|---|---|---|
| T1 | Information Disclosure | Local attacker or malware reads mapping files containing original PII. | High confidentiality loss. | Private dir/file permissions + atomic writes in CLI/proxy/UI (`src/main.rs:198`, `src/main.rs:213`, `src/proxy/mod.rs:68`, `src/proxy/mod.rs:160`, `src/ui/mod.rs:123`, `src/ui/mod.rs:152`). | Mapping is still plaintext at rest. Backups/indexers can expose it. | High |
| T2 | Spoofing / Elevation | Any local process can call proxy/UI endpoints (no auth layer), potentially using forwarded API credentials. | Unauthorized local usage, cost exposure, potential data misuse. | Loopback bind + host validation (`src/proxy/mod.rs:114`, `src/proxy/mod.rs:176`, `src/ui/mod.rs:372`, `src/ui/mod.rs:397`). | Same-host adversary still in trust zone. No bearer token or socket ACL auth. | High |
| T3 | Tampering | Maliciously modified mapping file causes incorrect or malicious restoration behavior. | Data integrity loss, accidental disclosure/corruption. | Proxy restore path uses bracketed-only restoration (`src/proxy/handler.rs:199`, `src/proxy/anthropic.rs:35`). | CLI/UI restore paths can use broad restore logic on untrusted mapping content (`src/main.rs:335`, `src/ui/mod.rs:340`, `src/mapping.rs:189`). | Medium |
| T4 | Denial of Service | Large payloads, long streams, or heavy detection/NER workloads exhaust CPU/memory. | Service slowdown/outage. | Input/body/SSE limits: 50 MB core max (`src/patterns.rs:331`), 10 MB proxy body (`src/proxy/handler.rs:15`), SSE caps/timeouts (`src/proxy/handler.rs:18`, `src/proxy/handler.rs:21`, `src/proxy/handler.rs:286`), UI max input (`src/ui/mod.rs:250`). | 50 MB text plus regex/NER remains expensive; no adaptive rate limit in UI/CLI path. | Medium |
| T5 | Information Disclosure | Redaction misses (false negatives) send sensitive data upstream unmasked. | High confidentiality loss. | Normalization + decoding + validators + overlap handling (`src/detection.rs:451`, `src/detection.rs:508`, `src/detection.rs:695`), format-aware paths (`src/detection.rs:780`, `src/detection.rs:814`). | Pattern-based detection is inherently incomplete for novel formats/entities. | High |
| T6 | Tampering / Supply Chain | Compromised model/runtime artifacts lead to malicious inference code or poisoned outputs. | Integrity compromise and possible code-execution vector. | SHA-256-pinned model downloads (`src/ner/download.rs:12`, `src/ner/download.rs:80`) and ORT path allowlist validation (`src/ner/ml.rs:6`, `src/ner/ml.rs:19`, `src/ner/ml.rs:79`). | Trust still anchored to pinned hashes and allowed filesystem prefixes; no signature/attestation workflow. | Medium |
| T7 | Repudiation | No structured audit trail linking anonymize/restore/proxy actions to a caller or request id. | Weak forensic traceability and incident response. | Minimal stderr logging only (multiple modules). | Hard to reconstruct misuse on shared machines. | Low |

## Existing strengths
- Proxy header forwarding is allowlisted to reduce credential/header leakage (`src/proxy/handler.rs:23`, `src/proxy/handler.rs:37`).
- Proxy restore path uses bracketed-token mode to reduce token-injection restoration risk (`src/proxy/handler.rs:199`, `src/proxy/anthropic.rs:39`).
- Session mapping in proxy has bounded entries (`src/proxy/mod.rs:21`, `src/proxy/mod.rs:33`).
- Host header checks and loopback binding reduce network-exposed attack surface (`src/proxy/mod.rs:114`, `src/ui/mod.rs:372`).

## Recommended mitigations (next iteration)
1. Protect mapping at rest: optional encryption with OS keychain key; add `--no-persist`/ephemeral mode as default for proxy/UI.
2. Add local auth for HTTP surfaces: random bearer token or Unix domain socket mode with filesystem ACLs.
3. Add mapping integrity checks: HMAC/signature on mapping files; strict mode to restore only bracketed tokens in CLI/UI unless explicitly overridden.
4. Add abuse controls: configurable request timeout, lower default size ceilings for proxy/UI, and optional per-minute rate limiting.
5. Improve redaction assurance: corpus-based coverage tests and custom pattern packs per organization/domain.
6. Add structured security audit logs: request id, mode, counts only (never raw PII), with optional local retention policy.

