# Pinned comparison: `anon-pii` and `censgate/redact`

This document helps choose a workflow; it does not declare a winner. The
projects overlap in pattern detection and anonymization, but their CLI and
deployment contracts emphasize different jobs. A same-corpus diagnostic below
measures two specific default configurations and keeps its limitations visible.

## Compared snapshots

| Project | Repository | Commit |
|---------|------------|--------|
| `anon-pii` | `tcheuD/anon-pii` | `1a22680e43b29c80e141a39b0a66eb3dcafb7522` |
| `redact` | `censgate/redact` | `123e1a955d43797d65fa9c4f342131a68d8af6d6` |

The report was recorded on 2026-07-13 from clean checkouts at those commits. Its
environment was Darwin arm64, Python 3.11.1, and Rust 1.93.0. The generated
artifact records the revisions, corpus and manifest hashes, build commands,
configuration, binary hash, native predictions, and per-case results.

## Measured configuration

| Setting | `anon-pii` | `redact` |
|---------|------------|----------|
| Adapter | Repository `quality_report` example, executed by the comparison script | `redact-cli` release binary, built by the comparison script |
| Recognizers | Default regex, context, and checksum recognizers; no NER | Default `AnalyzerEngine` pattern registry; one `PatternRecognizer`; no NER registered by the CLI |
| Language | Default `en` | Explicit `--language en` |
| Threshold | `0.5` | Native pattern-registry minimum `0.5`; the CLI has no threshold override |
| Entity filter | None | None |
| Matching | Predeclared neutral family plus exact UTF-8 byte span | The same; native labels remain in the artifact |

Changing any setting creates a different result. In particular, this comparison
says nothing about either optional NER path.

## Shared-family exact-span diagnostic

The manifest selects every corpus case whose expected spans use only the eleven
predeclared shared native types: email, URL, IP address, phone, payment card,
IBAN, UUID/GUID, MAC address, and date/time families. Empty-label negative cases
are included by the same rule. This produces 50 of the 62 `debug-pii-v1` cases;
the twelve excluded cases require secret, password, connection-string,
authentication-token, or phone-extension types outside that shared scope.

Predictions match only when both the neutral family and exact UTF-8 byte range
match. A partial span or extra native type is a false positive, and the missed
annotation is a false negative. No prediction is filtered after either tool
runs.

| Tool | TP | FP | FN | Precision | Recall |
|------|---:|---:|---:|----------:|-------:|
| `anon-pii` | 30 | 0 | 4 | 100.0000% | 88.2352% |
| `censgate/redact` | 15 | 14 | 19 | 51.7241% | 44.1176% |

These counts establish behavior on this selected corpus, not general detector
quality. The corpus belongs to `anon-pii`, was developed alongside its detector
fixes, is small by entity family, and is not an independent holdout. For
example, the pinned `redact` configuration exactly detects the context-free GB
IBAN case that `anon-pii` intentionally retains as a challenge miss. Conversely,
several exact-span differences come from normalization, formatted values,
partial timestamp or IPv4-mapped IPv6 matches, and negative controls. Inspect
the per-case evidence rather than reading the aggregate as a universal ranking.

The checked-in
[`comparison-redact-v1-report.json`](../testdata/quality/comparison-redact-v1-report.json)
contains all selected inputs, labels, native predictions, neutral mappings,
scores available from `redact`, metadata, per-family counts, and exclusions.

### Reproduce

Prepare clean checkouts at the two pins, then run the adapter from the pinned
`anon-pii` checkout:

```bash
ANON_SRC=/path/to/anon-pii
REDACT_SRC=/path/to/redact

test "$(git -C "$ANON_SRC" rev-parse HEAD)" = \
  1a22680e43b29c80e141a39b0a66eb3dcafb7522
test "$(git -C "$REDACT_SRC" rev-parse HEAD)" = \
  123e1a955d43797d65fa9c4f342131a68d8af6d6

cd "$ANON_SRC"
./scripts/compare-quality.py \
  --redact-repo "$REDACT_SRC" \
  --output /tmp/comparison-redact-v1-report.json

jq '.metrics | map_values(.overall)' \
  /tmp/comparison-redact-v1-report.json
```

The adapter rejects tracked changes and unexpected GitHub origins. It generates
the `anon-pii` report in that checkout, builds the pinned `redact` CLI with its
lockfile, verifies the expected language and pattern-only recognizer metadata,
validates every raw source span, and aborts on tool or schema failures. Binary
hashes are platform-specific; the exact-span counts are the cross-environment
result to compare.

## Functional and product-shape observations

These source-inspected differences are workflow observations, not accuracy
scores.

| Question | `anon-pii` pin | `redact` pin |
|----------|----------------|--------------|
| Primary CLI shape | Transaction-owned `run`, plus stdin/file anonymization and detached mapping/restore | Separate `analyze` and `anonymize` commands with entity filtering |
| Structure-aware input | Dedicated JSON-value, CSV-field, and SQL-literal paths | CLI passes the input string to the engine; JSON is an analysis-output format, not structured-input parsing |
| Reversibility surface | `run` keeps random token mappings in memory; detached flows can persist a token-to-original map | Replace, mask, hash, and encrypt strategies; no restore command in the inspected CLI |
| Library/server orientation | One crate with optional local API, UI, and proxy features | Workspace split into core, CLI, API, NER, and WASM crates, with container-oriented API documentation |
| Child-command orchestration | Buffers bounded stdin, starts one child directly, restores known tokens from stdout, and inherits stderr | Not present in the inspected CLI |

For a small functional example, both pins detect `Contact dev@example.com` and
reject the invalid-Luhn value `Card 4111111111111112`. With
`{"dev@example.com":"dev@example.com"}`, `anon-pii --format json` preserves the
key and transforms the value, while the pinned `redact` CLI treats the input as
text and transforms both occurrences. The JSON case is a format contract, not a
detector-quality test; treating keys as content can be correct for one
application and destructive for another.

## Choosing by use case

- Evaluate `anon-pii` when the requirement is a local, reversible,
  format-sensitive AI-debugging roundtrip with no long-running service.
- Evaluate `redact` when the requirement is an embeddable Rust engine,
  entity-filtered analysis, or an API/container deployment shape.
- Evaluate both on independently reviewed positives and negatives from your own
  data when detector coverage is the deciding factor.

Neither the diagnostic nor the smoke examples demonstrate legal
de-identification, compliance, safety for a particular dataset, or suitability
for unattended handling of sensitive records.

## What was not measured

- an independent or union-taxonomy holdout corpus;
- optional heuristic or ML NER;
- latency, throughput, memory, or binary size;
- API, proxy, UI, WASM, image, PDF, or workbook paths; and
- behavior outside the two pinned revisions.

See the [quality and claim policy](quality.md) for the evidence required before
publishing broader claims.
