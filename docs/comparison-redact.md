# Pinned comparison: `anon-pii` and `censgate/redact`

This document helps choose a workflow; it does not declare a winner. The two
projects overlap in pattern detection and anonymization, but their CLI and
deployment contracts emphasize different jobs.

## Compared snapshots

| Project | Repository | Commit |
|---------|------------|--------|
| `anon-pii` | `tcheuD/anon-pii` | `5e69c281b82f4d40a19d3951f94b1e5b76dc6785` |
| `redact` | `censgate/redact` | `123e1a955d43797d65fa9c4f342131a68d8af6d6` |

The observations below were recorded on 2026-07-13 from clean checkouts at
those commits. The `anon-pii` pin predates its transaction-owned `run` command;
that post-pin workflow is described separately and is not counted as an
observed capability of the pin.

## Configuration

Both CLIs were compiled in release mode with their lockfiles on Darwin arm64
using Rust 1.93.0.

| Setting | `anon-pii` | `redact` |
|---------|------------|----------|
| Build | Default features; regex/context/checksum recognizers; no NER | `redact-cli` with the default `AnalyzerEngine`; pattern registry only, with no NER recognizer registered by the CLI |
| Language | `en` default | `en` default |
| Detection threshold | CLI default `0.5` | Per-recognizer defaults in the pinned pattern registry |
| Transformation | Token operator | Default replace strategy |
| Structured fixture | Explicit `--format json` | Default text anonymization; its global `--format` controls output presentation rather than parsing input structure |

Changing any of these settings creates a different result. In particular, this
comparison says nothing about either optional NER path.

## Measured functional smoke check

These cases are deliberately small. They verify CLI semantics and make no
precision, recall, coverage, or performance claim. Random `anon-pii` token
suffixes are shown as `<random>`.

| Fixture | `anon-pii` observation | `redact` observation |
|---------|------------------------|----------------------|
| `Contact dev@example.com` | 1 detection; output `Contact [EMAIL_ADDRESS_<random>]` | 1 detection through `redact analyze` |
| `Card 4111111111111112` | 0 detections; input unchanged | 0 detections |
| `{"dev@example.com":"dev@example.com"}` | JSON key unchanged; value replaced with a random reversible token | Both key and value replaced with `[EMAIL_ADDRESS]` because the CLI treats the input as text |
| Standalone token roundtrip of `Contact dev@example.com` | Exact byte-for-byte restore with 1 replacement | Not run: the pinned CLI exposes `analyze` and `anonymize`, but no restore subcommand |

The JSON case measures a format contract, not detector accuracy. Treating a key
as content can be correct for one application and destructive for another.

### Reproduce

Build each pinned checkout:

```bash
# tcheuD/anon-pii at 5e69c281b82f4d40a19d3951f94b1e5b76dc6785
cargo build --locked --release

# censgate/redact at 123e1a955d43797d65fa9c4f342131a68d8af6d6
cargo build --locked --release -p redact-cli --bin redact
```

Then point `ANON` and `REDACT` at the two release binaries and run:

```bash
printf 'Contact dev@example.com\n' | "$ANON" --format text --verbose
printf 'Contact dev@example.com\n' | "$REDACT" analyze

printf 'Card 4111111111111112\n' | "$ANON" --format text --verbose
printf 'Card 4111111111111112\n' | "$REDACT" analyze

printf '%s\n' '{"dev@example.com":"dev@example.com"}' \
  | "$ANON" --format json --mapping ./comparison.map
printf '%s\n' '{"dev@example.com":"dev@example.com"}' \
  | "$REDACT" anonymize
```

Use a disposable mapping path when reproducing the detached roundtrip, and
remove it after inspection.

## Source-inspected product shape at the pins

| Question | `anon-pii` pin | `redact` pin |
|----------|----------------|--------------|
| Primary CLI shape | stdin/file anonymization plus a detached mapping/restore flow | Separate `analyze` and `anonymize` commands with entity filtering |
| Structure-aware input | Dedicated JSON-value, CSV-field, and SQL-literal paths | CLI passes the input string to the engine; JSON is available as an output representation for analysis |
| Reversibility surface | Random per-session tokens and a persisted token-to-original mapping | Replace, mask, hash, and encrypt strategies; no restore command in the inspected CLI |
| Library/server orientation | One crate with optional local API, UI, and proxy features | Workspace split into core, CLI, API, NER, and WASM crates, with container-oriented API documentation |
| Child-command orchestration | Not present at the pinned commit | Not present in the inspected CLI |

These are source observations, not quality scores. A larger workspace or a
larger recognizer inventory does not establish better detection, and a more
specialized workflow does not establish broader engine quality.

## Current `anon-pii` direction after the pin

The post-pin `run` workflow narrows `anon-pii` around local AI-assisted
debugging: buffer and anonymize finite stdin, start one child directly, stream
and restore child stdout, inherit stderr, keep the mapping in memory, and return
a shell-compatible exit code. It is not a sandbox, does not restore stderr, and
protects only recognized values.

That transaction is the main product distinction being pursued. It should be
evaluated as a workflow contract; it does not establish a detector-accuracy
ranking against `redact`.

## Choosing by use case

- Evaluate `anon-pii` when the requirement is a local, reversible,
  format-sensitive AI-debugging roundtrip with no long-running service.
- Evaluate `redact` when the requirement is an embeddable Rust engine,
  entity-filtered analysis, or an API/container deployment shape.
- Evaluate both on your own reviewed positives and negatives when detector
  coverage is the deciding factor.

Neither smoke output demonstrates legal de-identification, compliance, safety
for a particular dataset, or suitability for unattended handling of sensitive
records.

## What was not measured

- precision, recall, or F-score;
- optional heuristic or ML NER;
- latency, throughput, memory, or binary size;
- API, proxy, UI, WASM, image, PDF, or workbook paths; and
- behavior outside the two pinned revisions.

See the [quality and claim policy](quality.md) for the evidence required before
publishing broader or comparative claims.
