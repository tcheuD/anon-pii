# Quality and claim policy

`anon-pii` is a local data-minimization tool for AI-assisted debugging. Quality
means that a documented workflow behaves predictably on representative inputs;
it does not mean that every sensitive value will be detected.

The automated contract is versioned in
[`testdata/quality/v1.json`](../testdata/quality/v1.json), with ratcheted limits
in [`v1-baseline.json`](../testdata/quality/v1-baseline.json). The corpus hash
binds the labels and baseline together; changing either is an explicit reviewed
change rather than an invisible score reset.

## Scope tiers

| Tier | Surface | Quality expectation |
|------|---------|---------------------|
| **Core** | `run`; default regex, context, and checksum recognizers; reversible tokens; text, JSON, CSV, and SQL | Required release gates cover detection regressions, original-span replacement, format fidelity, mapping lifecycle, and roundtrip behavior |
| **Secondary** | Detached mapping/restore flows, custom recognizers, heuristic name detection, local API/UI/proxy modes | Maintained and tested, but evaluated separately from the default local transaction because configuration and trust boundaries differ |
| **Experimental** | ML NER, OCR image redaction, PDF redaction, and XLSX detection | Optional, dependency- or format-sensitive, and unsuitable for broad claims without fixture-specific validation |

Moving a surface between tiers requires tests and documentation that match its
real trust boundary and failure modes. A feature count alone is not evidence of
detection quality.

## Core workflow contract

For `anon-pii run -- <command> [args...]`:

1. stdin must be finite UTF-8 and within the configured input-size limit;
2. the complete input is buffered and anonymized before the child starts;
3. only the anonymized payload is written to child stdin;
4. known bracketed tokens are restored while child stdout is streamed;
5. child stderr is inherited unchanged and is not restored;
6. the reversible mapping stays in memory for that invocation; and
7. the wrapper returns a shell-compatible child exit code.

`run` is not an interactive or unbounded-streaming protocol. It is also not a
sandbox: it does not restrict the child process's network, filesystem,
environment, subprocesses, or other side effects.

The contract applies only to values recognized by the selected recognizers and
thresholds. False negatives, child-generated sensitive output, and sensitive
stderr remain possible. The tool is not a compliance control and does not prove
that a payload is anonymous.

## Quality gates

### Detection measurements

Any precision, recall, or F-score result must come from a versioned, reviewed
corpus with explicit positive spans and explicit negative examples. A published
result must include:

- repository revision and corpus revision;
- build features, recognizer configuration, language, and threshold;
- exact command;
- true-positive, false-positive, and false-negative counts, both overall and by
  entity type;
- exclusions, skipped cases, and known annotation ambiguity; and
- whether optional NER or external runtimes were available.

Results from different configurations are separate measurements. They must not
be merged into a single project-wide accuracy number.

Rates with no denominator are reported as `null`, not as 100%. Raw TP, FP, and
FN counts remain authoritative.

### Default-feature corpus v1

`debug-pii-v1` (SHA-256
`866c2292a7c0b5b06fb26b9bab32228dac64b5bb0c6b389ef4102194da3f03e7`)
contains 62 fictional cases, 46 annotated exact spans, 18 negative cases, 16
expected entity types, and both contract and challenge tiers. Matching requires
the entity type, UTF-8 byte range, and raw source bytes to agree.

At `anon-pii` revision
`1a22680e43b29c80e141a39b0a66eb3dcafb7522`, default features, threshold `0.5`,
and no NER, `cargo run --locked --example quality_report -- --check` reports
41 TP, 0 FP, and 5 FN: 100.0000% measured precision and 89.1304% measured recall. Those
numbers describe this project-owned corpus, not arbitrary production data.

All contract cases and every non-exempt case must remain exact. The five
reviewed challenge exceptions are intentionally visible in the baseline:

- context-free phone;
- context-free IBAN;
- lowercase IBAN;
- Basic authentication header; and
- newline-split email.

An improvement to an exception passes. Moving a miss to any other case does
not. Baseline limits also apply overall, by tier, category, and entity type.
The separate `debug-workflows-v1` corpus covers eight reversible text, JSON,
CSV, SQL, and restore workflows.

### Correctness invariants

The release gate for the core workflow must cover:

- exact source spans after Unicode, escaped, URL-encoded, and multiline
  detection paths;
- checksum and context validators with valid values, invalid near-misses, and
  benign numeric or identifier-shaped negatives;
- deterministic overlap resolution;
- token-to-original roundtrip equality;
- fail-safe mapping lifecycle, including no empty-map overwrite and no child
  spawn when a transaction cannot be restored;
- JSON key preservation, CSV record fidelity, and SQL lexical preservation; and
- streaming restoration across every token boundary while preserving unknown,
  malformed, and non-UTF-8 child-output bytes.

### Repository checks

Run the default and shared-feature gates with the lockfile:

```bash
cargo fmt --all --check
cargo test --locked
cargo test --locked --features ner-lite,proxy
cargo clippy --locked -- -D warnings
cargo clippy --locked --features ner-lite,proxy -- -D warnings

# Deterministic default-feature product contract
cargo test --locked --test quality_corpus
cargo test --locked --test quality_workflows
cargo run --locked --example quality_report -- --check
```

Optional features need their own documented environment and tests. A passing
default build is not evidence that an ONNX, OCR, PDF, or workbook workflow was
exercised.

## Publishing performance results

A performance statement must identify the revision, build profile, feature
set, input distribution and size, warm-up, repetitions, hardware, operating
system, and exact command. Report latency percentiles or throughput with units;
do not extrapolate a microbenchmark to end-to-end AI workflows.

Cross-project results require the same task, input, output requirement, and
measurement boundary. If one command performs structural parsing or reversible
mapping work and another does not, publish the raw observations but do not turn
them into a speed ranking.

## Cross-project measurements

The pinned [`censgate/redact` comparison](comparison-redact.md) includes a
reproducible same-corpus diagnostic through documented adapters. Its shared
subset comes from this project's corpus, uses a predeclared neutral family map,
and retains every native label and raw source span without using native labels
as a comparative score.
It is not an accuracy or performance benchmark, and the selected cases are not
independent test data.
