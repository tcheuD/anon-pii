# Quality and claim policy

`anon-pii` is a local data-minimization tool for AI-assisted debugging. Quality
means that a documented workflow behaves predictably on representative inputs;
it does not mean that every sensitive value will be detected.

This policy was written against `anon-pii` commit
`5e69c281b82f4d40a19d3951f94b1e5b76dc6785`. That pin is an evidence baseline,
not a claim about every later revision. The transaction-owned `run` command is
layered after that baseline and must pass the same gates before release.

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

## Current comparison status

The pinned [`censgate/redact` comparison](comparison-redact.md) contains a small
default-configuration functional smoke check and source-inspected workflow
differences. It is not an accuracy or performance benchmark. No cross-project
precision/recall ranking is published until both tools are evaluated through
documented adapters on the same reviewed corpus.
