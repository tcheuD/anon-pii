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

`run --dry-run` exercises the same preparation path but returns the prepared
payload on stdout without starting a child. It accepts an optional command,
reports unique detection counts on stderr without original values, and neither
creates nor replaces a persisted mapping. Preview output keeps the prepared
payload's exact bytes, including its trailing-newline behavior. Its tests cover
text, JSON, CSV, SQL, custom recognizers, thresholds, invalid input, command
argument forwarding, and preservation of an existing detached mapping.
Preview tokens are invocation-local and cannot be restored after exit. A later
`run` invocation is a fresh transaction, not execution of saved preview bytes.

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

Initially, at `anon-pii` revision
`1a22680e43b29c80e141a39b0a66eb3dcafb7522`, default features, threshold `0.5`,
and no NER, `cargo run --locked --example quality_report -- --check` reported
41 TP, 0 FP, and 5 FN: 100.0000% measured precision and 89.1304% measured recall. Those
numbers describe this project-owned corpus, not arbitrary production data.

After Basic authentication detection was added at revision
`0e5d6f253753cc3cf8a8d34f27168f26b1b9e90c`, the same unchanged corpus,
configuration, and command reported 42 TP, 0 FP, and 4 FN: 100.0000% measured precision and 91.3043% measured recall.
The Basic-auth case now matches its exact credential span, and the baseline
requires that match. The overall, challenge, secrets, and AUTH_TOKEN gates were
tightened; corpus labels and the remaining exceptions were not changed.

After compact ASCII-case IBAN detection was added at revision
`b678727b9e2efc5b495efb26a19c838a96dca383`, the same unchanged corpus,
configuration, and command report 43 TP, 0 FP, and 3 FN: 100.0000% measured precision and 93.4782% measured recall.
The lowercase IBAN case now matches its exact source span and is required by the
baseline. Overall, challenge, financial, and IBAN_CODE limits were tightened;
the corpus labels were not changed. These are maintainer regression measurements,
not evidence of customer adoption or production accuracy.

After wrapped-email detection was added at revision
`02df69dc677cd6df92985deadbb383b734efc868`, the same corpus, configuration, and command report
44 TP, 0 FP, and 2 FN: 100.0000% measured precision and 95.6521% measured recall.
The newline-split email now matches its exact source span and is required by the
baseline. Overall, challenge, normalization, and EMAIL_ADDRESS limits were
tightened without changing corpus labels.

After context-free compact UK IBAN detection was added at revision
`1e5f82ee0172b0ffafb05305a82fbd0be06b0313`, the same unchanged corpus and
configuration measured with `cargo run --locked --example quality_report -- --json`
report 45 TP, 0 FP, and 1 FN: 100.0000% measured precision and 97.8260% measured recall.
The compact GB case now matches its exact source span and is required by the
baseline. Overall, challenge, financial, and IBAN_CODE gates were tightened;
the corpus labels remain unchanged. These are maintainer regression measurements,
not customer adoption or production-accuracy estimates.

| Entity type | TP | FP | FN |
|-------------|---:|---:|---:|
| AUTH_TOKEN | 2 | 0 | 0 |
| CONNECTION_STRING | 1 | 0 | 0 |
| CREDIT_CARD | 4 | 0 | 0 |
| DATE_TIME | 1 | 0 | 0 |
| EMAIL_ADDRESS | 9 | 0 | 0 |
| FR_IBAN | 1 | 0 | 0 |
| FR_PHONE_NUMBER | 1 | 0 | 0 |
| IBAN_CODE | 3 | 0 | 0 |
| IP_ADDRESS | 4 | 0 | 0 |
| MAC_ADDRESS | 2 | 0 | 0 |
| PASSWORD | 3 | 0 | 0 |
| PHONE_EXTENSION | 1 | 0 | 0 |
| PHONE_NUMBER | 3 | 0 | 1 |
| SECRET_KEY | 5 | 0 | 0 |
| URL | 4 | 0 | 0 |
| UUID | 1 | 0 | 0 |

Generic lowercase and mixed-case IBAN recognition covers compact ASCII forms
and retains the existing context and checksum requirements. French compact and
fixed print forms also accept ASCII casing. Replacement and restoration preserve
the original casing and surrounding text. Outside the country-specific French
and UK print rules, grouped lowercase forms remain unsupported; broadly
accepting spaced words risks including following prose.

The separate compact UK rule recognizes a complete 22-character GB IBAN without
a context keyword: ASCII-case `GB`, check digits 02–98, four ASCII bank letters,
and fourteen digits, with word boundaries and a valid mod-97 checksum. It keeps
score `0.7`, including when financial context is present; threshold `0.8`
rejects it. These structural guarantees apply to this new context-free rule;
the existing context-gated generic rule remains broader. Grouped UK forms still
require context. This improvement is included in source builds and the browser
engine. Native archives through v0.3.5 do not include it; v0.3.6 is the first
native release with this rule.

Current source builds and the browser engine also recognize ASCII-case UK print
groups such as `gb82 west 1234 5698 7654 32` with space/tab separators, a financial
keyword outside the IBAN, and a valid mod-97 checksum. The fixed 4-4-4-4-4-2 groups
enforce the same national fields and check-digit range as the compact UK rule.
Replacement and restoration preserve the original separators and spelling. This rule does
not extend lowercase/mixed-case support across line breaks. It keeps score
`0.7` and requires context; threshold `0.8` rejects it. The broader generic
uppercase matcher is unchanged. Native v0.3.8 is the first archive release
with this grouped-casing support; earlier archives lack it.

The built-in URL recognizer keeps percent-encoded spaces, quotes, and delimiters
inside a complete URL when its scheme is recognized before percent decoding.
This includes NFKC and Unicode-escape normalization. Fully percent-encoded
schemes retain the existing decoded matching path and its boundary limitations.
Literal surrounding whitespace and punctuation retain the existing boundaries.
Query values are decoded separately for inner PII audit detections, which refer
to the original encoded bytes;
replacement masks the enclosing URL once. The local API's `/analyze` output
remains non-overlapping and can feed `/anonymize` directly, including when only
an inner entity type is selected. Native v0.3.8 is the first archive release
with this encoded-URL fix. Source and browser workflow checks also cover it.

Wrapped emails support one LF or CRLF immediately after `@`, followed by optional
spaces/tabs and a complete domain. Preparation and restoration preserve the
source newline, indentation, and spelling. Blank lines, whitespace before the
line break, and domains split across more lines remain unsupported. An incomplete
prefix cannot consume a complete address on the next line. A domain-only next
line can be indistinguishable from a wrapped address; review the prepared text.
This improvement applies to v0.3.3 native archives, source builds, and the browser
engine. Older v0.3.2 native archives do not include it.

All contract cases and every non-exempt case must remain exact. The remaining
reviewed challenge exception, context-free phone, is intentionally visible in
the baseline.

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
