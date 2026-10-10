# Product direction

Decision date: 2026-10-10.

Make the local AI-debugging roundtrip useful enough to become a developer's
habit: inspect the outgoing payload, send recognized values as reversible
tokens, and get a usable answer back with the original context restored.

## Initial user and job

Focus on developers and support engineers preparing finite incident logs,
API responses, CSV extracts, and SQL examples for AI-assisted diagnosis.
The useful outcome is a debugging answer that retains context while reducing
the sensitive data sent through stdin to the chosen tool.

This is a product hypothesis, not evidence of customer demand. The repository
has a tested CLI and a versioned quality corpus; it does not establish active
usage, retention, willingness to pay, or detection performance on customer data.

## Priorities

| Order | Outcome | Acceptance evidence |
|-------|---------|---------------------|
| 1 | Users can inspect a payload before trying an AI command | `run --dry-run` works without an AI tool, follows the normal preparation path, prints detection counts without original values, and leaves mappings untouched. Synthetic CLI tests cover supported core formats and failure paths. |
| 2 | Common debugging credentials are covered predictably | Basic authentication now has synthetic positive and negative cases plus exact-span and roundtrip checks. On the unchanged versioned corpus, true positives increased from 41 to 42 with zero false positives; the baseline now requires the recovered case. Four misses remain visible. |
| 3 | A new user can install and complete the workflow reliably | Follow the release checklist, verify supported binary archives on their target platforms, and exercise preview plus a local `run -- cat` roundtrip from a clean installation. |

The v0.2.0 release brings these milestones together. The installation guide
leads to a local preview and `run -- cat` before an AI tool is needed. Archive
checks verify the binary version, tokenized child input, exact restoration,
and mapping isolation on Linux x86_64 and both macOS architectures. Full main
CI and the tagged release workflow determine release readiness; local Linux
checks alone are not a completed release claim.

GitHub Releases is the current distribution channel. Keep the browser
playground's checked-in engine aligned with the CLI and publish checksums
alongside binary archives. Registry publication is a separate distribution
milestone, not a prerequisite for trying the product.

## Product boundaries

Keep the default core local and usable without a service, account, API key, or
ML runtime. Maintain secondary surfaces according to the existing scope tiers.
Expand into hosted services, additional document formats, or enterprise
controls only when a repeated user need and representative tests justify it.

Preview is a review aid. It cannot prove that data is anonymous, and its tokens
are regenerated on the next invocation. The child command also retains normal
filesystem, environment, and network access. Keep those boundaries explicit
where people start using the product.

## How to decide what comes next

In opt-in user trials, measure whether a developer can install the CLI,
understand the preview, complete the first roundtrip, and choose to use it
again on a later debugging task. Record failure reasons and elapsed setup
time; establish a baseline before setting conversion or retention targets.

The next detector candidates already have concrete reports: lowercase surnames
([#17](https://github.com/tcheuD/anon-pii/issues/17)) and French postal addresses
([#18](https://github.com/tcheuD/anon-pii/issues/18)). Reproduce each with fictional
fixtures and ordinary-text negatives before choosing an implementation. Do not
broaden name or address detection solely to improve a headline entity count.

Use synthetic reproductions for detector reports. Do not collect raw payloads,
mapping files, or command output as product analytics. Quality measurements
must retain the configuration, corpus, and integer counts required by the
[quality policy](quality.md). Distribution follows the
[release checklist](release.md).
