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

Review is an aid, not proof that data is anonymous. CLI preview tokens are
regenerated on the next invocation; the browser workspace keeps a prepared
mapping only in the current page session. A CLI child retains its normal
filesystem, environment, and network access. Browser users choose what to copy
to an external AI tool. Keep these boundaries explicit at the point of use.

## Next milestone: browser ticket workspace and CLI starter

Prioritize a repeatable ticket-to-AI handoff for developers and support
engineers working with finite English and French ticket text. The primary
entry point is a browser workspace: prepare a ticket, inspect and copy its
tokens, paste an AI response, and restore recognized references in the same
page session. It needs no CLI installation, account, or backend. A bookmark
returns to a fresh workspace for the next ticket. Keep a runnable CLI starter
for people who already work in the terminal.

The [support-ticket guide](support-ticket.md) covers both paths and their
session boundaries.

### Evidence and hypothesis

- **Established:** the repository has a fictional support-ticket demo, custom
  recognizers, optional heuristic name detection, and an in-memory child-command
  roundtrip. The v0.2.0 onboarding path reaches a local `run -- cat` proof.
- **Reported:** the two open issues as of this decision are lowercase surnames
  ([#17](https://github.com/tcheuD/anon-pii/issues/17)) and French postal addresses
  ([#18](https://github.com/tcheuD/anon-pii/issues/18)). Both were filed by the
  maintainer and describe playground inputs. They identify concrete coverage
  gaps; they do not establish how many independent users have this need.
- **Established, narrowly:** the [pinned comparison](comparison-redact.md)
  identifies local child-command orchestration and restoration as a distinct
  workflow at the compared revisions. Its project-owned corpus is not market
  validation or evidence of universal detector superiority.
- **Hypothesis:** a browser path will remove installation friction for support
  engineers, and a bookmark plus reusable CLI recipe will make the second use
  easier. Name and French-address coverage should make the ticket examples more
  useful. Activation, retention, and willingness to pay remain unmeasured.

### What the package must deliver

1. Reproduce the two reported gaps with fictional positives, ordinary-text
   negatives, exact spans, and restored output. Evaluate optional name detection
   separately from default recognizers; do not broaden recognition just to raise
   an entity count.
2. Provide a browser workspace that prepares one ticket, copies the reviewed
   tokenized text, restores a pasted reply, and clears the session. Edits and
   re-preparation must invalidate prior tokens and replies. Reloading must not
   resurrect a mapping. Keep heuristic name detection visible and never label
   the prepared text as guaranteed anonymous.
3. Provide a fictional example that completes the browser loop without an AI
   account. The CLI starter should show actual tokenized child input and a useful
   simulated response, then give users a reusable command/configuration for the
   next ticket. Neither path should persist mappings or transmit ticket text.
4. Verify the browser's source-edit, clipboard, restore, and clear behavior;
   verify CLI workflow cases from shipped binaries. Keep coverage measurements
   separate from interface checks. Passing the existing corpus alone does not
   establish coverage for names or addresses added by this milestone.

These are delivery criteria, not a claim that the package is already released.
Browser copy/restore uses one prepared session; editing the source, preparing
again, clearing, or reloading loses that session. CLI preview and execution
remain separate transactions with fresh tokens. Same-invocation terminal
approval is a later hypothesis with its own terminal and failure-path contract.

### Adoption loop without collecting payloads

Ship the bookmarkable workspace, local example, and reusable CLI recipe
together. Include a passive, optional feedback prompt in the guide: did the first workflow complete, was it
used on another ticket, and what blocked that use? Request only product version,
platform, configuration, first/repeat-use status, and the failure category.
Do not transmit usage automatically or treat a local demo run as an active user.

Use the existing issue/discussion paths for voluntarily supplied outcomes.
Detector reports need fictional reproductions; sensitive disclosures continue
through the [security reporting path](../SECURITY.md). Never request raw ticket
text, mappings, command output containing personal data, or private prompts as
analytics. Record the count and provenance of actual reports before claiming
activation or repeat use. There is no measured retention baseline yet.

A repeated blocker should produce a fictional regression case, a focused fix,
and an updated starter recipe, so the next user benefits from the same report.
Keep quality measurements tied to the configuration, corpus, and integer counts
required by the [quality policy](quality.md). Distribution follows the
[release checklist](release.md).
