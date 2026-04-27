---
name: Bug report
about: Report a defect in detection, mapping, restore, proxy, or CLI behavior
title: "[Bug] "
labels: bug
assignees: ''
---

<!--
Before filing:
- Search existing issues for duplicates.
- For security-sensitive defects (missed redaction, secret leakage, mapping disclosure),
  do NOT use this template. See SECURITY.md for the private disclosure path.
- Use synthetic data only. Do not paste real PII, API keys, prompts, or logs.
-->

## Summary

A clear, concise description of the bug.

## Environment

- `anon-pii` version or commit hash:
- Feature flags built with (default / `ner-lite` / `ner` / `proxy` / `xlsx`):
- OS and version:
- Rust toolchain (`rustc --version`):

## Reproduction

Minimal steps with synthetic input. Include the exact command line.

```bash
# Example
echo 'contact: alice@example.com' | anon-pii anonymize -
```

## Expected behavior

What you expected to happen.

## Actual behavior

What actually happened. Include the relevant CLI output or error message.

## Additional context

Logs, screenshots (with synthetic data only), or links to related issues.
