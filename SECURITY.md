# Security Policy

`anon` is a privacy aid for local data minimization. It is not a compliance guarantee, a formal anonymization proof, or a substitute for policy review.

## Reporting Vulnerabilities

Please do not open public issues with exploit details, real PII, API keys, model prompts, mapping files, screenshots, or logs.

Preferred reporting path:

1. Use GitHub private vulnerability reporting for this repository if it is enabled.
2. If private reporting is not available, open a public issue with no sensitive details and ask for a private contact path.

Include the affected version or commit, the feature area, reproduction steps using synthetic data, and the expected impact.

## Sensitive Data Handling

The default token operator persists a local mapping so `anon restore` can recover original values. That mapping contains the original sensitive data and must be protected like the source data.

Do not commit:

- `~/.anon/mapping.json` or any copied mapping file.
- Real debug logs, screenshots, PDFs, spreadsheets, support tickets, or prompts.
- API keys, bearer tokens, cookies, JWTs, SSH keys, or cloud credentials.
- OCR/image redaction outputs derived from real user data.

Use synthetic fixtures for tests and examples.

## Supported Versions

Security fixes are handled on the main branch until versioned releases are established. After public releases exist, this section should be updated with supported release lines.

## Security Scope

In scope:

- Missed or unsafe redaction behavior caused by implementation bugs.
- Mapping persistence, restore, proxy, UI, image, PDF, and custom recognizer vulnerabilities.
- Secret leakage through logs, errors, generated artifacts, or release packages.

Out of scope:

- False negatives caused only by unsupported entity types or documented limitations.
- Compromise of the local machine, shell history, clipboard, or third-party LLM provider.
- Reports that require real PII instead of synthetic reproduction data.
