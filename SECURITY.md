# Security Policy

`anon-pii` is a privacy aid for local data minimization. It is not a compliance guarantee, a formal anonymization proof, or a substitute for policy review.

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| latest  | :white_check_mark: |

Security fixes are applied to the main branch. After versioned releases are established, this table will be updated with supported release lines.

## Reporting a Vulnerability

**Please do not report security vulnerabilities through public GitHub issues.**

Instead, please report them via [GitHub Security Advisories](https://github.com/tcheuD/anon-pii/security/advisories/new).

Do not include:
- Exploit details in public issues
- Real PII, API keys, model prompts, mapping files, screenshots, or logs

### What to Include in Your Report

- Affected version or commit hash
- Feature area (detection, mapping, proxy, NER, etc.)
- Step-by-step reproduction instructions using synthetic data
- Expected vs. actual behavior
- Potential impact assessment

### Response Timeline

- **Acknowledgment**: Within 48 hours of submission
- **Assessment**: We will investigate and assess severity
- **Resolution**: We will work on a fix and coordinate disclosure timing
- **Credit**: You will be credited in the security advisory (unless you prefer anonymity)

## Sensitive Data Handling

The default token operator persists a local mapping so `anon-pii restore` can recover original values. That mapping contains the original sensitive data and must be protected like the source data.

Do not commit:

- `~/.anon-pii/mapping.json` or any copied mapping file
- Real debug logs, screenshots, PDFs, spreadsheets, support tickets, or prompts
- API keys, bearer tokens, cookies, JWTs, SSH keys, or cloud credentials
- OCR/image redaction outputs derived from real user data

Use synthetic fixtures for tests and examples.

## Security Scope

**In scope:**

- Missed or unsafe redaction behavior caused by implementation bugs
- Mapping persistence, restore, proxy, UI, image, PDF, and custom recognizer vulnerabilities
- Secret leakage through logs, errors, generated artifacts, or release packages

**Out of scope:**

- False negatives caused only by unsupported entity types or documented limitations
- Compromise of the local machine, shell history, clipboard, or third-party LLM provider
- Reports that require real PII instead of synthetic reproduction data

## Security Properties

`anon-pii` implements the following security measures:

- **Atomic file writes**: Mapping files are written atomically (temp file + rename) to prevent TOCTOU races
- **Restrictive permissions**: Mapping files are created with mode 0600, directories with 0700
- **Symlink defense**: The tool does not follow symlinks in mapping paths
- **Proxy host validation**: Only localhost addresses (127.0.0.1, localhost, [::1]) are allowed to prevent DNS rebinding
- **Header allowlist**: Only safe headers are forwarded through the proxy
- **Cryptographic RNG**: Token generation uses `getrandom` for secure random bytes
- **NER library path validation**: `ORT_DYLIB_PATH` is validated against system library allowlist
