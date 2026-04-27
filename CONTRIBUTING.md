# Contributing to anon-pii

Thank you for your interest in contributing to anon-pii! This document provides guidelines and instructions for contributing.

## Getting Started

### Prerequisites

- Rust (stable toolchain) - install via [rustup](https://rustup.rs/)
- Git

### Setup

```bash
# Clone the repository
git clone https://github.com/tcheuD/anon-pii.git
cd anon-pii

# Build the project
cargo build

# Run tests
cargo test
```

## Development Workflow

### Running Tests

The project uses a feature-flag system. Always run the default test suite after any change:

```bash
# Default features (regex-only, no NER, no proxy)
cargo test

# Full test suite (recommended before submitting PR)
cargo test --features ner-lite,proxy
```

### Test Matrix

| Feature Set | Command | When to Run |
|-------------|---------|-------------|
| Default | `cargo test` | Always |
| ner-lite,proxy | `cargo test --features ner-lite,proxy` | Changes to NER or proxy code |
| xlsx | `cargo test --features xlsx` | Changes to XLSX handling |
| image | `cargo test --features image` | Changes to image/OCR handling (requires Tesseract) |

### Linting and Formatting

All code must pass these checks before merging:

```bash
# Check formatting
cargo fmt --all --check

# Run clippy (default features)
cargo clippy -- -D warnings

# Run clippy (with features)
cargo clippy --features ner-lite,proxy -- -D warnings
```

To auto-fix formatting:

```bash
cargo fmt --all
```

### Optional Dependencies

Some features require additional system dependencies:

- `image`: Tesseract and Leptonica
- `pdf`: No external runtime dependency beyond the Rust feature
- `ner`: ONNX Runtime plus the downloaded NER model

## Code Style

- Follow Rust conventions and idioms
- Use `rustfmt` defaults
- Write doc comments for public functions and modules
- Keep functions focused and reasonably sized

### Naming Conventions

- Entity types follow Presidio-style naming: `EMAIL_ADDRESS`, `FR_PHONE_NUMBER`, `AIRCRAFT_REGISTRATION`
- Tokens follow the format `[ENTITY_TYPE_XXXXXXXX]` with an 8-character hex suffix
- Test functions: `test_<what_is_tested>`

## Test Data Rules

Use synthetic data only. Do not add real tickets, prompts, logs, PDFs, spreadsheets, screenshots, mappings, customer identifiers, or credentials.

Good fixture values:

- Reserved domains such as `example.com`, `example.org`, and `test.invalid`
- Documentation IP ranges such as `192.0.2.0/24`, `198.51.100.0/24`, and `203.0.113.0/24`
- Obviously fake names, IDs, and credentials

Avoid plausible live secrets even in examples. If a value looks like a real API key, JWT, private key, cookie, or cloud token, do not commit it.

## Security-Sensitive Changes

For changes touching detection, mappings, restore, proxying, OCR/PDF redaction, custom recognizers, or dependency downloads:

- Add regression tests with synthetic data
- Include false-positive and false-negative edge cases where practical
- Document any new limitations or trust boundaries
- Keep mapping files and generated redaction outputs out of git

## Pull Request Process

### Before Submitting

1. Ensure your code compiles without warnings
2. Run the full test suite: `cargo test && cargo test --features ner-lite,proxy`
3. Run linting: `cargo fmt --all --check && cargo clippy -- -D warnings`
4. Write tests for new functionality
5. Update documentation if needed

### PR Expectations

- Keep PRs focused on a single change
- Write a clear description of what the PR does and why
- Reference related issues (e.g., "Closes #123")
- Respond to review feedback promptly
- Fixtures and examples contain no real PII or credentials
- Public docs do not overclaim anonymization or compliance guarantees

### Commit Messages

Use [Conventional Commits](https://www.conventionalcommits.org/) format:

```
<type>(<scope>): <description>

[optional body]

[optional footer]
```

Types: `feat`, `fix`, `docs`, `style`, `refactor`, `test`, `chore`, `perf`, `ci`, `build`

Examples:
- `feat(patterns): add Italian fiscal code detection`
- `fix(proxy): handle SSE chunks split mid-token`
- `docs: update NER setup instructions`

## Adding New Patterns

When adding PII detection patterns:

1. Create or update the pattern file in `src/patterns/`
2. Add validators to `src/patterns/validators.rs` if checksum validation is needed
3. Register the pattern in `src/patterns/mod.rs`
4. Wire validators in `detection.rs` (search for existing validator calls as examples)
5. Add comprehensive tests including:
   - Positive matches with context
   - Rejection without context (if context-required)
   - Checksum validation (valid and invalid)
   - Edge cases

## Reporting Bugs

Please use the [bug report template](.github/ISSUE_TEMPLATE/bug_report.md) when filing issues.

## Security Issues

**Do not report security vulnerabilities through public issues.** See [SECURITY.md](SECURITY.md) for responsible disclosure instructions.

## Code of Conduct

This project adopts the [Contributor Covenant](https://www.contributor-covenant.org/). By participating, you agree to abide by its terms. See [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).

## Questions?

Feel free to open a [discussion](https://github.com/tcheuD/anon-pii/discussions) or issue if you have questions about contributing.
