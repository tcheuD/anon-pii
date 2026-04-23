# Contributing

Thanks for helping improve `anon`.

## Development Setup

```bash
cargo test
cargo test --features ner-lite,proxy
cargo fmt --all --check
cargo clippy -- -D warnings
```

Optional features require additional system dependencies:

- `image`: Tesseract and Leptonica.
- `pdf`: no external runtime dependency beyond the Rust feature.
- `ner`: ONNX Runtime plus the downloaded NER model.

## Test Data Rules

Use synthetic data only. Do not add real tickets, prompts, logs, PDFs, spreadsheets, screenshots, mappings, customer identifiers, or credentials.

Good fixture values:

- Reserved domains such as `example.com`, `example.org`, and `test.invalid`.
- Documentation IP ranges such as `192.0.2.0/24`, `198.51.100.0/24`, and `203.0.113.0/24`.
- Obviously fake names, IDs, and credentials.

Avoid plausible live secrets even in examples. If a value looks like a real API key, JWT, private key, cookie, or cloud token, do not commit it.

## Security-Sensitive Changes

For changes touching detection, mappings, restore, proxying, OCR/PDF redaction, custom recognizers, or dependency downloads:

- Add regression tests with synthetic data.
- Include false-positive and false-negative edge cases where practical.
- Document any new limitations or trust boundaries.
- Keep mapping files and generated redaction outputs out of git.

## Pull Request Checklist

- Tests pass for the feature set you changed.
- `cargo fmt` has been run.
- Public docs do not overclaim anonymization or compliance guarantees.
- Fixtures and examples contain no real PII or credentials.
