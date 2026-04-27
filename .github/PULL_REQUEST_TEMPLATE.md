<!--
Thank you for contributing to anon-pii!
Please fill out this checklist so reviewers can verify your change quickly.
-->

## Summary

Briefly describe what this PR changes and why.

## Related issues

Closes #
Related to #

## Type of change

- [ ] Bug fix
- [ ] New feature (new entity, operator, format, or capability)
- [ ] Refactor (no behavior change)
- [ ] Documentation only
- [ ] CI / build / tooling
- [ ] Performance
- [ ] Security fix

## Verification checklist

Required for all PRs:

- [ ] `cargo fmt --all --check` passes
- [ ] `cargo clippy -- -D warnings` passes
- [ ] `cargo test` passes (default features)

Required if your change touches NER or proxy code:

- [ ] `cargo clippy --features ner-lite,proxy -- -D warnings` passes
- [ ] `cargo test --features ner-lite,proxy` passes

For new patterns or detection changes:

- [ ] Added regression tests with synthetic data only
- [ ] Included false-positive and false-negative edge cases where practical
- [ ] Added context-required and checksum validation tests where relevant
- [ ] No real PII, API keys, or credentials in fixtures or examples

For documentation changes:

- [ ] Public docs do not overclaim anonymization or compliance guarantees
- [ ] Examples use reserved domains (`example.com`, `test.invalid`) and documentation IP ranges (`192.0.2.0/24`)

## Notes for reviewers

Anything else reviewers should know: trade-offs you considered, limitations, follow-up work, etc.
