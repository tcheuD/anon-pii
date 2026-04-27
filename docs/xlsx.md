# XLSX Feature

[Back to README](../README.md)

The `xlsx` feature currently adds XLSX format detection scaffolding and exposes
`xlsx` as a format value in feature-enabled builds. Full workbook anonymization
is not implemented yet; the CLI exits with guidance to export the workbook to
CSV first.

## Install

```bash
cargo install anon-pii --features xlsx
```

From a source checkout:

```bash
cargo install --path . --features xlsx
```

## Current Behavior

```bash
anon-pii --format xlsx -i workbook.xlsx
# Error: XLSX parsing not yet implemented
# Hint: use --format csv to export to CSV first
```

For now, export the sheet to CSV and run:

```bash
anon-pii --format csv -i exported.csv -o exported-safe.csv
```

## Verification

```bash
cargo test --features xlsx
```

The feature has tests for XLSX magic-byte and extension detection so future
workbook parsing can build on a checked detection layer.
