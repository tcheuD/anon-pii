# PDF Redaction

[Back to README](../README.md)

`anon-pii pdf` anonymizes text-based PDF files by extracting words and
coordinates, running the normal PII detector, and drawing filled rectangles over
detected regions in a new PDF.

## Install

```bash
cargo install anon-pii --features pdf
```

From a source checkout:

```bash
cargo install --path . --features pdf
```

## Usage

```bash
# Basic redaction
anon-pii pdf report.pdf -o report-redacted.pdf

# Custom fill color and threshold
anon-pii pdf report.pdf -o safe.pdf --fill-color white --threshold 0.8

# Extra padding around detections
anon-pii pdf report.pdf -o safe.pdf --padding 4

# Hex color
anon-pii pdf report.pdf -o safe.pdf --fill-color '#000000'
```

## Options

| Option | Default | Description |
|--------|---------|-------------|
| `<PATH>` | required | Input PDF file |
| `--output`, `-o` | required | Output PDF path |
| `--threshold` | `0.5` | Minimum detection confidence (0.0-1.0) |
| `--fill-color` | `black` | Fill color: named or `#RRGGBB`/`#RGB` hex |
| `--padding` | `2` | Extra points around each detected region |

## Limitations

- Works best on PDFs with extractable text.
- Scanned PDFs need OCR before this command can redact their text.
- Redaction is region-based: visually inspect output before sharing.
- Links and annotations that overlap redacted regions are removed or neutralized
  where the current implementation can identify them.
