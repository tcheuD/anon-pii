# PDF Redaction

[Back to README](../README.md)

`anon-pii pdf` provides destructive text redaction for supported text-based PDF
files by extracting words and coordinates, running the normal PII detector,
rewriting matching PDF text drawing operands, and drawing filled rectangles over
detected regions in a new PDF. If a detected span cannot be mapped to removable
PDF text, the command fails closed.

Use `--visual-mask-only` only when you explicitly want overlay-only visual
masking. In that mode, underlying PDF text/content may remain extractable by
copy/paste, search, PDF parsers, or forensic tooling.

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

# Explicit overlay-only visual masking
anon-pii pdf report.pdf -o report-masked.pdf --visual-mask-only
```

## Options

| Option | Default | Description |
|--------|---------|-------------|
| `<PATH>` | required | Input PDF file |
| `--output`, `-o` | required | Output PDF path |
| `--threshold` | `0.5` | Minimum detection confidence (0.0-1.0) |
| `--fill-color` | `black` | Fill color: named or `#RRGGBB`/`#RGB` hex |
| `--padding` | `2` | Extra points around each detected region |
| `--visual-mask-only` | `false` | Draw overlays without rewriting PDF text streams |

## Hidden Data Scrubbing

Every PDF output is saved as a newly written file after stripping hidden data
structures that can carry PII outside visible page text:

- Document info metadata and catalog XMP metadata.
- Embedded files, associated file arrays, and file attachment annotations.
- Form fields and AcroForm data.
- Outlines/bookmarks and named destinations.
- Catalog/page interactive actions, additional actions, JavaScript name trees,
  and related named action containers.
- All page annotations, including links, comments, widgets, and attachments.

Disconnected objects are pruned before saving so removed metadata, annotations,
attachments, and original replaced content streams are not serialized as orphan
objects in the output PDF.

## Limitations

- Works best on PDFs with extractable text.
- Scanned PDFs need OCR before this command can detect and redact visible text.
- Destructive redaction is limited to supported PDF text drawing operations.
- Unsupported mappings fail closed unless `--visual-mask-only` is selected.
- Visual masking mode is region-based: visually inspect output before sharing.
- In visual masking mode, underlying PDF text/content may remain extractable.
- OCR layers, raster images, embedded fonts, and non-text page resources remain
  unsupported unless their visible text is extractable and mapped to redaction
  regions.
