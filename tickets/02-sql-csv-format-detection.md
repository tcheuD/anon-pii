# Ticket #02: Add SQL and CSV Format Detection

**Priority:** Medium
**Complexity:** Low
**Status:** DONE
**File:** `src/main.rs`

## Description

The Python implementation detects SQL and CSV input formats via auto-detection. While both are currently processed as plain text (no specialized handlers), format detection is reported in verbose mode and prepares for future format-specific handling.

## Current State (Rust)

The `Format` enum only has: `Auto`, `Json`, `Text`.

## Required Changes

### 1. Extend the Format enum

```rust
#[derive(Debug, Clone, Copy, ValueEnum)]
enum Format {
    Auto,
    Json,
    Text,
    Sql,
    Csv,
}
```

### 2. Add SQL detection

Check if the first word (uppercased) of trimmed content matches any of:
`SELECT`, `INSERT`, `UPDATE`, `DELETE`, `CREATE`, `ALTER`, `DROP`

### 3. Add CSV detection

If the content has multiple lines and the first line contains commas:
- Check the first 5 non-empty lines
- If they all have a consistent comma count (within +/-1), classify as CSV

### 4. Update format detection logic

In the `detect_format()` function (or equivalent), add SQL and CSV checks after JSON detection but before defaulting to Text.

### 5. Processing behavior

SQL and CSV should both fall through to text processing (same as Python). The format value is only used for:
- Verbose output ("Detected format: sql")
- Future extensibility

## Implementation Details

Python detection logic for reference:

```python
# SQL detection
first_word = content.strip().split()[0].upper()
if first_word in {"SELECT", "INSERT", "UPDATE", "DELETE", "CREATE", "ALTER", "DROP"}:
    return Format.SQL

# CSV detection
lines = content.strip().split("\n")
if len(lines) > 1 and "," in lines[0]:
    non_empty = [l for l in lines[:5] if l.strip()]
    counts = [l.count(",") for l in non_empty]
    if counts and all(abs(c - counts[0]) <= 1 for c in counts):
        return Format.CSV
```

## Tests to Add

```rust
#[test]
fn test_format_detection_sql() {
    assert!(matches!(detect_format("SELECT * FROM users WHERE id = 1"), Format::Sql));
    assert!(matches!(detect_format("INSERT INTO logs VALUES (1, 'test')"), Format::Sql));
    assert!(matches!(detect_format("  DELETE FROM sessions"), Format::Sql));
}

#[test]
fn test_format_detection_csv() {
    let csv = "name,email,phone\nJohn,john@test.com,0612345678\nJane,jane@test.com,0698765432";
    assert!(matches!(detect_format(csv), Format::Csv));
}

#[test]
fn test_format_detection_not_csv() {
    // Single line with commas is not CSV
    assert!(!matches!(detect_format("hello, world, foo"), Format::Csv));
}
```

## Acceptance Criteria

- [x] `Format` enum extended with `Sql` and `Csv` variants
- [x] `--format sql` and `--format csv` accepted on CLI
- [x] Auto-detection identifies SQL statements
- [x] Auto-detection identifies CSV data
- [x] Both formats processed as plain text (same anonymization as `--format text`)
- [x] Verbose mode reports correct format name
- [x] All existing tests pass
