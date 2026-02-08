# Ticket #12: Align Restore Command Interface

**Priority:** Low
**Complexity:** Low
**Status:** DONE
**File:** `src/main.rs`

## Description

The `restore` subcommand has a minor interface difference:

| | Python | Rust |
|---|--------|------|
| Input | Positional argument | `--input` / `-i` flag |

Python: `anon restore INPUT_FILE -m mapping.json`
Rust: `anon restore -i INPUT_FILE -m mapping.json`

## Proposed Change

Support both positional and flag-based input for the restore command:

```rust
#[derive(Args)]
struct RestoreArgs {
    /// Anonymized input file (positional, optional)
    #[arg(value_name = "INPUT")]
    input_positional: Option<PathBuf>,

    /// Anonymized input file (flag, optional)
    #[arg(short, long)]
    input: Option<PathBuf>,

    /// Mapping file (required)
    #[arg(short, long)]
    mapping: PathBuf,

    /// Output file
    #[arg(short, long)]
    output: Option<PathBuf>,
}
```

Resolution logic: Use `input_positional` if provided, else `input` flag, else stdin.

## Alternative

Keep the current `--input` flag as-is. The difference is minor and Rust's approach is arguably more consistent (both commands use `--input`).

## Acceptance Criteria

- [x] `anon restore INPUT -m mapping.json` works (positional)
- [x] `anon restore -i INPUT -m mapping.json` still works (flag)
- [x] Stdin fallback still works when neither is provided
