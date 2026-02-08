# Ticket #08: Align `--include-mapping` Placement

**Priority:** Low
**Complexity:** Low
**Status:** DONE
**File:** `src/main.rs`

## Description

The `--include-mapping` flag embeds the mapping JSON in the output. Python appends it at the **end** of the output. Rust prepends it at the **top**.

## Current Behavior

**Python:**
```
anonymized content here...
/* MAPPING: {"session_id":"abc","mappings":{...}} */
```

**Rust:**
```
/* MAPPING: {"session_id":"abc","mappings":{...}} */
anonymized content here...
```

## Proposed Change

Move the mapping comment to the end of the output to match Python behavior. Appending is arguably better because:
1. The useful anonymized content comes first
2. JSON output remains valid if the comment is at the end (less likely to break parsers)
3. Matches Python behavior

## Implementation

In `main()`, move the mapping insertion from before the content output to after it. Change from prepending to appending:

```rust
// Before (current):
output = format!("/* MAPPING: {} */\n{}", mapping_json, output);

// After (proposed):
output = format!("{}\n/* MAPPING: {} */", output.trim_end(), mapping_json);
```

## Acceptance Criteria

- [x] Mapping comment appended at end of output instead of top
- [x] Newline handling is correct (no double newlines)
- [x] Warning message to stderr still prints
- [x] Works correctly for both JSON and text formats
