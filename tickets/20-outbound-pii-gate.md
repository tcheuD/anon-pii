# Ticket #20: Outbound PII Gate for Write Path

**Priority:** Critical (P0)
**Complexity:** Medium
**Status:** Open
**File:** `youtrack-mcp/` (new)

## Description

The read path runs `anon` to strip PII before the AI sees content. The write path has no equivalent — AI-generated content goes directly to YouTrack after human approval. This is the single highest-risk gap.

The AI can leak PII it learned from:
- User messages ("update the issue about Captain Dupont")
- Inference from anonymized data ("the captain who flew Bordeaux-Paris last Tuesday")
- Prompt injection in issue content that tricks the AI into including PII
- Cross-issue context (AI read issue A with crew data, writes to issue B)

## Solution

Run `anon`'s detection engine on all AI-generated content before it reaches YouTrack. **Block** (don't tokenize) if raw PII patterns are found — force the AI to regenerate.

```
AI output → anon detect (not anonymize) → BLOCK if PII found → else continue
```

Key distinction: the outbound filter **rejects**, it does not replace. Tokenizing on the write path would put `[EMAIL_ADDRESS_xxx]` into YouTrack, which is useless. Instead, the write is refused and the AI must retry without the PII.

## Implementation

```python
def write_guard(content: str) -> tuple[bool, list[str]]:
    """Returns (is_clean, list_of_detected_pii_types)"""
    detections = anon_detect(content)  # reuse anon's regex set
    if detections:
        return False, [d.entity_type for d in detections]
    return True, []
```

## Edge Cases

- AI writes restored PII intentionally (after mapping restore) — the PII gate runs BEFORE restore, on raw AI output. Restored content is shown to the human in the preview step, not scanned again.
- False positives blocking legitimate writes — provide an override mechanism (human types "force-approve") with audit log entry.

## Acceptance Criteria

- [ ] All AI-generated write content passes through PII detection before YouTrack API call
- [ ] Writes containing raw PII patterns are blocked with clear error message
- [ ] Blocked writes are logged with detected entity types
- [ ] Human override exists for false positive blocks (with audit trail)
