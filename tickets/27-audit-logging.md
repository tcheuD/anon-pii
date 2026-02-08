# Ticket #27: Audit Logging for MCP Operations

**Priority:** High (P1)
**Complexity:** Medium
**Status:** Open
**File:** `youtrack-mcp/` (new)

## Description

Every MCP operation — approved or rejected — must be logged to an append-only file. This enables post-hoc review, incident investigation, and GDPR compliance.

## Log Format

```json
{
  "timestamp": "2026-02-01T14:23:07Z",
  "operation": "create_issue",
  "project": "OPS",
  "issue_id": "OPS-456",
  "action": "approved",
  "content_hash": "sha256:abc123...",
  "content_length": 842,
  "pii_tokens_restored": ["[CREW_CODE_a1b2]", "[EMAIL_ADDRESS_c3d4]"],
  "pii_count": 2,
  "raw_pii_blocked": false,
  "source_issues_read": ["OPS-450", "OPS-451"],
  "cross_issue_warning": false
}
```

## Key Rules

- **Never log raw PII values** — log token names and hashes only
- **Log rejections too** — blocked writes, failed PII gates, user rejections
- **Append-only** — no log rotation that deletes entries within retention period
- **Separate from application logs** — dedicated audit file

## GDPR Consideration

The audit log references token IDs, not raw PII. When a mapping expires (TTL) or is purged (erasure request), the audit log becomes unlinkable — it says "[CREW_CODE_a1b2] was restored" but without the mapping, nobody knows who that was.

## Acceptance Criteria

- [ ] All MCP operations logged (reads, writes, approvals, rejections, blocks)
- [ ] Log contains no raw PII — only token names and content hashes
- [ ] Append-only log file with restricted permissions (0600)
- [ ] Session summary available on demand
