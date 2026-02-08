# Ticket #22: Two-Phase Preview/Confirm Approval UX

**Priority:** Critical (P0)
**Complexity:** Medium
**Status:** Open
**File:** `youtrack-mcp/` (new)

## Description

The default Claude Code tool approval ("Allow youtrack_create_issue?") is not sufficient — it shows parameters but doesn't highlight PII or show the restored version. A secure approval flow requires showing the human exactly what PII will be written.

## Design: Two-Phase Flow

### Phase 1: Preview (no write)

AI calls `youtrack_preview_create(project, summary, description)`. MCP server:
1. Runs outbound PII gate (ticket #20) — blocks if raw PII found
2. Restores bracketed tokens from mapping → produces the "real" version
3. Returns a structured preview with both versions and a `preview_id`

### Phase 2: Confirm (human approves)

AI shows the preview and calls `youtrack_confirm(preview_id)`. MCP server posts to YouTrack only after this second call.

## Approval Display

```
╔═══════════════════════════════════════════════════════╗
║  YOUTRACK WRITE PREVIEW                               ║
║  Action: CREATE in project OPS                        ║
╠═══════════════════════════════════════════════════════╣
║                                                       ║
║  What AI wrote (anonymized):                          ║
║  > [CREW_CODE_a1b2] reported radio failure on         ║
║  > [AIRCRAFT_REGISTRATION_c3d4] during approach       ║
║                                                       ║
║  What YouTrack will receive (PII restored):           ║
║  > JDU reported radio failure on F-HOPY during        ║
║  > approach                                           ║
║                                                       ║
║  PII to be written:                                   ║
║    CREW_CODE        → JDU                             ║
║    AIRCRAFT_REG     → F-HOPY                          ║
║                                                       ║
║  ⚠  2 PII values will be sent to YouTrack            ║
╠═══════════════════════════════════════════════════════╣
║  Type "approve OPS" to confirm                        ║
╚═══════════════════════════════════════════════════════╝
```

## Anti-Rubber-Stamping

- **Typed confirmation** — user types `approve <project>`, not just Y/Enter. Breaks muscle memory.
- **PII count always shown** — zero-PII writes are fast, PII-containing writes are deliberate.
- **Forced 3s delay** on writes with >5 PII tokens before approve becomes available.
- **Edit capability** — user can modify the restored content before posting.
- **Anomaly warning** — if AI writes tokens from a different issue than the target, display cross-issue warning (see ticket #26).

## Session Summary

On session end or on demand, show:
```
Session writes:
  1. Created OPS-456   (2 PII values)  approved
  2. Comment OPS-123   (0 PII values)  approved
  3. Update OPS-789    (3 PII values)  rejected
```

## Acceptance Criteria

- [ ] Preview returns both anonymized and restored versions
- [ ] PII tokens listed explicitly with their restored values
- [ ] Typed confirmation required (not just Y/N)
- [ ] Edit capability before final submit
- [ ] Preview IDs expire after 5 minutes (no stale approvals)
