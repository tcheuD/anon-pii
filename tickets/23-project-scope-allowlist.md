# Ticket #23: Project Scope Allowlist/Blocklist

**Priority:** Critical (P0)
**Complexity:** Low
**Status:** Open
**File:** `youtrack-mcp/config.json` (new)

## Description

Aviation companies have YouTrack projects containing highly sensitive data — incident reports, medical evacuations, crew HR records. The MCP server must refuse to read or write to designated sensitive projects.

## Configuration

```json
{
  "allowed_projects": ["DEV", "INFRA", "TOOLS", "OPS"],
  "blocked_projects": ["SAFETY", "MEDEVAC", "CREW-HR", "INCIDENT", "LEGAL"]
}
```

Enforcement logic:
- If `allowed_projects` is set (non-empty), only those projects are accessible. Everything else is blocked.
- If only `blocked_projects` is set, everything except listed projects is accessible.
- If both are set, `allowed_projects` takes precedence.

## Enforcement Points

1. **Read path** — `youtrack_read_issue` and `youtrack_search` filter results by project scope
2. **Write path** — `youtrack_create_issue`, `youtrack_update_issue`, `youtrack_add_comment` reject if target project is out of scope
3. **Search results** — issues from blocked projects are stripped from search results before AI sees them

## Acceptance Criteria

- [ ] Config file defines allowed/blocked projects
- [ ] All MCP tools enforce project scope before any API call
- [ ] Clear error message when project is out of scope
- [ ] Search results filtered to exclude blocked projects
