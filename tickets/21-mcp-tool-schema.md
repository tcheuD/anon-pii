# Ticket #21: Rigid MCP Tool Schema with Field Allowlist

**Priority:** Critical (P0)
**Complexity:** Medium
**Status:** Open
**File:** `youtrack-mcp/` (new)

## Description

The MCP server must expose typed, constrained tools — not a free-form YouTrack API passthrough. The AI should control only content fields (summary, description, comment text). All structural fields (visibility, project, assignee, custom fields) are locked by the MCP server.

Without this, a prompt injection could cause the AI to:
- Change issue visibility from restricted to public
- Move issues to different projects
- Modify custom fields carrying operational data
- Delete issues via unexpected API endpoints

## MCP Tools to Expose

```
youtrack_read_issue:
  issue_id:    string, pattern [A-Za-z]+-[0-9]+

youtrack_search:
  query:       string, max 500 chars

youtrack_create_issue:
  project:     enum (from allowed_projects config)
  summary:     string, max 200 chars
  description: string, max 10000 chars
  type:        enum [Bug, Task, Feature, Incident]

youtrack_update_issue:
  issue_id:    string, pattern [A-Za-z]+-[0-9]+
  description: string, optional, max 10000 chars
  state:       enum (project-specific allowed states)

youtrack_add_comment:
  issue_id:    string, pattern [A-Za-z]+-[0-9]+
  text:        string, max 5000 chars
```

## What the AI Cannot Do

- Set or change visibility
- Change assignee
- Modify custom fields
- Delete issues or comments
- Access admin/user management endpoints
- Move issues between projects

Each of these can be added later with explicit security review.

## Implementation Notes

- MCP server constructs the YouTrack API payload server-side, only inserting AI-provided content fields
- Input validation on all parameters (length, pattern, enum membership)
- The MCP server never passes AI-generated JSON directly to the YouTrack API

## Acceptance Criteria

- [ ] MCP tools accept only the fields listed above
- [ ] All inputs validated (length, pattern, enum)
- [ ] YouTrack API payload is constructed server-side, not from AI JSON
- [ ] Attempting to set unlisted fields returns a clear error
