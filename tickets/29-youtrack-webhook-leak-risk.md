# Ticket #29: YouTrack Webhook/Automation PII Leak Risk

**Priority:** High (P1)
**Complexity:** Low (documentation + config review)
**Status:** Open
**File:** YouTrack admin config (not code)

## Description

YouTrack supports server-side workflows and webhooks that fire on issue events. When the AI creates or updates an issue, these automations may replicate PII to systems outside the security perimeter — even though the human only approved a write to YouTrack.

### Leak Vectors

| Automation | Risk |
|-----------|------|
| Webhook to external URL | Issue content sent to third-party system |
| Email notification with full body | PII in email to distribution list |
| Slack/Teams integration | Issue content cross-posted to channel |
| Jira/ServiceNow sync | PII replicated to external tracker |
| Workflow copying to another project | PII moved to less-restricted project |

The human approved the write to YouTrack. They did **not** approve the N downstream systems that automations propagate to.

## Solution

This is not a code fix — it's an operational checklist before enabling MCP writes.

### Pre-Deployment Review

1. **Audit all YouTrack workflows** on projects in the allowlist (ticket #23)
   - Document every workflow that fires on issue create/update/comment
   - Identify which send data externally (webhooks, email, integrations)

2. **Disable or restrict automations** on AI-writable projects
   - Option A: Disable webhooks on projects the MCP can write to
   - Option B: Create a dedicated "AI-written" tag and exclude tagged issues from automations
   - Option C: Configure automations to strip PII before forwarding (complex)

3. **Document the consent boundary**
   - The approval step covers YouTrack only
   - If automations forward data, the user must be warned during approval

### Approval UI Integration

If the target project has active webhooks/workflows, the approval display should warn:

```
⚠  Project OPS has 3 active automations:
   - Slack notification to #ops-alerts
   - Email to ops-team@example-air.com
   - Webhook to monitoring.internal
   Content may be forwarded to these systems.
```

## Acceptance Criteria

- [ ] All YouTrack workflows on MCP-writable projects audited and documented
- [ ] Decision made on automation handling (disable, tag-exclude, or warn)
- [ ] Approval UI warns about active automations on target project (if chosen)
