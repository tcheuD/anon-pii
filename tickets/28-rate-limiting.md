# Ticket #28: Rate Limiting on MCP Write Operations

**Priority:** High (P1)
**Complexity:** Low
**Status:** Open
**File:** `youtrack-mcp/` (new)

## Description

Without rate limiting, a prompt injection or bug could cause the AI to spam writes, overwhelming the human approver (approval fatigue) or creating noise in YouTrack.

## Limits

```
- Max 5 write operations per 10-minute window
- Max 20 write operations per hour
- Cooldown after 3 consecutive writes without a read
  (prevents batch spam patterns)
- Read operations: max 10 per minute (prevents enumeration)
```

## Implementation

Simple in-memory sliding window counter. No need for Redis — the MCP server is a single local process.

```python
class RateLimiter:
    def __init__(self):
        self.writes = deque()  # timestamps
        self.consecutive_writes = 0

    def check_write(self) -> bool:
        now = time.time()
        # Prune old entries
        while self.writes and self.writes[0] < now - 3600:
            self.writes.popleft()
        # Check limits
        recent_10m = sum(1 for t in self.writes if t > now - 600)
        if recent_10m >= 5:
            return False
        if len(self.writes) >= 20:
            return False
        if self.consecutive_writes >= 3:
            return False
        return True
```

## Acceptance Criteria

- [ ] Write rate limits enforced (5/10min, 20/hour)
- [ ] Consecutive write cooldown enforced (max 3 without a read)
- [ ] Clear error message when rate limited
- [ ] Limits configurable in config file
