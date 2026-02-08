# Ticket #25: Token Storage Hardening (Keychain)

**Priority:** Critical (P0)
**Complexity:** Low
**Status:** Open
**File:** `youtrack-mcp/` (new)

## Description

The current `yt` script reads `YOUTRACK_TOKEN` from an environment variable. Env vars are visible via `/proc/*/environ`, crash dumps, child process inheritance, CI logs, and shell history.

For the MCP server (a long-running process handling sensitive API calls), the token must be stored in the OS secret store.

## Solution

### macOS: Keychain

```bash
# Store once
security add-generic-password -a "youtrack-mcp" \
  -s "youtrack-api-token" -w "$YOUTRACK_TOKEN"

# MCP server retrieves at startup
token = subprocess.check_output([
    "security", "find-generic-password",
    "-a", "youtrack-mcp", "-s", "youtrack-api-token", "-w"
]).decode().strip()
```

### Linux: libsecret / pass

```bash
secret-tool store --label="YouTrack MCP" service youtrack-mcp
```

### Fallback

If no secret store is available, the MCP server reads from a file with `0600` permissions, warns on startup, and refuses to start if the file is world-readable.

## Additional Measures

- Token never logged, never in config files, never in shell history
- MCP server clears the token from memory after building the HTTP client (if language allows)
- Short-lived tokens if YouTrack supports them, with rotation schedule

## Acceptance Criteria

- [ ] MCP server reads token from Keychain (macOS) or libsecret (Linux)
- [ ] Refuses to start if token is passed as env var (with override flag for dev)
- [ ] Token not present in any log output
- [ ] Fallback file mode enforces 0600 permissions
