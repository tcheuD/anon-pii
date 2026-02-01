# YouTrack Integration (`scripts/yt`)

[Back to README](../README.md)

Shell script that fetches YouTrack issues, anonymizes them through `anon --ner`, and lets you review before sending to stdout. Human stays in the loop — nothing reaches the LLM without your approval.

```bash
yt get CREW-1234          # Fetch issue by ID
yt search "state: Open"   # Search issues (max 25)
yt comments CREW-1234     # Get issue comments
```

Requires: `anon` (with NER), `curl`, `jq`.

## Setup — macOS (Keychain)

```bash
# 1. Symlink the script
ln -sf /path/to/anon-pii/scripts/yt ~/.local/bin/yt

# 2. Store the YouTrack token in Keychain (prompted interactively, never on disk)
security add-generic-password -a "$USER" -s youtrack-token -w

# 3. Add to ~/.zshrc
export YOUTRACK_URL="https://amelia.youtrack.cloud"

yt() {
  YOUTRACK_TOKEN=$(security find-generic-password -a "$USER" -s youtrack-token -w) \
    ~/.local/bin/yt "$@"
}
```

The token is fetched from Keychain on each call. It only exists in the environment of the `yt` process — not exported to your shell.

## Setup — Linux (secret-tool / GNOME Keyring)

```bash
# 1. Symlink the script
ln -sf /path/to/anon-pii/scripts/yt ~/.local/bin/yt

# 2. Store the token (requires libsecret / GNOME Keyring or KWallet)
secret-tool store --label="YouTrack Token" service youtrack account token
# Pastes interactively

# 3. Add to ~/.bashrc or ~/.zshrc
export YOUTRACK_URL="https://amelia.youtrack.cloud"

yt() {
  YOUTRACK_TOKEN=$(secret-tool lookup service youtrack account token) \
    ~/.local/bin/yt "$@"
}
```

On headless Linux without a keyring, use a permissions-restricted file as a fallback:

```bash
# Store token in a file readable only by you
echo "perm:your-token" > ~/.config/youtrack-token
chmod 600 ~/.config/youtrack-token

# In ~/.bashrc
yt() {
  YOUTRACK_TOKEN=$(cat ~/.config/youtrack-token) \
    ~/.local/bin/yt "$@"
}
```

## Setup — Windows (Credential Manager via PowerShell)

```powershell
# 1. Store the token in Windows Credential Manager
cmdkey /generic:youtrack-token /user:youtrack /pass:perm:your-token-here
```

Use from Git Bash or WSL:

```bash
# Git Bash — read from Credential Manager via cmdkey
export YOUTRACK_URL="https://amelia.youtrack.cloud"

yt() {
  YOUTRACK_TOKEN=$(cmdkey /list:youtrack-token 2>/dev/null | grep -oP 'Password: *\K.*' || \
    powershell.exe -Command "(Get-StoredCredential -Target youtrack-token).GetNetworkCredential().Password" 2>/dev/null) \
    /path/to/anon-pii/scripts/yt "$@"
}
```

```bash
# WSL — simpler, use secret-tool (Linux keyring) or a restricted file
# Same as the Linux headless setup above
echo "perm:your-token" > ~/.config/youtrack-token
chmod 600 ~/.config/youtrack-token

yt() {
  YOUTRACK_TOKEN=$(cat ~/.config/youtrack-token) \
    ~/.local/bin/yt "$@"
}
```

## Usage

```bash
# Fetch an issue — review anonymized output, confirm before it goes to stdout
yt get CREW-1234

# Pipe directly into Claude
yt get CREW-1234 | claude -p "summarize this issue"

# Search and review
yt search "project: OPS state: Open"
```

Each call shows the anonymized JSON on your terminal for review. Type `y` to send to stdout, anything else to abort.
