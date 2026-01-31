# Proxy Mode: AI Tool PII Firewall

## Idea

Run `anon` as a man-in-the-middle proxy between the user and an AI tool (Claude Code, OpenCode, Cursor, Copilot, etc.). The proxy intercepts prompts and responses, anonymizing PII on the way out and restoring it on the way back.

```
User prompt → [anon] → sanitized prompt → AI API → sanitized response → [anon restore] → restored response
```

The user sees normal output with real values. The AI never sees actual PII.

## Use Cases

- Companies using AI coding assistants on proprietary codebases (internal hostnames, employee emails, API keys, DB credentials in logs)
- Compliance with GDPR/data residency — PII never leaves the local machine
- Aviation-specific: crew names, flight numbers, aircraft registrations stay internal
- Healthcare/fintech: patient IDs, account numbers stripped before reaching external APIs

---

## 1. Feasibility by Integration Point

### A. HTTP Reverse Proxy (base URL override) — Best option

**Claude Code**: Fully supported. Set `ANTHROPIC_BASE_URL=http://localhost:9100` and Claude Code routes all API traffic to the proxy. Also respects `HTTPS_PROXY`/`HTTP_PROXY` env vars natively, and supports custom CA certs via `NODE_EXTRA_CA_CERTS`. Documented in the [enterprise network config docs](https://code.claude.com/docs/en/network-config).

**Cursor**: Supports "Override OpenAI Base URL" in Settings → Models. Limitation: only works for Ask/Plan modes, **not Agent mode** (Agent routes through Cursor's backend regardless). See [Cursor network docs](https://cursor.com/docs/enterprise/network-configuration).

**Copilot**: GitHub Copilot does **not** expose a base URL override. It hardcodes its endpoint. Would need `HTTPS_PROXY` env var (VS Code respects `http.proxy` setting), meaning TLS interception with a custom CA — more complex.

**OpenCode / other CLIs**: Most OpenAI-compatible CLIs support `OPENAI_BASE_URL` or equivalent. Easy.

**Verdict**: HTTP reverse proxy via base URL override is the most viable path. Claude Code is the easiest target — one env var, no TLS, full API compatibility.

### B. CLI Pipe Wrapper — Limited

Wrapping stdin/stdout doesn't work for tools that make their own HTTP calls internally (all of them). Claude Code doesn't read prompts from stdin in a pipeable way — it has its own TUI. A pipe wrapper only works for one-shot `echo "text" | anon | curl-to-api`.

**Verdict**: Not viable for interactive use.

### C. MCP Server — Wrong abstraction

MCP servers provide tools, resources, and prompts to the LLM — they don't intercept the request/response pipeline. An MCP server cannot:
- Modify the user's prompt before it's sent to the API
- Intercept or modify the API response

Claude Code [hooks](https://docs.claude.com/en/docs/claude-code/hooks) (not MCP) can modify tool inputs via `PreToolUse` and intercept user prompts via `UserPromptSubmit`. But hooks modify what Claude *does*, not the API request body itself. A `UserPromptSubmit` hook could anonymize the prompt text, but there's no hook to restore the response.

**Verdict**: MCP is the wrong layer. Hooks can anonymize input but not restore output.

### D. VS Code Extension Middleware — Overkill

Could intercept `fetch`/`http` calls via monkey-patching or a custom `http.Agent`. Fragile and extension-specific. Not worth it when base URL override exists.

**Verdict**: Skip.

---

## 2. Hard Technical Problems

### Streaming (SSE) Token Splitting

The hardest problem. Anthropic's streaming API sends `content_block_delta` events with partial text. A token like `[EMAIL_ADDRESS_1]` could arrive split across chunks:

```
data: {"type":"content_block_delta","delta":{"text":"The email is [EMAIL_ADD"}}
data: {"type":"content_block_delta","delta":{"text":"RESS_1] and the phone"}}
```

**Solution**: Buffer-and-flush with bracket detection.

```
State machine:
- PASSTHROUGH: forward bytes immediately
- BUFFERING: saw '[', accumulate until ']' or buffer exceeds max token length

On ']': check if buffer matches a known token → restore → flush
On buffer overflow (no ']' within ~30 chars): not a token → flush buffer as-is
On stream end: flush remaining buffer
```

Max token length is bounded (longest ~`[AIRCRAFT_REGISTRATION_12]` = ~27 chars). Buffer is tiny, latency impact is negligible (a few SSE events delayed by microseconds).

Important: buffer at the semantic text level within SSE events, not at the HTTP chunk level. Parse each `data:` line, extract JSON, find `delta.text`, run buffer/restore, re-serialize, forward.

### TLS Interception

**Not needed for MVP.** With `ANTHROPIC_BASE_URL`, the proxy runs plain HTTP locally and makes its own HTTPS call upstream:

```
Claude Code --HTTP--> localhost:9100 (anon proxy) --HTTPS--> api.anthropic.com
```

Only needed if using `HTTPS_PROXY` (forward proxy mode, e.g., for Copilot). That requires generating a CA cert, adding to system trust store, dynamically generating certs per domain — what `mitmproxy` does. Avoid for MVP.

### Session / Mapping Lifecycle

The mapping must persist across multi-turn conversations.

- **Session boundary**: proxy process lifetime. Start `anon proxy`, use Claude Code, stop proxy = one session.
- **Additive mapping**: new PII detected in later turns gets new token numbers. `EMAIL_ADDRESS_1` always maps to the same email within a session.
- **Storage**: in-memory `HashMap`, persisted to disk on shutdown (`~/.anon/sessions/<id>.json`). Reload on restart.

### Tool Use / Structured JSON

API responses contain tool calls:

```json
{"type": "tool_use", "name": "Read", "input": {"file_path": "/tmp/[EMAIL_ADDRESS_1].log"}}
```

Rule: only restore inside JSON string **values**, recursively. Never touch keys, field names, or JSON structure. The existing `anonymize_json_value` logic (walks `serde_json::Value`, only touches strings) applies directly to restoration.

For request-side anonymization, target specific fields in the API schema:
- Anthropic: `messages[].content` (string or content blocks), `system`
- OpenAI: `messages[].content`

Don't blindly anonymize the entire request body — model names, tool definitions, etc. must stay untouched.

### Token Length Mismatch

`john.doe@acme-corp.com` (22 chars) → `[EMAIL_ADDRESS_1]` (17 chars). Generally fine — AI tools don't do their own token counting on the prompt. The only edge case is short originals expanding (crew code `JD` → `[CREW_CODE_1]` = 13 chars), but impact on context window is negligible.

---

## 3. MVP Architecture

### Target: Reverse proxy for Claude Code, streaming-aware

```
ANTHROPIC_BASE_URL=http://127.0.0.1:9100 claude

┌─────────────────────────────────────────────────┐
│                anon proxy (:9100)                │
│                                                  │
│  Request:                                        │
│    Parse JSON body                               │
│    Walk messages[].content → anonymize strings   │
│    Walk system → anonymize                       │
│    Store mapping (session-scoped)                │
│    Forward to api.anthropic.com                  │
│                                                  │
│  Response:                                       │
│    If streaming (SSE):                           │
│      Parse each event's delta.text               │
│      Buffer-restore [TOKEN] patterns             │
│      Forward restored events                     │
│    If non-streaming:                             │
│      Parse JSON, walk content → restore strings  │
│      Forward restored response                   │
│                                                  │
│  Session: in-memory HashMap, persisted to disk   │
└─────────────────────────────────────────────────┘
```

**Stack**: existing Rust `Anonymizer` + `hyper` (HTTP server) + `reqwest` (upstream client) + `tokio` (async). All in the Rust ecosystem.

**MVP scope**:
- Anthropic Messages API only (`/v1/messages`)
- Anonymize request `messages[].content` and `system` fields
- Restore response `content[].text` and streaming `delta.text`
- In-memory mapping, dump to file on shutdown
- Single session (one proxy instance = one session)

**Skip in MVP**: OpenAI format, tool call content restoration, multi-session management, TLS/forward proxy, pretty-print mapping.

### Estimated scope

~400-600 lines of Rust on top of the existing anonymizer:
- HTTP server + routing: ~100 lines (hyper)
- Request anonymization (parse Anthropic schema, walk fields): ~100 lines
- Response restoration (non-streaming): ~50 lines
- SSE streaming parser + buffer-restore: ~150 lines
- Session/mapping management: ~50 lines
- CLI integration (`anon proxy` subcommand): ~50 lines

### Usage

```bash
# Terminal 1: start proxy
anon proxy --port 9100

# Terminal 2: use Claude Code normally
ANTHROPIC_BASE_URL=http://127.0.0.1:9100 claude
```

---

## 4. Existing Tools

| Project | What it does | Gap |
|---------|-------------|-----|
| [anonLLM](https://github.com/fsndzomga/anonLLM) | Python lib, anonymize before LLM call, de-anonymize after | Library, not proxy. No streaming. |
| [Ploomber + Presidio proxy](https://ploomber.io/blog/pii-openai/) | FastAPI reverse proxy using Presidio for OpenAI | Python, no streaming, OpenAI only |
| [Private AI](https://www.private-ai.com/en) | Commercial SaaS, 50+ entity types, proxy mode | Paid, cloud-based |
| [LiteLLM + Pillar Security](https://docs.litellm.ai/docs/proxy/guardrails/pillar_security) | LiteLLM guardrails that mask PII before forwarding | Python, requires LiteLLM infra |
| [Anonymizer SLM](https://huggingface.co/blog/pratyushrt/anonymizerslm) | Small LM that replaces PII with semantic fakes | Needs model inference, heavyweight |
| [prompt-anonymizer](https://github.com/akazah/prompt-anonymizer) | Browser extension for ChatGPT web UI | Web only, no API proxy |
| [DataFog](https://github.com/DataFog/datafog-python) | Python PII detection lib with FastAPI middleware | Library, no restore/de-anonymization |

None of these are: (a) a Rust single-binary proxy, (b) streaming-aware with SSE buffering, (c) designed for CLI AI tools like Claude Code, or (d) supporting custom domain-specific patterns (aviation, crew codes).

---

## 5. Agent Recommendations

Consolidated recommendations from seven specialist reviews: architecture, security, performance, design, DevOps, UX, and offensive security.

### Architecture (Tech Lead)

**File structure**: Single binary, but split `src/main.rs` into modules:

```
src/
  lib.rs          # re-exports
  patterns.rs     # PiiPattern, PATTERNS, CREW_CODE_BLOCKLIST
  mapping.rs      # Mapping struct, serialization, restore logic
  detection.rs    # Anonymizer, CompiledPattern, Detection
  format.rs       # DetectedFormat, detect_format, detect_json_indent
  cli.rs          # Clap structs, main() for batch mode
  proxy/
    mod.rs        # proxy server entry point
    handler.rs    # request/response anonymize/restore
    sse.rs        # SSE stream parser, bracket-buffer state machine
    anthropic.rs  # Anthropic API schema (which fields to walk)
```

**HTTP framework**: axum 0.8. One route (`POST /v1/messages`) + catch-all passthrough. Don't use axum's SSE extractor — return a raw streaming `Body` instead. hyper alone would work but axum eliminates routing boilerplate for ~3s extra compile time.

**Upstream client**: reqwest 0.12 with `rustls-tls` + `stream` features. Create one `reqwest::Client` at startup, clone into each handler (Arc, free clone). Set timeout to 300s (Opus responses can take 60s+).

**Shared state**: `Arc<Mutex<Anonymizer>>` for MVP. Claude Code sends one request at a time — no real contention. Don't reach for `RwLock` or lock-free structures yet.

**Feature gating**: Gate proxy deps behind a cargo feature to keep CLI-only builds fast:

```toml
[dependencies]
tokio = { version = "1", features = ["full"], optional = true }
axum = { version = "0.8", optional = true }
reqwest = { version = "0.12", default-features = false, features = ["rustls-tls", "stream"], optional = true }
futures = { version = "0.3", optional = true }
bytes = { version = "1", optional = true }

[features]
default = []
proxy = ["tokio", "axum", "reqwest", "futures", "bytes"]
```

**Mapping persistence**: Dump after every request completion (not just shutdown). Sub-millisecond overhead, survives SIGKILL/OOM. Use `tokio::signal::ctrl_c()` + `tokio::select!` for graceful shutdown.

**Blind spots in the original design**:
- `system` can be a string (legacy) or array of content blocks — handle both
- `tool_result` content blocks in messages contain file contents/command output — these have PII too
- `input_json_delta` in streaming responses carries tool call inputs (file paths with tokens) — missing restoration here is a showstopper
- Must recalculate or remove `Content-Length` after body transformation

### Performance (ThePrimeagen)

**File split**: Agrees — sync CLI and async proxy are different execution models. Two or three files, not for "clean code" but because `#[tokio::main]` shouldn't infect the synchronous CLI path.

**Framework**: Prefers hyper over axum — "you're building a reverse proxy, not a web app. One route. axum's abstractions are in your way." Valid counterpoint, but axum's overhead is negligible for this use case.

**SSE buffer**: Don't over-engineer a state machine with explicit state enum. Just scan the string: if it ends mid-bracket (has `[` but no `]`), hold the suffix and prepend to next chunk. Two cases, not an enum.

**Regex perf**: 22 compiled regex patterns on a few KB prompt = microseconds. The API call takes 500ms-5000ms. Don't optimize this. If you ever want to, use `RegexSet` for a single-pass check, but you won't need to.

**reqwest vs hyper client**: reqwest is fine. You're proxying to an API at ~50 tokens/s. The bottleneck is network I/O, not allocations.

**MVP scope adjustment**: Cut session persistence to disk — in-memory only for v0.1. Add a `GET /health` endpoint (5 lines, invaluable for debugging).

### Design (Martin Fowler)

**Core insight**: Separate the immutable (pattern engine) from the mutable (session mapping):

```rust
struct PatternEngine { patterns: Vec<CompiledPattern>, threshold: f64 }  // Arc, shared freely
struct SessionMapping { ... }  // Arc<RwLock<...>>, append-only
```

Detection is `&self` on the engine (no lock). Only mapping insertion needs a write lock. Restoration only needs a read lock.

**Don't unify anonymize/restore**: They're asymmetric. Anonymize = detection + replacement (complex). Restore = substitution (simple). Instead, extract the shared JSON walker:

```rust
fn walk_json_strings(value: &Value, transform: &mut dyn FnMut(&str) -> String) -> Value
```

Both anonymize and restore call this with different closures.

**Schema knowledge as explicit module**: `anthropic.rs` knows which fields to walk. When you add OpenAI, add `openai.rs` with the same interface. Field whitelist, not blacklist.

**Testing strategy**:
- Unit tests: pattern detection, mapping consistency, restore round-trip, JSON walking (you already have 31)
- Integration tests: SSE buffer with split tokens, Anthropic schema field targeting
- E2E tests: 3-5 scenarios with a mock upstream HTTP server, not the real API
- The SSE buffer state machine is the single most important thing to test. Write those tests first.

**Preparatory refactoring**: Extract modules first (patterns, mapping, detection, format, cli). Get tests passing. Then add `proxy/` on top. "Make the change easy, then make the easy change."

### Security (Defensive Review)

**12 must-have controls for day one**:

| # | Control |
|---|---------|
| 1 | Bind to `127.0.0.1` only, never `0.0.0.0` |
| 2 | Validate `Host` header — reject if not `127.0.0.1:<port>` or `localhost:<port>` (DNS rebinding defense) |
| 3 | SSE buffer hard cap at 64 bytes |
| 4 | Total response size cap (100 MB) |
| 5 | Upstream timeouts (connect: 10s, read: 300s) |
| 6 | Sanitize error messages — never include raw request/response body (serde_json errors include input snippets) |
| 7 | Custom panic hook — suppress PII in panic output |
| 8 | Session directory `0o700`, mapping files `0o600` |
| 9 | Never log `x-api-key` or `Authorization` headers |
| 10 | Randomized token IDs: `[EMAIL_ADDRESS_a7f3e2]` not `[EMAIL_ADDRESS_1]` — prevents prompt injection guessing |
| 11 | Context-aware restoration — only restore in display text, not in tool_use inputs |
| 12 | Hardcode upstream URL, never derive from request headers |

**Token injection is the critical finding**: The model can output `[EMAIL_ADDRESS_1]` in its response, and the restore logic substitutes real PII. Worse, a prompt injection could enumerate all tokens (`[EMAIL_ADDRESS_1]`, `[EMAIL_ADDRESS_2]`, `[FR_SSN_1]`, etc.) and exfiltrate all session PII in one response. Randomized hex IDs make this impractical.

**API key handling**: Consider having the proxy inject the key from its own environment instead of forwarding from the client. Claude Code sends a dummy key, proxy injects the real one. Reduces exposure surface.

**PII leakage paths**: Error messages (serde_json includes input snippets), panic payloads, `Debug` trait on structs holding PII, core dumps, `RUST_LOG` debug-level logging on reqwest/hyper. Disable core dumps at process start with `setrlimit(RLIMIT_CORE, 0)`.

### Offensive Security

**Threat model**:
```
[User/Claude Code] --trusts--> [anon proxy on localhost] --distrusts--> [api.anthropic.com]
```

**Top findings by severity**:

1. **Critical — Token injection / PII exfiltration**: Model outputs `[EMAIL_ADDRESS_1]` → proxy restores real email → attacker reads it. Cross-context injection: model emits a `Write` tool call with `[EMAIL_ADDRESS_1]` in the content → proxy restores → PII written to a file. Mitigation: randomized token IDs + restore only in display text, not tool inputs.

2. **Critical — SSE buffer unbounded growth**: A `[` followed by infinite chars without `]` = OOM. Hard cap at 64 bytes is non-negotiable.

3. **High — DNS rebinding**: Browser JS at `evil.com` can reach `127.0.0.1:9100` via DNS rebinding. Attacker uses victim's API key, reads restored PII. Mitigation: `Host` header validation + no CORS headers.

4. **High — No authentication**: Any local process can call the proxy. Mitigation: per-session bearer token generated at startup.

5. **High — Mapping file is cleartext PII**: `~/.anon/sessions/*.json` is a single point of compromise. Mitigation: auto-delete with TTL, or encrypt with derived key.

6. **Medium — SSRF via path traversal**: If proxy forwards any path (not just `/v1/messages`), attacker can access other Anthropic API endpoints. Mitigation: allowlist `/v1/messages` only.

**Non-guessable token format is the single most impactful security change**: `[__ANON_a7f3b2c1__]` with random hex instead of sequential integers.

### UX Review

**Primary UX recommendation — wrapper mode as default interface**:

```bash
# Primary usage (recommended)
anon proxy --wrap claude

# What it does:
# 1. Start proxy on ephemeral port (no port conflicts)
# 2. Set ANTHROPIC_BASE_URL automatically
# 3. Spawn claude as child process, forward stdin/stdout/stderr
# 4. On child exit: save mapping, print summary, exit
```

Two-terminal mode stays as advanced option. The wrapper eliminates three failure modes: forgetting the env var, typo in port, accidentally closing the proxy terminal.

**Terminal output — three verbosity levels**:

Default (per-request summary):
```
14:32:01  POST /v1/messages  5 entities anonymized  [EMAIL_ADDRESS: 2, IP_ADDRESS: 2, FR_PHONE_NUMBER: 1]
14:32:04  POST /v1/messages  (streaming) 5 entities restored
```

`-v` (verbose): entity types and lengths, no values.
`-vv` (debug): full PII in output, with a printed warning.

**Verification is critical**: Users need proof PII is being stripped. A `--dry-run` mode and verbose logging are the minimum. Later: `GET /_anon/status` endpoint returning session stats as JSON.

**Error handling**: Port-in-use → suggest `--port 9101` or auto-detect. Upstream unreachable → health check on startup, clear message. Parse failure → forward raw response unchanged ("do no harm").

**First-run onboarding**: On first run (no `~/.anon/` directory), print a brief explanation of how it works. Only once.

**Session inspection**:
```bash
anon sessions list       # list all sessions with entity counts
anon sessions show <id>  # show mapping grouped by entity type
```

### DevOps / Infrastructure

**Distribution**: GitLab Releases with pre-built binaries (x86_64 + aarch64 macOS, x86_64 Linux gnu + musl). Install script: `curl -fsSL .../install.sh | sh`. Homebrew tap second. `cargo install` as fallback. Skip Nix/AUR/Debian until users ask.

**Wrapper mode** (`anon proxy --wrap claude`) is the most impactful adoption decision. If users have to manage two terminals and an env var, they try it once and forget.

**Port management**: Default 9100, auto-increment on conflict (like webpack-dev-server/Vite). In wrapper mode, use ephemeral port — user never needs to know.

**Graceful shutdown**: SIGINT/SIGTERM → stop accepting connections → drain in-flight (5s timeout) → dump mapping → print summary → exit. Double SIGINT = force exit.

**Logging**: Use `tracing` crate from the start. JSON output option (`--log-format json`) for observability pipelines. Not MVP, but the right foundation.

**Config**: CLI flags with env var fallbacks. No config file for MVP.

```
--port          ANON_PROXY_PORT       9100
--bind          ANON_PROXY_BIND       127.0.0.1
--upstream      ANON_PROXY_UPSTREAM   https://api.anthropic.com
--session-dir   ANON_SESSION_DIR      ~/.anon/sessions
--verbose / -v  ANON_LOG_LEVEL        info
```

**CI**: GitLab CI cross-compile matrix (macOS x86+arm, Linux gnu+musl). `cargo audit` + `cargo deny` in CI. Commit `Cargo.lock`. Release on tag push.

---

## 6. Consolidated Decision Matrix

| Decision | Recommendation | Agreed by |
|----------|---------------|-----------|
| File structure | Split to modules (`lib.rs`, `proxy/`, `sse.rs`) | All |
| HTTP framework | axum 0.8 (arch, design) or hyper (perf) — axum wins for maintainability | 5/7 axum, 2/7 hyper |
| Upstream client | reqwest 0.12 with rustls | All |
| Shared state | `Arc<Mutex<Anonymizer>>` for MVP, separate `PatternEngine`/`SessionMapping` later | Arch + Design |
| SSE buffer | Bracket-detect, 64-byte hard cap, buffer persists per-response | All |
| Token format | **Randomized hex IDs** (`[EMAIL_ADDRESS_a7f3e2]`) — prevents injection | Security + Offensive |
| Primary UX | `anon proxy --wrap claude` (single command) | UX + DevOps |
| Restore scope | Display text only, **not** tool_use inputs (prevents exfiltration) | Security + Offensive |
| Mapping persistence | Dump after each request + on shutdown (survives SIGKILL) | Arch + DevOps |
| Auth | Per-session bearer token on localhost | Offensive + Security |
| Host validation | Reject non-localhost Host headers | Security + Offensive |
| Error handling | Never include raw body in errors, custom panic hook | Security |
| Distribution | GitLab Releases + Homebrew tap + cargo install | DevOps |
| Testing | SSE buffer tests first, mock upstream for E2E, cargo-fuzz later | Design + DevOps |
| Feature gating | `proxy` cargo feature to avoid async deps for CLI builds | Arch |

---

## 7. Implementation Order

### Phase 1: Preparatory Refactoring
- Extract modules: `patterns.rs`, `mapping.rs`, `detection.rs`, `format.rs`, `cli.rs`
- All existing tests pass, binary works identically
- Add randomized token IDs to `Mapping`

### Phase 2: Core Proxy
- `proxy/mod.rs`: axum server, startup, shutdown, signal handling
- `proxy/handler.rs`: request anonymization, non-streaming response restoration
- `proxy/anthropic.rs`: field whitelist for Anthropic Messages API
- Bind `127.0.0.1` only, `Host` header validation, hardcoded upstream

### Phase 3: SSE Streaming
- `proxy/sse.rs`: SSE event parser + `TokenBuffer` bracket-detect state machine
- Streaming response restoration
- 64-byte buffer cap, response size cap

### Phase 4: UX
- `--wrap` mode (spawn child process with env var set)
- Three verbosity levels, terminal output spec
- Graceful shutdown with mapping dump
- First-run onboarding message
- Error messages (port in use, upstream unreachable)

### Phase 5: Distribution
- GitLab CI cross-compile matrix
- Pre-built binaries, install script
- Homebrew tap

---

## References

- [Claude Code enterprise network configuration](https://code.claude.com/docs/en/network-config)
- [Claude Code hooks reference](https://docs.claude.com/en/docs/claude-code/hooks)
- [Cursor network configuration](https://cursor.com/docs/enterprise/network-configuration)
- [TensorZero: Reverse engineering Cursor's LLM client](https://www.tensorzero.com/blog/reverse-engineering-cursors-llm-client/)
- [Ploomber: Removing PII from OpenAI API calls with Presidio](https://ploomber.io/blog/pii-openai/)
- [LiteLLM Pillar Security guardrails](https://docs.litellm.ai/docs/proxy/guardrails/pillar_security)
