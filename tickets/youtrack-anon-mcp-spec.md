# youtrack-anon-mcp — Technical Spec

> This is the build spec for Phase 2. Do not start until the pre-requisites in `youtrack-anon-mcp.md` are met and the `yt` script has been used long enough to validate detection coverage.

## Architecture

```
Claude Code (LLM) <--> MCP Server (local stdio) <--> YouTrack Cloud API
                              |
                       Presidio + spaCy + custom aviation recognizers
                       (anonymize/restore with token mapping)
```

Data flow:
- **READ**: YouTrack API -> raw data -> Presidio anonymize -> `[PERSON_1]`, `[EMAIL_ADDRESS_1]` etc -> Claude sees only tokens
- **WRITE**: Claude sends tokens -> restore from mapping -> real values -> YouTrack API

## Tech Stack

- **Python 3.12+**
- `presidio-analyzer` + `presidio-anonymizer` for PII detection/replacement
- `spacy` with `fr_core_news_lg` model for French NER (names, addresses, organizations)
- Custom `PatternRecognizer` classes for aviation entities
- `mcp` (Python MCP SDK, stdio transport)
- `httpx` for YouTrack API calls
- `pydantic` for configuration and data models

### Why Presidio over Rust `anon`?

| Capability | Rust `anon` | Python Presidio |
|---|---|---|
| Physical addresses | No | Yes (spaCy NER) |
| Person names (multilingual) | DistilBERT NER (8 languages) | spaCy NER (broader) |
| Aviation patterns (crew, aircraft, flights) | Yes (built-in) | No (must add custom) |
| PNR locators, route pairs | No | No (must add custom) |
| Custom pattern addition | Rust regex + recompile | `PatternRecognizer` subclass, ~20 lines |
| Latency | ~1ms | ~50-200ms |
| Runtime dependency | Single binary | Python + spaCy model (~500MB) |

Presidio's broader NLP coverage matters more than raw speed for MCP (YouTrack API calls dominate at ~200-500ms each). Aviation patterns are added as custom recognizer classes.

The Rust `anon` CLI remains the right tool for fast piping of debug logs and the Anthropic API proxy.

## MCP Tools

### Read tools (anonymized output)

| Tool | Description | Anonymized fields |
|---|---|---|
| `get_issue` | Fetch issue by ID | summary, description, reporter name |
| `search_issues` | Search with YouTrack query (max 25 results) | summary |
| `get_issue_comments` | Get comments for an issue | comment text, author name |
| `get_project` | Get project details | description, lead name |

### Write tools (restore before sending, dry_run default)

| Tool | Description | Restored fields |
|---|---|---|
| `create_issue` | Create a new issue | summary, description |
| `update_issue_state` | Update issue state | none (state is not PII) |
| `add_comment` | Add comment to issue | comment text |

### Utility tools

| Tool | Description |
|---|---|
| `get_mapping` | Show current token-to-type mapping (types only, never originals) |

## Configuration

```json
{
  "mcpServers": {
    "youtrack": {
      "command": "uv",
      "args": ["run", "--directory", "/path/to/youtrack-anon-mcp", "youtrack-anon-mcp"],
      "env": {
        "YOUTRACK_URL": "https://instance.youtrack.cloud",
        "YOUTRACK_TOKEN": "perm:xxx"
      }
    }
  }
}
```

## Project Structure

```
youtrack-anon-mcp/
├── pyproject.toml
├── src/
│   └── youtrack_anon_mcp/
│       ├── __init__.py
│       ├── server.py          # MCP server setup, stdio transport
│       ├── tools.py           # Tool definitions and handlers
│       ├── youtrack.py        # YouTrack API client
│       ├── anonymizer.py      # Presidio setup + custom aviation recognizers
│       └── recognizers/
│           ├── __init__.py
│           ├── aviation.py    # Aircraft reg, flight numbers, crew codes
│           └── french.py      # PNR locators, route pairs, employee IDs
├── tests/
├── CLAUDE.md
└── README.md
```

## Dependencies (pyproject.toml)

```toml
[project]
name = "youtrack-anon-mcp"
requires-python = ">=3.12"

[tool.uv]
dev-dependencies = ["pytest", "pytest-asyncio", "ruff", "mypy"]

dependencies = [
    "mcp",
    "httpx",
    "presidio-analyzer",
    "presidio-anonymizer",
    "spacy",
    "pydantic",
    "pydantic-settings",
]

[project.scripts]
youtrack-anon-mcp = "youtrack_anon_mcp.server:main"
```

## Mandatory Technical Conditions

1. **Load spaCy model**: Install and load `fr_core_news_lg` at startup for French NER
2. **Add custom recognizers**: Aviation `PatternRecognizer` classes for PNR locators, route pairs, crew codes, aircraft registrations, flight numbers, employee IDs
3. **Pre-write validation**: Reject write payloads containing unresolved bracket tokens
4. **Persist mapping**: Atomic writes to disk on every tool call, require FileVault/LUKS
5. **Detection logging**: Log entity count per type per tool call, warn on zero detections for large text
6. **Rate limiting**: Prevent rapid enumeration of issues through automated queries

## Deployment Phases

### Phase 1: Read-only

- Deploy with read tools only (get_issue, search_issues, get_issue_comments, get_project)
- No write tools enabled
- Monitor what data flows through, review detection logs
- Tune custom patterns based on observed misses

### Phase 2: Writes with dry_run

- Enable write tools with `dry_run: true` as default
- Claude must explicitly set `dry_run: false` to execute
- Human reviews the restored payload in dry_run output before approving

### Phase 3: Full deployment

- Enable writes with dry_run still defaulting to true
- Consider hybrid: MCP for reads, shell script (`yt`) for writes (human confirms on `/dev/tty`)
