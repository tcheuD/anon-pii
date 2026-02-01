# Proxy Mode

[Back to README](../README.md)

Anonymizing reverse proxy that sits between AI coding tools and the Anthropic API. PII is stripped from outgoing prompts and restored in incoming responses — including SSE streams.

## Start the proxy

```bash
anon proxy
# anon proxy listening on http://127.0.0.1:9100
# upstream: https://api.anthropic.com
```

## Use with Claude Code

```bash
ANTHROPIC_BASE_URL=http://127.0.0.1:9100 claude
```

All prompts are anonymized before reaching the API. Responses have tokens restored automatically.

## Options

| Option | Short | Default | Description |
|--------|-------|---------|-------------|
| `--port` | `-p` | `9100` | Port to listen on |
| `--upstream` | `-u` | `https://api.anthropic.com` | Upstream API URL |
| `--threshold` | | `0.5` | Minimum confidence score (0.0-1.0) |
| `--session-dir` | | `/tmp/anon-proxy-<random>` | Directory for mapping files |

## Testing without an API key

Point the proxy at a local echo server to inspect what gets sent upstream:

```bash
# Terminal 1 — echo server
python3 -c "
import http.server, json
class H(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        body = self.rfile.read(int(self.headers['Content-Length']))
        print(json.dumps(json.loads(body), indent=2))
        self.send_response(200)
        self.send_header('content-type','application/json')
        self.end_headers()
        self.wfile.write(json.dumps({'content':[{'type':'text','text':'ok'}]}).encode())
http.server.HTTPServer(('127.0.0.1',8888),H).serve_forever()
"

# Terminal 2 — proxy pointing at echo server
anon proxy --upstream http://127.0.0.1:8888

# Terminal 3 — send a request
curl -s http://127.0.0.1:9100/v1/messages \
  -H "content-type: application/json" \
  -d '{"messages":[{"role":"user","content":"Email me at john@secret.com"}]}' | jq .
```

The echo server prints the anonymized body — `[EMAIL_ADDRESS_1]` instead of `john@secret.com`.

## Monitoring

The mapping file is written after each request and on shutdown. The session directory path is printed at startup:

```bash
# Watch the mapping grow (use the path printed by the proxy)
watch -n1 'jq . /tmp/anon-proxy-*/mapping.json 2>/dev/null'

# Or use a fixed session dir
anon proxy --session-dir /tmp/my-session
watch -n1 'jq . /tmp/my-session/mapping.json'
```

## Test with curl

```bash
# Non-streaming
curl -s http://127.0.0.1:9100/v1/messages \
  -H "x-api-key: $ANTHROPIC_API_KEY" \
  -H "anthropic-version: 2023-06-01" \
  -H "content-type: application/json" \
  -d '{
    "model": "claude-sonnet-4-20250514",
    "max_tokens": 256,
    "messages": [
      {"role": "user", "content": "Summarize: John lives at john@example.com, IP 192.168.1.42"}
    ]
  }' | jq .

# Streaming
curl -s --no-buffer http://127.0.0.1:9100/v1/messages \
  -H "x-api-key: $ANTHROPIC_API_KEY" \
  -H "anthropic-version: 2023-06-01" \
  -H "content-type: application/json" \
  -d '{
    "model": "claude-sonnet-4-20250514",
    "max_tokens": 256,
    "stream": true,
    "messages": [
      {"role": "user", "content": "What about pilot JDU on aircraft F-HOPA?"}
    ]
  }'
```

## Security notes

- Binds to `127.0.0.1` only — not accessible from the network
- Host header validation blocks DNS rebinding attacks
- Mapping file contains original PII — treat it as sensitive
- API keys are forwarded but never logged or stored
