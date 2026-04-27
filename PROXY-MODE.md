# Proxy Mode

[Back to README](README.md)

`anon-pii proxy` runs a local reverse proxy between an AI client and an
upstream LLM API. It anonymizes supported request fields before forwarding the
request, then restores bracketed random-hex tokens in supported response fields.

The maintained proxy guide is [docs/proxy.md](docs/proxy.md). This root file is
kept as a short public entry point for users who discover proxy mode from older
links.

## Install

```bash
cargo install anon-pii --features proxy
```

From a source checkout:

```bash
cargo install --path . --features proxy
```

## Start

```bash
# Anthropic-compatible Messages API
anon-pii proxy

# OpenAI-compatible Chat Completions API
anon-pii proxy --provider openai --upstream https://api.openai.com

# Generic JSON LLM endpoint, including local servers
anon-pii proxy --provider generic --upstream http://localhost:11434
```

The proxy binds to `127.0.0.1`, validates local Host headers, caps request and
stream buffers, and writes a session mapping file under its session directory.
Treat that session file as sensitive because it contains the original values
needed for restoration.

## Related Docs

- [Proxy guide](docs/proxy.md)
- [REST API guide](docs/api.md)
- [OpenAPI specification](docs/openapi.yaml)
