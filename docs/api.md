# REST API

[Back to README](../README.md)

`anon-pii api` starts a local Presidio-compatible HTTP API. It is compiled by
the `proxy` feature because it uses the same async HTTP stack as proxy mode.

## Install

The [native release archives](../README.md#installation) include the API.
The crate is not published on crates.io. From a source checkout:

```bash
cargo install --locked --path . --features ner-lite,proxy
```

## Start

```bash
anon-pii api --port 8080
```

The server listens on `127.0.0.1`. It exposes the OpenAPI document at
`/openapi.yaml`; the checked-in reference is [openapi.yaml](openapi.yaml).

## Endpoints

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/analyze` | `POST` | Detect PII entities and return spans, entity types, and scores |
| `/anonymize` | `POST` | Apply Presidio-style anonymizers to supplied analyzer results |
| `/supportedentities` | `GET` | List entity types available in the current build |
| `/health` | `GET` | Health check |
| `/openapi.yaml` | `GET` | OpenAPI specification |

## Analyze Example

```bash
curl -s http://127.0.0.1:8080/analyze \
  -H "content-type: application/json" \
  -d '{
    "text": "Contact john@example.com or call +33 6 12 34 56 78",
    "language": "en",
    "score_threshold": 0.5
  }' | jq .
```

## Anonymize Example

Native v0.3.5 archives and current source builds return nonoverlapping `/analyze`
results that can be sent directly to `/anonymize` with the same original text.
Offsets are UTF-8 byte positions, not character counts. Requested `entities` are
selected before overlap resolution. If both a URL and an email inside it are
recognized, the enclosing URL is returned. Selecting only `EMAIL_ADDRESS`
returns the email's source span instead. Nested URL audit details remain
available in CLI detection reports. `/anonymize` still rejects overlapping
results supplied by a caller.

Native archives through v0.3.4 predate this API handoff fix and can return
overlapping URL and query-value results. Upgrade to v0.3.5 or use a current source
build for this workflow.

```bash
curl -s http://127.0.0.1:8080/anonymize \
  -H "content-type: application/json" \
  -d '{
    "text": "Contact john@example.com",
    "analyzer_results": [
      {"entity_type": "EMAIL_ADDRESS", "start": 8, "end": 24, "score": 0.85}
    ],
    "anonymizers": {
      "DEFAULT": {"type": "replace"},
      "EMAIL_ADDRESS": {"type": "mask", "masking_char": "*"}
    }
  }' | jq .
```

## Feature Notes

- Regex and validator-based entities are always available.
- PERSON detection on `/analyze` requires a build with `ner-lite` or `ner`.
  The endpoint enables the compiled detector automatically; `ner` also requires
  the local model and ONNX Runtime to be available.
- The API is local-only and does not add authentication. Do not expose it on a
  network interface without an external access-control layer.
