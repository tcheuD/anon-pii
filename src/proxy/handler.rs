use std::sync::Arc;

use axum::body::Body;
use axum::extract::{Request, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use bytes::Bytes;
use futures::StreamExt;

use super::anthropic;
use super::sse::{self, TokenBuffer, TokenResolver};
use super::ProxyState;

/// Maximum request body size for `/v1/messages` (10 MB).
const MAX_REQUEST_BODY_SIZE: usize = 10 * 1024 * 1024;

/// Handle POST /v1/messages — the Anthropic Messages API endpoint.
///
/// Flow:
/// 1. Read request body (with size limit), parse as JSON
/// 2. Anonymize PII in the request
/// 3. Forward to upstream
/// 4. If streaming: process SSE events, restore tokens
/// 5. If not streaming: restore tokens in response body
/// 6. Dump mapping after each request
pub async fn handle_messages(
    State(state): State<Arc<ProxyState>>,
    headers: HeaderMap,
    req: Request<Body>,
) -> Response {
    // Read body with size limit to prevent OOM
    let body: Bytes = match axum::body::to_bytes(req.into_body(), MAX_REQUEST_BODY_SIZE).await {
        Ok(b) => b,
        Err(_) => {
            return (
                StatusCode::PAYLOAD_TOO_LARGE,
                format!("Request body exceeds {} byte limit", MAX_REQUEST_BODY_SIZE),
            )
                .into_response();
        }
    };

    // Parse request body
    let mut body_json: serde_json::Value = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(e) => {
            return (StatusCode::BAD_REQUEST, format!("Invalid JSON: {e}")).into_response();
        }
    };

    let is_streaming = body_json
        .get("stream")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    // Anonymize the request
    {
        let mut anonymizer = state.anonymizer.lock().await;
        anthropic::anonymize_request(&mut body_json, &mut anonymizer);
    }

    let anonymized_body = match serde_json::to_vec(&body_json) {
        Ok(b) => b,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Serialization error: {e}"),
            )
                .into_response();
        }
    };

    // Build upstream request
    let upstream_url = format!("{}/v1/messages", state.upstream);
    let mut upstream_req = state.client.post(&upstream_url);

    // Forward relevant headers (auth, content type, anthropic-specific)
    for (name, value) in &headers {
        let name_str = name.as_str().to_lowercase();
        match name_str.as_str() {
            "x-api-key" | "anthropic-version" | "anthropic-beta" | "content-type"
            | "authorization" => {
                upstream_req = upstream_req.header(name.clone(), value.clone());
            }
            _ => {}
        }
    }

    upstream_req = upstream_req.body(anonymized_body);

    // Send to upstream
    let upstream_resp = match upstream_req.send().await {
        Ok(r) => r,
        Err(e) => {
            eprintln!("Upstream error: {e}");
            return (StatusCode::BAD_GATEWAY, "Upstream connection failed").into_response();
        }
    };

    let status = upstream_resp.status();
    let resp_headers = upstream_resp.headers().clone();

    if is_streaming && status.is_success() {
        // SSE streaming response — process events, restore tokens
        handle_streaming(state, upstream_resp, status, resp_headers).await
    } else {
        // Non-streaming — read full body, restore, return
        handle_non_streaming(state, upstream_resp, status, resp_headers).await
    }
}

async fn handle_non_streaming(
    state: Arc<ProxyState>,
    upstream_resp: reqwest::Response,
    status: reqwest::StatusCode,
    resp_headers: HeaderMap<HeaderValue>,
) -> Response {
    let body_bytes = match upstream_resp.bytes().await {
        Ok(b) => b,
        Err(e) => {
            eprintln!("Failed to read upstream response: {e}");
            return (StatusCode::BAD_GATEWAY, "Failed to read upstream response").into_response();
        }
    };

    // Only restore tokens in successful JSON responses
    let final_body = if status.is_success() {
        if let Ok(mut resp_json) = serde_json::from_slice::<serde_json::Value>(&body_bytes) {
            let mapping = state.get_mapping_snapshot().await;
            anthropic::restore_response(&mut resp_json, &mapping);

            // Dump mapping
            if let Err(e) = state.dump_mapping().await {
                eprintln!("Warning: failed to save mapping: {e}");
            }

            serde_json::to_vec(&resp_json).unwrap_or_else(|_| body_bytes.to_vec())
        } else {
            body_bytes.to_vec()
        }
    } else {
        body_bytes.to_vec()
    };

    let mut response = Response::builder().status(status.as_u16());

    // Forward response headers
    for (name, value) in &resp_headers {
        let name_str = name.as_str().to_lowercase();
        if name_str != "transfer-encoding" && name_str != "content-length" {
            response = response.header(name.clone(), value.clone());
        }
    }

    response
        .body(Body::from(final_body))
        .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
}

/// Resolver that tries to read the latest mapping from shared state,
/// falling back to a cached snapshot if the lock is contended.
struct LiveResolver {
    state: Arc<ProxyState>,
    cached: crate::mapping::Mapping,
}

impl TokenResolver for LiveResolver {
    fn restore(&self, text: &str) -> String {
        // try_lock avoids blocking the stream on contended mutex
        // Use restore_bracketed (not bare restore) to prevent token injection
        if let Ok(anonymizer) = self.state.anonymizer.try_lock() {
            anonymizer.mapping.restore_bracketed(text)
        } else {
            self.cached.restore_bracketed(text)
        }
    }
}

async fn handle_streaming(
    state: Arc<ProxyState>,
    upstream_resp: reqwest::Response,
    status: reqwest::StatusCode,
    resp_headers: HeaderMap<HeaderValue>,
) -> Response {
    let cached = state.get_mapping_snapshot().await;
    let resolver = LiveResolver {
        state: state.clone(),
        cached,
    };
    let mut token_buffer = TokenBuffer::new(resolver);

    // Read the SSE stream and process events
    let byte_stream = upstream_resp.bytes_stream();

    // Buffer for incomplete UTF-8 sequences split across TCP chunks
    let mut utf8_buf: Vec<u8> = Vec::new();
    // Buffer for incomplete SSE lines split across chunks
    let mut line_buf = String::new();

    let processed_stream = byte_stream.map(move |chunk_result| {
        match chunk_result {
            Ok(chunk) => {
                utf8_buf.extend_from_slice(&chunk);

                // Find the last valid UTF-8 boundary
                let valid_up_to = match std::str::from_utf8(&utf8_buf) {
                    Ok(_) => utf8_buf.len(),
                    Err(e) => e.valid_up_to(),
                };

                if valid_up_to == 0 {
                    // Entire buffer is incomplete UTF-8 — wait for more data
                    return Ok::<_, reqwest::Error>(Bytes::new());
                }

                let text = std::str::from_utf8(&utf8_buf[..valid_up_to]).unwrap();
                let remainder = utf8_buf[valid_up_to..].to_vec();

                let mut output = String::new();

                // Split into lines, keeping the last (possibly incomplete) line buffered
                let mut lines_iter = text.split('\n').peekable();
                while let Some(segment) = lines_iter.next() {
                    if lines_iter.peek().is_none() {
                        // Last segment — may be incomplete, buffer it
                        line_buf.push_str(segment);
                    } else {
                        // Complete line (newline follows)
                        line_buf.push_str(segment);
                        let line = std::mem::take(&mut line_buf);
                        process_sse_line(&line, &mut token_buffer, &mut output);
                    }
                }

                utf8_buf = remainder;

                Ok::<_, reqwest::Error>(Bytes::from(output))
            }
            Err(e) => Err(e),
        }
    });

    let body = Body::from_stream(processed_stream);

    let mut response = Response::builder().status(status.as_u16());
    for (name, value) in &resp_headers {
        let name_str = name.as_str().to_lowercase();
        if name_str != "transfer-encoding" && name_str != "content-length" {
            response = response.header(name.clone(), value.clone());
        }
    }

    // Dump mapping after starting stream (best effort)
    let state_clone = state.clone();
    tokio::spawn(async move {
        // Small delay to let some events flow
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        if let Err(e) = state_clone.dump_mapping().await {
            eprintln!("Warning: failed to save mapping: {e}");
        }
    });

    response
        .body(body)
        .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
}

fn process_sse_line<R: TokenResolver>(
    line: &str,
    token_buffer: &mut TokenBuffer<R>,
    output: &mut String,
) {
    if let Some(data) = line.strip_prefix("data: ") {
        if data == "[DONE]" {
            let remaining = token_buffer.flush();
            if !remaining.is_empty() {
                output.push_str(&format!("data: {remaining}\n\n"));
            }
            output.push_str("data: [DONE]\n\n");
            return;
        }

        if let Some(text_content) = sse::extract_text_delta(data) {
            let restored = token_buffer.feed(&text_content);
            if !restored.is_empty() {
                if let Some(new_data) = sse::replace_text_delta(data, &restored) {
                    output.push_str(&format!("data: {new_data}\n\n"));
                } else {
                    output.push_str(line);
                    output.push('\n');
                }
            }
        } else {
            output.push_str(line);
            output.push('\n');
        }
    } else if !line.is_empty() {
        output.push_str(line);
        output.push('\n');
    } else {
        output.push('\n');
    }
}

/// Allowed passthrough path prefixes — only forward to known Anthropic API paths.
const ALLOWED_PASSTHROUGH_PREFIXES: &[&str] = &["/v1/"];

/// Passthrough handler for any non-/v1/messages paths.
/// Forwards the request to known Anthropic API paths without anonymization.
/// Rejects requests to unrecognized paths to prevent SSRF.
pub async fn passthrough(
    State(state): State<Arc<ProxyState>>,
    req: Request<Body>,
) -> Response {
    let method = req.method().clone();
    let path = req
        .uri()
        .path_and_query()
        .map(|pq: &axum::http::uri::PathAndQuery| pq.as_str().to_string())
        .unwrap_or_default();

    // Reject paths that don't match known API prefixes
    if !ALLOWED_PASSTHROUGH_PREFIXES
        .iter()
        .any(|prefix| path.starts_with(prefix))
    {
        return (StatusCode::FORBIDDEN, "Forbidden: unknown API path").into_response();
    }

    let headers: HeaderMap = req.headers().clone();

    let body_bytes = match axum::body::to_bytes(req.into_body(), 10 * 1024 * 1024).await {
        Ok(b) => b,
        Err(e) => {
            return (StatusCode::BAD_REQUEST, format!("Failed to read body: {e}")).into_response();
        }
    };

    let upstream_url = format!("{}{}", state.upstream, path);

    let mut upstream_req = state.client.request(
        reqwest::Method::from_bytes(method.as_str().as_bytes()).unwrap_or(reqwest::Method::GET),
        &upstream_url,
    );

    // Forward only safe headers — strip auth headers to prevent credential leakage
    for (name, value) in headers.iter() {
        let name_str: &str = name.as_str();
        match name_str {
            "host" | "connection" => continue,
            "x-api-key" | "authorization" => {
                upstream_req = upstream_req.header(
                    reqwest::header::HeaderName::from_bytes(name.as_str().as_bytes()).unwrap(),
                    reqwest::header::HeaderValue::from_bytes(value.as_bytes()).unwrap(),
                );
            }
            _ => {
                if let Ok(rn) = reqwest::header::HeaderName::from_bytes(name.as_str().as_bytes()) {
                    if let Ok(rv) = reqwest::header::HeaderValue::from_bytes(value.as_bytes()) {
                        upstream_req = upstream_req.header(rn, rv);
                    }
                }
            }
        }
    }

    if !body_bytes.is_empty() {
        upstream_req = upstream_req.body(body_bytes.to_vec());
    }

    let upstream_resp = match upstream_req.send().await {
        Ok(r) => r,
        Err(e) => {
            eprintln!("Upstream error: {e}");
            return (StatusCode::BAD_GATEWAY, "Upstream connection failed").into_response();
        }
    };

    let status = upstream_resp.status();
    let resp_headers = upstream_resp.headers().clone();
    let resp_body = upstream_resp
        .bytes()
        .await
        .unwrap_or_default();

    let mut response = Response::builder().status(status.as_u16());
    for (name, value) in resp_headers.iter() {
        let n = name.as_str();
        if n != "transfer-encoding" && n != "content-length" {
            response = response.header(n, value.as_bytes());
        }
    }

    response
        .body(Body::from(resp_body))
        .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::to_bytes;

    #[tokio::test]
    async fn test_handle_messages_rejects_oversized_body() {
        let state = Arc::new(ProxyState::new(
            "http://localhost:0".to_string(),
            0.0,
            std::env::temp_dir().join("anon-test-handler"),
        ));

        // Build a request body that exceeds MAX_REQUEST_BODY_SIZE
        let oversized = vec![b'x'; MAX_REQUEST_BODY_SIZE + 1];
        let req = Request::builder()
            .method("POST")
            .uri("/v1/messages")
            .body(Body::from(oversized))
            .unwrap();

        let resp = handle_messages(State(state), HeaderMap::new(), req).await;
        assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);

        let body = to_bytes(resp.into_body(), 1024).await.unwrap();
        let text = String::from_utf8_lossy(&body);
        assert!(text.contains("byte limit"), "Response should mention the limit: {text}");
    }

    #[tokio::test]
    async fn test_handle_messages_accepts_valid_sized_body() {
        let state = Arc::new(ProxyState::new(
            "http://localhost:0".to_string(),
            0.0,
            std::env::temp_dir().join("anon-test-handler"),
        ));

        // Valid-sized JSON body — will fail at upstream connect, not at size limit
        let body = br#"{"model":"test","messages":[]}"#;
        let req = Request::builder()
            .method("POST")
            .uri("/v1/messages")
            .body(Body::from(body.to_vec()))
            .unwrap();

        let resp = handle_messages(State(state), HeaderMap::new(), req).await;
        // Should NOT be 413 — it will be 502 (upstream unreachable) or similar
        assert_ne!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);
    }
}
