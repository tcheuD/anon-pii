use std::sync::Arc;

use axum::body::Body;
use axum::extract::{Request, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use bytes::Bytes;
use futures::StreamExt;

use super::anthropic;
use super::sse::{self, TokenBuffer};
use super::ProxyState;

/// Handle POST /v1/messages — the Anthropic Messages API endpoint.
///
/// Flow:
/// 1. Read request body, parse as JSON
/// 2. Anonymize PII in the request
/// 3. Forward to upstream
/// 4. If streaming: process SSE events, restore tokens
/// 5. If not streaming: restore tokens in response body
/// 6. Dump mapping after each request
pub async fn handle_messages(
    State(state): State<Arc<ProxyState>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
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

async fn handle_streaming(
    state: Arc<ProxyState>,
    upstream_resp: reqwest::Response,
    status: reqwest::StatusCode,
    resp_headers: HeaderMap<HeaderValue>,
) -> Response {
    let mapping = state.get_mapping_snapshot().await;
    let mut token_buffer = TokenBuffer::new(mapping);

    // Read the SSE stream and process events
    let byte_stream = upstream_resp.bytes_stream();

    let processed_stream = byte_stream.map(move |chunk_result| {
        match chunk_result {
            Ok(chunk) => {
                let text = String::from_utf8_lossy(&chunk);
                let mut output = String::new();

                // Process each SSE line
                for line in text.split('\n') {
                    if let Some(data) = line.strip_prefix("data: ") {
                        if data == "[DONE]" {
                            // Flush remaining buffer
                            let remaining = token_buffer.flush();
                            if !remaining.is_empty() {
                                output.push_str(&format!("data: {remaining}\n\n"));
                            }
                            output.push_str("data: [DONE]\n\n");
                            continue;
                        }

                        // Check if this event has a text delta
                        if let Some(text_content) = sse::extract_text_delta(data) {
                            // Feed through token buffer for restoration
                            let restored = token_buffer.feed(&text_content);
                            if !restored.is_empty() {
                                // Rebuild the SSE event with restored text
                                if let Some(new_data) =
                                    sse::replace_text_delta(data, &restored)
                                {
                                    output.push_str(&format!("data: {new_data}\n\n"));
                                } else {
                                    output.push_str(line);
                                    output.push('\n');
                                }
                            }
                            // If restored is empty, buffer is accumulating — don't emit
                        } else {
                            // Non-text event, pass through
                            output.push_str(line);
                            output.push('\n');
                        }
                    } else if !line.is_empty() {
                        // Event type or other SSE lines
                        output.push_str(line);
                        output.push('\n');
                    } else {
                        // Empty line (event separator)
                        output.push('\n');
                    }
                }

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

/// Passthrough handler for any non-/v1/messages paths.
/// Forwards the request as-is without anonymization.
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

    // Forward all headers
    for (name, value) in headers.iter() {
        let name_str: &str = name.as_str();
        if name_str != "host" && name_str != "connection" {
            if let Ok(rn) = reqwest::header::HeaderName::from_bytes(name.as_str().as_bytes()) {
                if let Ok(rv) = reqwest::header::HeaderValue::from_bytes(value.as_bytes()) {
                    upstream_req = upstream_req.header(rn, rv);
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
