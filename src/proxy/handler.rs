use std::sync::Arc;

use axum::body::Body;
use axum::extract::{Request, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use bytes::Bytes;
use futures::StreamExt;

use super::ProxyState;
use super::anthropic;
use super::generic;
use super::openai;
use super::sse::{self, TokenBuffer, TokenResolver};

/// Maximum request body size for `/v1/messages` (10 MB).
const MAX_REQUEST_BODY_SIZE: usize = 10 * 1024 * 1024;

/// Maximum SSE stream duration (10 minutes).
const SSE_STREAM_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(600);

/// Maximum size for internal SSE buffers (utf8_buf, line_buf) — 1 MB each.
const MAX_SSE_BUFFER_SIZE: usize = 1024 * 1024;

/// Headers allowed to be forwarded to the upstream API (base headers).
/// Provider-specific headers are added via `allowed_headers_for_provider`.
const ALLOWED_UPSTREAM_HEADERS_BASE: &[&str] =
    &["authorization", "content-type", "accept", "user-agent"];

/// Anthropic-specific headers.
const ALLOWED_UPSTREAM_HEADERS_ANTHROPIC: &[&str] =
    &["x-api-key", "anthropic-version", "anthropic-beta"];

/// OpenAI-specific headers.
const ALLOWED_UPSTREAM_HEADERS_OPENAI: &[&str] = &["openai-organization", "openai-project"];

use super::Provider;

/// Get the list of allowed headers for a specific provider.
fn allowed_headers_for_provider(provider: Provider) -> Vec<&'static str> {
    allowed_headers_for_provider_with_options(provider, false)
}

/// Get the list of allowed headers for a provider with generic-provider options.
fn allowed_headers_for_provider_with_options(
    provider: Provider,
    generic_forward_provider_headers: bool,
) -> Vec<&'static str> {
    let mut headers: Vec<&'static str> = ALLOWED_UPSTREAM_HEADERS_BASE.to_vec();
    match provider {
        Provider::Anthropic => {
            headers.extend_from_slice(ALLOWED_UPSTREAM_HEADERS_ANTHROPIC);
        }
        Provider::OpenAi => {
            headers.extend_from_slice(ALLOWED_UPSTREAM_HEADERS_OPENAI);
        }
        Provider::Generic => {
            if generic_forward_provider_headers {
                headers.extend_from_slice(ALLOWED_UPSTREAM_HEADERS_ANTHROPIC);
                headers.extend_from_slice(ALLOWED_UPSTREAM_HEADERS_OPENAI);
            }
        }
    }
    headers
}

/// Filter headers to only include those allowed for the provider.
fn filter_headers_for_upstream(
    headers: &HeaderMap,
    builder: reqwest::RequestBuilder,
    provider: Provider,
) -> reqwest::RequestBuilder {
    let allowed = allowed_headers_for_provider(provider);
    filter_headers_by_allowlist(headers, builder, &allowed)
}

/// Filter headers with generic-provider forwarding options.
fn filter_headers_for_upstream_with_options(
    headers: &HeaderMap,
    builder: reqwest::RequestBuilder,
    provider: Provider,
    generic_forward_provider_headers: bool,
) -> reqwest::RequestBuilder {
    let allowed =
        allowed_headers_for_provider_with_options(provider, generic_forward_provider_headers);
    filter_headers_by_allowlist(headers, builder, &allowed)
}

fn filter_headers_by_allowlist(
    headers: &HeaderMap,
    builder: reqwest::RequestBuilder,
    allowed: &[&str],
) -> reqwest::RequestBuilder {
    let mut req = builder;
    for (name, value) in headers.iter() {
        let name_str = name.as_str();
        if allowed.contains(&name_str) {
            if let Ok(rn) = reqwest::header::HeaderName::from_bytes(name.as_str().as_bytes()) {
                if let Ok(rv) = reqwest::header::HeaderValue::from_bytes(value.as_bytes()) {
                    req = req.header(rn, rv);
                }
            }
        }
    }
    req
}

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
    // Extract the request path before consuming the body (needed for generic mode)
    let request_path = req
        .uri()
        .path_and_query()
        .map(|pq| pq.as_str().to_string())
        .unwrap_or_else(|| "/".to_string());

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

    // Parse request body as JSON
    let parse_result: Result<serde_json::Value, _> = serde_json::from_slice(&body);

    // Requests must be valid JSON so the proxy can anonymize before forwarding.
    let (anonymized_body, is_streaming) = match parse_result {
        Ok(mut body_json) => {
            let is_streaming = body_json
                .get("stream")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);

            // Anonymize the request based on provider
            {
                let mut anonymizer = state.anonymizer.lock().await;
                match state.provider {
                    Provider::Anthropic => {
                        anthropic::anonymize_request(&mut body_json, &mut anonymizer)
                    }
                    Provider::OpenAi => openai::anonymize_request(&mut body_json, &mut anonymizer),
                    Provider::Generic => {
                        generic::anonymize_request(&mut body_json, &mut anonymizer)
                    }
                }
            }

            let serialized = match serde_json::to_vec(&body_json) {
                Ok(b) => b,
                Err(e) => {
                    return (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        format!("Serialization error: {e}"),
                    )
                        .into_response();
                }
            };

            (serialized, is_streaming)
        }
        Err(e) => {
            return (StatusCode::BAD_REQUEST, format!("Invalid JSON: {e}")).into_response();
        }
    };

    // Build upstream request with provider-specific path
    let upstream_url = match state.provider {
        Provider::Anthropic => format!("{}/v1/messages", state.upstream),
        Provider::OpenAi => format!("{}/v1/chat/completions", state.upstream),
        Provider::Generic => {
            // Generic mode: preserve the original request path
            format!("{}{}", state.upstream, request_path)
        }
    };
    let mut upstream_req = state.client.post(&upstream_url);

    // Forward only allowlisted headers
    upstream_req = if state.generic_forward_provider_headers {
        filter_headers_for_upstream_with_options(&headers, upstream_req, state.provider, true)
    } else {
        filter_headers_for_upstream(&headers, upstream_req, state.provider)
    };

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

            // Restore tokens based on provider
            match state.provider {
                Provider::Anthropic => anthropic::restore_response(&mut resp_json, &mapping),
                Provider::OpenAi => openai::restore_response(&mut resp_json, &mapping),
                Provider::Generic => generic::restore_response(&mut resp_json, &mapping),
            }

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
    let provider = state.provider;

    // Read the SSE stream and process events
    let byte_stream = upstream_resp.bytes_stream();

    // Buffer for incomplete UTF-8 sequences split across TCP chunks
    let mut utf8_buf: Vec<u8> = Vec::new();
    // Buffer for incomplete SSE lines split across chunks
    let mut line_buf = String::new();
    // Once a buffer limit is exceeded, restoration state is unreliable; drop all
    // further content (fail closed) rather than risk passing tokens unrestored.
    let mut poisoned = false;

    let processed_stream = byte_stream.map(move |chunk_result| {
        match chunk_result {
            Ok(chunk) => {
                if poisoned {
                    return Ok::<_, reqwest::Error>(Bytes::new());
                }
                utf8_buf.extend_from_slice(&chunk);

                // Guard against unbounded buffer growth from upstream
                if utf8_buf.len() > MAX_SSE_BUFFER_SIZE {
                    eprintln!(
                        "Warning: SSE utf8_buf exceeded {} bytes, aborting stream (fail closed)",
                        MAX_SSE_BUFFER_SIZE
                    );
                    utf8_buf.clear();
                    line_buf.clear();
                    poisoned = true;
                    // SSE comment line: protocol-safe, ignored by event parsers.
                    return Ok::<_, reqwest::Error>(Bytes::from(
                        ": anon-pii proxy aborted stream (buffer limit exceeded)\n\n",
                    ));
                }

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
                        process_sse_line(&line, &mut token_buffer, &mut output, provider);
                    }
                }

                // Guard line_buf growth
                if line_buf.len() > MAX_SSE_BUFFER_SIZE {
                    eprintln!(
                        "Warning: SSE line_buf exceeded {} bytes, aborting stream (fail closed)",
                        MAX_SSE_BUFFER_SIZE
                    );
                    line_buf.clear();
                    utf8_buf.clear();
                    poisoned = true;
                    return Ok::<_, reqwest::Error>(Bytes::from(
                        ": anon-pii proxy aborted stream (buffer limit exceeded)\n\n",
                    ));
                }

                utf8_buf = remainder;

                Ok::<_, reqwest::Error>(Bytes::from(output))
            }
            Err(e) => Err(e),
        }
    });

    // Wrap stream with a total duration timeout to prevent indefinite connections.
    // When the deadline expires, the stream ends cleanly.
    let deadline = tokio::time::Instant::now() + SSE_STREAM_TIMEOUT;
    let timed_stream = processed_stream
        .take_while(move |_| std::future::ready(tokio::time::Instant::now() < deadline));

    let body = Body::from_stream(timed_stream);

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
    provider: Provider,
) {
    if let Some(data) = line
        .strip_prefix("data:")
        .map(|data| data.strip_prefix(' ').unwrap_or(data))
    {
        // Both Anthropic and OpenAI use data: [DONE] for termination
        if data == "[DONE]" {
            let remaining = token_buffer.flush();
            if !remaining.is_empty() {
                output.push_str(&format!("data: {remaining}\n\n"));
            }
            output.push_str("data: [DONE]\n\n");
            return;
        }

        // Extract text delta based on provider
        let extract_result = match provider {
            Provider::Anthropic => sse::extract_text_delta(data),
            Provider::OpenAi => sse::extract_text_delta_openai(data),
            Provider::Generic => {
                // Try OpenAI first (more common format), fall back to Anthropic
                sse::extract_text_delta_openai(data).or_else(|| sse::extract_text_delta(data))
            }
        };

        if let Some(text_content) = extract_result {
            let restored = token_buffer.feed(&text_content);
            if !restored.is_empty() {
                // Replace text delta based on provider
                let replace_result = match provider {
                    Provider::Anthropic => sse::replace_text_delta(data, &restored),
                    Provider::OpenAi => sse::replace_text_delta_openai(data, &restored),
                    Provider::Generic => {
                        // Try OpenAI first, fall back to Anthropic
                        sse::replace_text_delta_openai(data, &restored)
                            .or_else(|| sse::replace_text_delta(data, &restored))
                    }
                };

                if let Some(new_data) = replace_result {
                    output.push_str(&format!("data: {new_data}\n\n"));
                } else {
                    output.push_str(line);
                    output.push('\n');
                }
            }
        } else if provider == Provider::Generic {
            // Generic mode: restore tokens directly in the raw data line
            // This handles non-standard SSE formats from arbitrary LLM APIs
            let restored = token_buffer.feed(data);
            output.push_str(&format!("data: {restored}\n"));
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

/// Allowed passthrough path prefixes for Anthropic API.
const ALLOWED_PASSTHROUGH_PREFIXES_ANTHROPIC: &[&str] = &["/v1/"];

/// Allowed passthrough path prefixes for OpenAI API.
const ALLOWED_PASSTHROUGH_PREFIXES_OPENAI: &[&str] = &["/v1/"];

/// Default passthrough path prefixes for generic provider.
const ALLOWED_PASSTHROUGH_PREFIXES_GENERIC: &[&str] = &[];

/// Get allowed passthrough prefixes for a provider.
fn allowed_passthrough_prefixes_for_provider(provider: Provider) -> &'static [&'static str] {
    match provider {
        Provider::Anthropic => ALLOWED_PASSTHROUGH_PREFIXES_ANTHROPIC,
        Provider::OpenAi => ALLOWED_PASSTHROUGH_PREFIXES_OPENAI,
        Provider::Generic => ALLOWED_PASSTHROUGH_PREFIXES_GENERIC,
    }
}

fn path_contains_traversal(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    path.contains("..")
        || lower.contains("%2e%2e")
        || lower.contains("%2e.")
        || lower.contains(".%2e")
}

fn path_matches_prefix(path: &str, prefix: &str) -> bool {
    if prefix.ends_with('/') {
        return path.starts_with(prefix);
    }

    path == prefix
        || path
            .strip_prefix(prefix)
            .is_some_and(|rest| rest.starts_with('/'))
}

fn passthrough_path_allowed(state: &ProxyState, path: &str) -> bool {
    if state.provider == Provider::Generic {
        return state.unsafe_generic_allow_all_paths
            || state
                .generic_allowed_path_prefixes
                .iter()
                .any(|prefix| path_matches_prefix(path, prefix));
    }

    allowed_passthrough_prefixes_for_provider(state.provider)
        .iter()
        .any(|prefix| path_matches_prefix(path, prefix))
}

fn generic_method_requires_json_body(method: &axum::http::Method) -> bool {
    method == axum::http::Method::POST
        || method == axum::http::Method::PUT
        || method == axum::http::Method::PATCH
}

fn response_is_event_stream(headers: &HeaderMap<HeaderValue>) -> bool {
    headers
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(';').next())
        .map(|media_type| media_type.trim().eq_ignore_ascii_case("text/event-stream"))
        .unwrap_or(false)
}

async fn prepare_generic_passthrough_body(
    state: &Arc<ProxyState>,
    method: &axum::http::Method,
    body_bytes: &[u8],
) -> Result<Option<Vec<u8>>, Response> {
    if body_bytes.is_empty() {
        if generic_method_requires_json_body(method) {
            return Err((StatusCode::BAD_REQUEST, "Invalid JSON: empty body").into_response());
        }
        return Ok(None);
    }

    let mut body_json: serde_json::Value = serde_json::from_slice(body_bytes)
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("Invalid JSON: {e}")).into_response())?;

    {
        let mut anonymizer = state.anonymizer.lock().await;
        generic::anonymize_request(&mut body_json, &mut anonymizer);
    }

    let serialized = serde_json::to_vec(&body_json).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Serialization error: {e}"),
        )
            .into_response()
    })?;

    Ok(Some(serialized))
}

/// Passthrough handler for provider-specific fallback paths.
/// Rejects requests to unrecognized paths to prevent SSRF.
pub async fn passthrough(State(state): State<Arc<ProxyState>>, req: Request<Body>) -> Response {
    let method = req.method().clone();
    let path = req.uri().path().to_string();
    let upstream_path = req
        .uri()
        .path_and_query()
        .map(|pq: &axum::http::uri::PathAndQuery| pq.as_str().to_string())
        .unwrap_or_default();

    // Reject path traversal attempts
    if path_contains_traversal(&path) {
        return (
            StatusCode::BAD_REQUEST,
            "Bad request: path traversal not allowed",
        )
            .into_response();
    }

    // Reject paths that don't match known API prefixes for this provider
    if !passthrough_path_allowed(&state, &path) {
        return (StatusCode::FORBIDDEN, "Forbidden: unknown API path").into_response();
    }

    let headers: HeaderMap = req.headers().clone();

    let body_bytes = match axum::body::to_bytes(req.into_body(), 10 * 1024 * 1024).await {
        Ok(b) => b,
        Err(e) => {
            return (StatusCode::BAD_REQUEST, format!("Failed to read body: {e}")).into_response();
        }
    };

    let upstream_url = format!("{}{}", state.upstream, upstream_path);
    let provider = state.provider;

    let mut upstream_req = state.client.request(
        reqwest::Method::from_bytes(method.as_str().as_bytes()).unwrap_or(reqwest::Method::GET),
        &upstream_url,
    );

    // Forward only allowlisted headers
    upstream_req = if state.generic_forward_provider_headers {
        filter_headers_for_upstream_with_options(&headers, upstream_req, state.provider, true)
    } else {
        filter_headers_for_upstream(&headers, upstream_req, state.provider)
    };

    if provider == Provider::Generic {
        let body = match prepare_generic_passthrough_body(&state, &method, &body_bytes).await {
            Ok(prepared) => prepared,
            Err(response) => return response,
        };
        if let Some(body) = body {
            upstream_req = upstream_req.body(body);
        }
    } else if !body_bytes.is_empty() {
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

    if provider == Provider::Generic {
        if status.is_success() && response_is_event_stream(&resp_headers) {
            return handle_streaming(state, upstream_resp, status, resp_headers).await;
        }
        return handle_non_streaming(state, upstream_resp, status, resp_headers).await;
    }

    let resp_body = upstream_resp.bytes().await.unwrap_or_default();

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
    use std::sync::atomic::{AtomicUsize, Ordering};

    async fn spawn_counting_upstream(
        calls: Arc<AtomicUsize>,
        captured_body: Arc<tokio::sync::Mutex<Vec<u8>>>,
    ) -> String {
        spawn_recording_upstream(
            calls,
            captured_body,
            Arc::new(tokio::sync::Mutex::new(None)),
        )
        .await
    }

    async fn spawn_recording_upstream(
        calls: Arc<AtomicUsize>,
        captured_body: Arc<tokio::sync::Mutex<Vec<u8>>>,
        captured_method: Arc<tokio::sync::Mutex<Option<String>>>,
    ) -> String {
        let app = axum::Router::new().fallback(axum::routing::any(
            move |method: axum::http::Method, body: Bytes| {
                let calls = Arc::clone(&calls);
                let captured_body = Arc::clone(&captured_body);
                let captured_method = Arc::clone(&captured_method);
                async move {
                    calls.fetch_add(1, Ordering::SeqCst);
                    *captured_method.lock().await = Some(method.as_str().to_string());
                    *captured_body.lock().await = body.to_vec();
                    (StatusCode::OK, r#"{"message":"ok"}"#)
                }
            },
        ));

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        format!("http://{addr}")
    }

    async fn spawn_hanging_sse_upstream(calls: Arc<AtomicUsize>) -> String {
        let app = axum::Router::new().fallback(axum::routing::any(move || {
            let calls = Arc::clone(&calls);
            async move {
                calls.fetch_add(1, Ordering::SeqCst);

                let stream = futures::stream::once(async {
                    Ok::<Bytes, std::convert::Infallible>(Bytes::from_static(
                        b"data: {\"message\":\"hello\"}\n\n",
                    ))
                })
                .chain(futures::stream::pending::<
                    Result<Bytes, std::convert::Infallible>,
                >());

                Response::builder()
                    .status(StatusCode::OK)
                    .header(axum::http::header::CONTENT_TYPE, "text/event-stream")
                    .body(Body::from_stream(stream))
                    .unwrap()
            }
        }));

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        format!("http://{addr}")
    }

    #[test]
    fn test_allowed_upstream_headers_allowlist() {
        // Verify that sensitive headers are NOT in any provider's allowlist
        let sensitive = [
            "cookie",
            "set-cookie",
            "proxy-authorization",
            "x-forwarded-for",
            "x-real-ip",
            "x-forwarded-host",
            "forwarded",
            "referer",
        ];
        for provider in [Provider::Anthropic, Provider::OpenAi, Provider::Generic] {
            let allowed = allowed_headers_for_provider(provider);
            for h in &sensitive {
                assert!(
                    !allowed.contains(h),
                    "Sensitive header '{h}' must not be in the {provider} allowlist"
                );
            }
        }
    }

    #[test]
    fn test_filter_headers_drops_sensitive() {
        let client = reqwest::Client::new();
        let mut headers = HeaderMap::new();
        // Allowed for Anthropic
        headers.insert("x-api-key", HeaderValue::from_static("sk-test"));
        headers.insert("content-type", HeaderValue::from_static("application/json"));
        headers.insert("anthropic-version", HeaderValue::from_static("2024-01-01"));
        // Sensitive — must be dropped
        headers.insert("cookie", HeaderValue::from_static("session=secret"));
        headers.insert("x-forwarded-for", HeaderValue::from_static("10.0.0.1"));
        headers.insert("proxy-authorization", HeaderValue::from_static("Basic abc"));
        headers.insert("referer", HeaderValue::from_static("http://internal.corp"));

        let builder = client.post("http://localhost/test");
        let filtered = filter_headers_for_upstream(&headers, builder, Provider::Anthropic);

        // Build the request to inspect headers
        let req = filtered.build().unwrap();
        let fwd_headers = req.headers();

        // Allowed headers are present
        assert_eq!(fwd_headers.get("x-api-key").unwrap(), "sk-test");
        assert_eq!(fwd_headers.get("content-type").unwrap(), "application/json");
        assert_eq!(fwd_headers.get("anthropic-version").unwrap(), "2024-01-01");

        // Sensitive headers are absent
        assert!(
            fwd_headers.get("cookie").is_none(),
            "cookie must be dropped"
        );
        assert!(
            fwd_headers.get("x-forwarded-for").is_none(),
            "x-forwarded-for must be dropped"
        );
        assert!(
            fwd_headers.get("proxy-authorization").is_none(),
            "proxy-authorization must be dropped"
        );
        assert!(
            fwd_headers.get("referer").is_none(),
            "referer must be dropped"
        );
    }

    #[tokio::test]
    async fn test_handle_messages_rejects_oversized_body() {
        let state = Arc::new(ProxyState::new(
            "http://localhost:0".to_string(),
            0.0,
            std::env::temp_dir().join("anon-test-handler"),
            Provider::Anthropic,
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
        assert!(
            text.contains("byte limit"),
            "Response should mention the limit: {text}"
        );
    }

    #[test]
    fn test_sse_constants_are_bounded() {
        assert!(
            SSE_STREAM_TIMEOUT.as_secs() <= 900,
            "SSE timeout should not exceed 15 minutes"
        );
        assert!(
            MAX_SSE_BUFFER_SIZE <= 10 * 1024 * 1024,
            "SSE buffer limit should not exceed 10MB"
        );
    }

    #[tokio::test]
    async fn test_passthrough_rejects_path_traversal() {
        let state = Arc::new(ProxyState::new(
            "http://localhost:0".to_string(),
            0.0,
            std::env::temp_dir().join("anon-test-traversal"),
            Provider::Anthropic,
        ));

        let req = Request::builder()
            .method("GET")
            .uri("/v1/../../internal/admin")
            .body(Body::empty())
            .unwrap();

        let resp = passthrough(State(state), req).await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

        let body = to_bytes(resp.into_body(), 1024).await.unwrap();
        let text = String::from_utf8_lossy(&body);
        assert!(
            text.contains("path traversal"),
            "Response should mention path traversal: {text}"
        );
    }

    #[tokio::test]
    async fn test_passthrough_allows_valid_v1_path() {
        let state = Arc::new(ProxyState::new(
            "http://localhost:0".to_string(),
            0.0,
            std::env::temp_dir().join("anon-test-traversal-ok"),
            Provider::Anthropic,
        ));

        let req = Request::builder()
            .method("GET")
            .uri("/v1/models")
            .body(Body::empty())
            .unwrap();

        let resp = passthrough(State(state), req).await;
        // Should NOT be 400 (traversal) or 403 (forbidden) — will be 502 (upstream unreachable)
        assert_ne!(resp.status(), StatusCode::BAD_REQUEST);
        assert_ne!(resp.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn test_passthrough_rejects_encoded_traversal() {
        let state = Arc::new(ProxyState::new(
            "http://localhost:0".to_string(),
            0.0,
            std::env::temp_dir().join("anon-test-traversal-enc"),
            Provider::Anthropic,
        ));

        // Even with valid prefix, .. in query or later segments should be blocked
        let req = Request::builder()
            .method("GET")
            .uri("/v1/../v1/../../etc/passwd")
            .body(Body::empty())
            .unwrap();

        let resp = passthrough(State(state), req).await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_generic_passthrough_rejects_unknown_path_without_upstream_call() {
        let calls = Arc::new(AtomicUsize::new(0));
        let captured_body = Arc::new(tokio::sync::Mutex::new(Vec::new()));
        let upstream =
            spawn_counting_upstream(Arc::clone(&calls), Arc::clone(&captured_body)).await;

        let state = Arc::new(ProxyState::new(
            upstream,
            0.0,
            std::env::temp_dir().join("anon-test-generic-unknown-path"),
            Provider::Generic,
        ));

        let req = Request::builder()
            .method("POST")
            .uri("/api/generate")
            .body(Body::from(r#"{"prompt":"Contact john@example.com"}"#))
            .unwrap();

        let resp = passthrough(State(state), req).await;

        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        assert_eq!(
            calls.load(Ordering::SeqCst),
            0,
            "Rejected generic fallback path must not be forwarded upstream"
        );
        assert!(captured_body.lock().await.is_empty());
    }

    #[tokio::test]
    async fn test_generic_passthrough_allows_configured_path_prefix() {
        let calls = Arc::new(AtomicUsize::new(0));
        let captured_body = Arc::new(tokio::sync::Mutex::new(Vec::new()));
        let upstream =
            spawn_counting_upstream(Arc::clone(&calls), Arc::clone(&captured_body)).await;

        let state = Arc::new(
            ProxyState::new(
                upstream,
                0.0,
                std::env::temp_dir().join("anon-test-generic-configured-path"),
                Provider::Generic,
            )
            .with_generic_allowed_path_prefixes(["/api/"])
            .unwrap(),
        );

        let req = Request::builder()
            .method("POST")
            .uri("/api/generate")
            .body(Body::from(r#"{"prompt":"Contact john@example.com"}"#))
            .unwrap();

        let resp = passthrough(State(state), req).await;

        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn test_generic_passthrough_prefix_does_not_match_neighbor_path() {
        let calls = Arc::new(AtomicUsize::new(0));
        let captured_body = Arc::new(tokio::sync::Mutex::new(Vec::new()));
        let upstream =
            spawn_counting_upstream(Arc::clone(&calls), Arc::clone(&captured_body)).await;

        let state = Arc::new(
            ProxyState::new(
                upstream,
                0.0,
                std::env::temp_dir().join("anon-test-generic-prefix-neighbor"),
                Provider::Generic,
            )
            .with_generic_allowed_path_prefixes(["/api"])
            .unwrap(),
        );

        let req = Request::builder()
            .method("POST")
            .uri("/api2/generate")
            .body(Body::from(r#"{"prompt":"Contact john@example.com"}"#))
            .unwrap();

        let resp = passthrough(State(state), req).await;

        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert!(captured_body.lock().await.is_empty());
    }

    #[tokio::test]
    async fn test_generic_passthrough_configured_path_still_rejects_traversal() {
        let calls = Arc::new(AtomicUsize::new(0));
        let captured_body = Arc::new(tokio::sync::Mutex::new(Vec::new()));
        let upstream =
            spawn_counting_upstream(Arc::clone(&calls), Arc::clone(&captured_body)).await;

        let state = Arc::new(
            ProxyState::new(
                upstream,
                0.0,
                std::env::temp_dir().join("anon-test-generic-configured-traversal"),
                Provider::Generic,
            )
            .with_generic_allowed_path_prefixes(["/api/"])
            .unwrap(),
        );

        let req = Request::builder()
            .method("GET")
            .uri("/api/../admin")
            .body(Body::empty())
            .unwrap();

        let resp = passthrough(State(state), req).await;

        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert!(captured_body.lock().await.is_empty());
    }

    #[tokio::test]
    async fn test_generic_passthrough_allows_dot_segments_in_query() {
        let calls = Arc::new(AtomicUsize::new(0));
        let captured_body = Arc::new(tokio::sync::Mutex::new(Vec::new()));
        let upstream =
            spawn_counting_upstream(Arc::clone(&calls), Arc::clone(&captured_body)).await;

        let state = Arc::new(
            ProxyState::new(
                upstream,
                0.0,
                std::env::temp_dir().join("anon-test-generic-query-dot-segments"),
                Provider::Generic,
            )
            .with_generic_allowed_path_prefixes(["/api/"])
            .unwrap(),
        );

        let req = Request::builder()
            .method("POST")
            .uri("/api/generate?prompt=%2e%2e")
            .body(Body::from(r#"{"prompt":"Contact john@example.com"}"#))
            .unwrap();

        let resp = passthrough(State(state), req).await;

        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn test_generic_passthrough_unsafe_allows_all_paths() {
        let calls = Arc::new(AtomicUsize::new(0));
        let captured_body = Arc::new(tokio::sync::Mutex::new(Vec::new()));
        let upstream =
            spawn_counting_upstream(Arc::clone(&calls), Arc::clone(&captured_body)).await;

        let state = Arc::new(
            ProxyState::new(
                upstream,
                0.0,
                std::env::temp_dir().join("anon-test-generic-unsafe-all-paths"),
                Provider::Generic,
            )
            .with_unsafe_generic_allow_all_paths(true),
        );

        let req = Request::builder()
            .method("POST")
            .uri("/internal/admin")
            .body(Body::from(r#"{"prompt":"Contact john@example.com"}"#))
            .unwrap();

        let resp = passthrough(State(state), req).await;

        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn test_handle_messages_accepts_valid_sized_body() {
        let state = Arc::new(ProxyState::new(
            "http://localhost:0".to_string(),
            0.0,
            std::env::temp_dir().join("anon-test-handler"),
            Provider::Anthropic,
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

    #[test]
    fn test_allowed_headers_for_anthropic_provider() {
        let headers = allowed_headers_for_provider(Provider::Anthropic);
        assert!(headers.contains(&"x-api-key"));
        assert!(headers.contains(&"anthropic-version"));
        assert!(headers.contains(&"anthropic-beta"));
        assert!(headers.contains(&"authorization"));
        assert!(headers.contains(&"content-type"));
        // Should NOT contain OpenAI-specific headers
        assert!(!headers.contains(&"openai-organization"));
        assert!(!headers.contains(&"openai-project"));
    }

    #[test]
    fn test_allowed_headers_for_openai_provider() {
        let headers = allowed_headers_for_provider(Provider::OpenAi);
        assert!(headers.contains(&"openai-organization"));
        assert!(headers.contains(&"openai-project"));
        assert!(headers.contains(&"authorization"));
        assert!(headers.contains(&"content-type"));
        // Should NOT contain Anthropic-specific headers
        assert!(!headers.contains(&"x-api-key"));
        assert!(!headers.contains(&"anthropic-version"));
    }

    #[test]
    fn test_allowed_headers_for_generic_provider() {
        let headers = allowed_headers_for_provider(Provider::Generic);
        assert!(!headers.contains(&"x-api-key"));
        assert!(!headers.contains(&"anthropic-version"));
        assert!(!headers.contains(&"anthropic-beta"));
        assert!(!headers.contains(&"openai-organization"));
        assert!(!headers.contains(&"openai-project"));
        assert!(headers.contains(&"authorization"));
    }

    #[test]
    fn test_allowed_headers_for_generic_provider_with_explicit_provider_headers() {
        let headers = allowed_headers_for_provider_with_options(Provider::Generic, true);
        assert!(headers.contains(&"x-api-key"));
        assert!(headers.contains(&"anthropic-version"));
        assert!(headers.contains(&"anthropic-beta"));
        assert!(headers.contains(&"openai-organization"));
        assert!(headers.contains(&"openai-project"));
        assert!(headers.contains(&"authorization"));
    }

    #[test]
    fn test_passthrough_prefixes_for_anthropic() {
        let prefixes = allowed_passthrough_prefixes_for_provider(Provider::Anthropic);
        assert!(prefixes.contains(&"/v1/"));
    }

    #[test]
    fn test_passthrough_prefixes_for_openai() {
        let prefixes = allowed_passthrough_prefixes_for_provider(Provider::OpenAi);
        assert!(prefixes.contains(&"/v1/"));
    }

    #[test]
    fn test_passthrough_prefixes_for_generic() {
        let prefixes = allowed_passthrough_prefixes_for_provider(Provider::Generic);
        assert!(prefixes.is_empty());
    }

    // ============================================================================
    // PROCESS_SSE_LINE PROVIDER-AWARE TESTS
    // ============================================================================

    #[test]
    fn test_process_sse_line_anthropic_text_delta() {
        let mut mapping = crate::mapping::Mapping::new();
        mapping.mappings.insert(
            "[EMAIL_ADDRESS_a1b2c3d4]".to_string(),
            "john@example.com".to_string(),
        );
        mapping.rebuild_caches();
        let mut token_buffer = sse::TokenBuffer::new(mapping);
        let mut output = String::new();

        let line = r#"data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"[EMAIL_ADDRESS_a1b2c3d4]"}}"#;
        process_sse_line(line, &mut token_buffer, &mut output, Provider::Anthropic);

        assert!(
            output.contains("john@example.com"),
            "Anthropic: email should be restored, got: {output}"
        );
        assert!(
            !output.contains("[EMAIL_ADDRESS_"),
            "Anthropic: token should not appear"
        );
    }

    #[test]
    fn test_process_sse_line_openai_text_delta() {
        let mut mapping = crate::mapping::Mapping::new();
        mapping.mappings.insert(
            "[EMAIL_ADDRESS_a1b2c3d4]".to_string(),
            "john@example.com".to_string(),
        );
        mapping.rebuild_caches();
        let mut token_buffer = sse::TokenBuffer::new(mapping);
        let mut output = String::new();

        let line = r#"data: {"id":"chatcmpl-abc","choices":[{"index":0,"delta":{"content":"[EMAIL_ADDRESS_a1b2c3d4]"},"finish_reason":null}]}"#;
        process_sse_line(line, &mut token_buffer, &mut output, Provider::OpenAi);

        assert!(
            output.contains("john@example.com"),
            "OpenAI: email should be restored, got: {output}"
        );
        assert!(
            !output.contains("[EMAIL_ADDRESS_"),
            "OpenAI: token should not appear"
        );
    }

    #[test]
    fn test_process_sse_line_openai_tool_calls() {
        let mut mapping = crate::mapping::Mapping::new();
        mapping.mappings.insert(
            "[EMAIL_ADDRESS_abcd1234]".to_string(),
            "admin@secret.org".to_string(),
        );
        mapping.rebuild_caches();
        let mut token_buffer = sse::TokenBuffer::new(mapping);
        let mut output = String::new();

        let line = r#"data: {"id":"chatcmpl-abc","choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"function":{"arguments":"[EMAIL_ADDRESS_abcd1234]"}}]},"finish_reason":null}]}"#;
        process_sse_line(line, &mut token_buffer, &mut output, Provider::OpenAi);

        assert!(
            output.contains("admin@secret.org"),
            "OpenAI tool call: email should be restored, got: {output}"
        );
    }

    #[test]
    fn test_process_sse_line_done_flushes_buffer() {
        let mut mapping = crate::mapping::Mapping::new();
        mapping.mappings.insert(
            "[EMAIL_ADDRESS_a1b2c3d4]".to_string(),
            "test@example.com".to_string(),
        );
        mapping.rebuild_caches();
        let mut token_buffer = sse::TokenBuffer::new(mapping);
        let mut output = String::new();

        // Both OpenAI and Anthropic use data: [DONE] for termination
        process_sse_line(
            "data: [DONE]",
            &mut token_buffer,
            &mut output,
            Provider::OpenAi,
        );

        assert!(
            output.contains("data: [DONE]"),
            "DONE should be forwarded, got: {output}"
        );
    }

    #[test]
    fn test_process_sse_line_generic_detects_openai_format() {
        let mut mapping = crate::mapping::Mapping::new();
        mapping.mappings.insert(
            "[IP_ADDRESS_12345678]".to_string(),
            "192.168.1.100".to_string(),
        );
        mapping.rebuild_caches();
        let mut token_buffer = sse::TokenBuffer::new(mapping);
        let mut output = String::new();

        // OpenAI-style SSE event should be processed correctly in generic mode
        let line = r#"data: {"id":"chatcmpl-abc","choices":[{"index":0,"delta":{"content":"Server at [IP_ADDRESS_12345678]"},"finish_reason":null}]}"#;
        process_sse_line(line, &mut token_buffer, &mut output, Provider::Generic);

        assert!(
            output.contains("192.168.1.100"),
            "Generic (OpenAI format): IP should be restored, got: {output}"
        );
    }

    #[test]
    fn test_process_sse_line_generic_detects_anthropic_format() {
        let mut mapping = crate::mapping::Mapping::new();
        mapping
            .mappings
            .insert("[IP_ADDRESS_12345678]".to_string(), "10.0.0.42".to_string());
        mapping.rebuild_caches();
        let mut token_buffer = sse::TokenBuffer::new(mapping);
        let mut output = String::new();

        // Anthropic-style SSE event should be processed correctly in generic mode
        let line = r#"data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"IP is [IP_ADDRESS_12345678]"}}"#;
        process_sse_line(line, &mut token_buffer, &mut output, Provider::Generic);

        assert!(
            output.contains("10.0.0.42"),
            "Generic (Anthropic format): IP should be restored, got: {output}"
        );
    }

    // ============================================================================
    // GENERIC PROVIDER WHOLE-BODY ANONYMIZATION TESTS
    // ============================================================================

    /// Test that generic provider anonymizes the full request JSON body via anonymize_json_value()
    #[test]
    fn test_generic_anonymize_request_whole_body() {
        let mut anonymizer = crate::detection::Anonymizer::new(0.0);
        let mut body = serde_json::json!({
            "prompt": "My email is john@example.com",
            "config": {
                "user_ip": "192.168.1.100",
                "nested": {
                    "phone": "+33 6 12 34 56 78"
                }
            },
            "metadata": {
                "source": "Server at 10.0.0.42"
            }
        });

        generic::anonymize_request(&mut body, &mut anonymizer);

        // Email in prompt should be anonymized
        let prompt = body["prompt"].as_str().unwrap();
        assert!(
            prompt.contains("[EMAIL_ADDRESS_"),
            "Email in prompt should be anonymized, got: {prompt}"
        );
        assert!(
            !prompt.contains("john@example.com"),
            "Original email should not appear"
        );

        // IP in nested config should be anonymized
        let user_ip = body["config"]["user_ip"].as_str().unwrap();
        assert!(
            user_ip.contains("[IP_ADDRESS_"),
            "IP should be anonymized, got: {user_ip}"
        );

        // Phone in deeply nested object should be anonymized
        let phone = body["config"]["nested"]["phone"].as_str().unwrap();
        assert!(
            phone.contains("[FR_PHONE_NUMBER_") || phone.contains("[PHONE_NUMBER_"),
            "Phone should be anonymized, got: {phone}"
        );

        // IP in metadata should be anonymized
        let source = body["metadata"]["source"].as_str().unwrap();
        assert!(
            source.contains("[IP_ADDRESS_"),
            "IP in metadata should be anonymized, got: {source}"
        );
    }

    /// Test that generic provider restores tokens in the full response body
    #[test]
    fn test_generic_restore_response_whole_body() {
        let mut mapping = crate::mapping::Mapping::new();
        mapping.mappings.insert(
            "[EMAIL_ADDRESS_a1b2c3d4]".to_string(),
            "john@example.com".to_string(),
        );
        mapping.mappings.insert(
            "[IP_ADDRESS_12345678]".to_string(),
            "192.168.1.100".to_string(),
        );
        mapping.rebuild_caches();

        let mut response = serde_json::json!({
            "result": "User [EMAIL_ADDRESS_a1b2c3d4] connected from [IP_ADDRESS_12345678]",
            "data": {
                "email": "[EMAIL_ADDRESS_a1b2c3d4]",
                "nested": {
                    "ip": "[IP_ADDRESS_12345678]"
                }
            }
        });

        generic::restore_response(&mut response, &mapping);

        // All tokens should be restored
        let result = response["result"].as_str().unwrap();
        assert!(
            result.contains("john@example.com"),
            "Email should be restored in result, got: {result}"
        );
        assert!(
            result.contains("192.168.1.100"),
            "IP should be restored in result, got: {result}"
        );

        let email = response["data"]["email"].as_str().unwrap();
        assert!(
            email.contains("john@example.com"),
            "Email should be restored in data.email, got: {email}"
        );

        let ip = response["data"]["nested"]["ip"].as_str().unwrap();
        assert!(
            ip.contains("192.168.1.100"),
            "IP should be restored in data.nested.ip, got: {ip}"
        );
    }

    /// Test that generic SSE streaming restores tokens in data lines (line-by-line)
    #[test]
    fn test_generic_sse_line_restores_tokens_in_any_data_line() {
        let mut mapping = crate::mapping::Mapping::new();
        mapping.mappings.insert(
            "[EMAIL_ADDRESS_abcd1234]".to_string(),
            "admin@secret.org".to_string(),
        );
        mapping.rebuild_caches();
        let mut token_buffer = sse::TokenBuffer::new(mapping);
        let mut output = String::new();

        // Non-standard SSE format (not OpenAI or Anthropic) — generic should still restore
        let line = r#"data: {"text": "[EMAIL_ADDRESS_abcd1234] is the user"}"#;
        process_sse_line(line, &mut token_buffer, &mut output, Provider::Generic);

        // Generic mode should restore tokens in any data: line
        assert!(
            output.contains("admin@secret.org"),
            "Generic SSE: token should be restored in any data line, got: {output}"
        );
    }

    /// Test that generic SSE restores tokens when data: has no following space
    #[test]
    fn test_generic_sse_line_restores_tokens_without_space_after_colon() {
        let mut mapping = crate::mapping::Mapping::new();
        mapping.mappings.insert(
            "[EMAIL_ADDRESS_nospace1]".to_string(),
            "admin@secret.org".to_string(),
        );
        mapping.rebuild_caches();
        let mut token_buffer = sse::TokenBuffer::new(mapping);
        let mut output = String::new();

        let line = r#"data:{"text":"[EMAIL_ADDRESS_nospace1] is the user"}"#;
        process_sse_line(line, &mut token_buffer, &mut output, Provider::Generic);

        assert!(
            output.contains("admin@secret.org"),
            "Generic SSE without space after data: should restore tokens, got: {output}"
        );
    }

    /// Test that arrays in generic request body are anonymized
    #[test]
    fn test_generic_anonymize_request_arrays() {
        let mut anonymizer = crate::detection::Anonymizer::new(0.0);
        let mut body = serde_json::json!({
            "emails": ["john@example.com", "jane@test.org"],
            "records": [
                {"ip": "192.168.1.1"},
                {"ip": "10.0.0.42"}
            ]
        });

        generic::anonymize_request(&mut body, &mut anonymizer);

        // Array elements should be anonymized
        let email0 = body["emails"][0].as_str().unwrap();
        assert!(
            email0.contains("[EMAIL_ADDRESS_"),
            "First email in array should be anonymized, got: {email0}"
        );

        let email1 = body["emails"][1].as_str().unwrap();
        assert!(
            email1.contains("[EMAIL_ADDRESS_"),
            "Second email in array should be anonymized, got: {email1}"
        );

        // Nested objects in arrays should be anonymized
        let ip0 = body["records"][0]["ip"].as_str().unwrap();
        assert!(
            ip0.contains("[IP_ADDRESS_"),
            "IP in first record should be anonymized, got: {ip0}"
        );

        let ip1 = body["records"][1]["ip"].as_str().unwrap();
        assert!(
            ip1.contains("[IP_ADDRESS_"),
            "IP in second record should be anonymized, got: {ip1}"
        );
    }

    /// Test that generic provider preserves non-string values
    #[test]
    fn test_generic_anonymize_preserves_non_strings() {
        let mut anonymizer = crate::detection::Anonymizer::new(0.0);
        let mut body = serde_json::json!({
            "count": 42,
            "enabled": true,
            "ratio": 3.14,
            "nothing": null,
            "text": "Contact john@example.com"
        });

        generic::anonymize_request(&mut body, &mut anonymizer);

        // Non-string values should be preserved
        assert_eq!(body["count"], 42);
        assert_eq!(body["enabled"], true);
        assert_eq!(body["ratio"], 3.14);
        assert!(body["nothing"].is_null());

        // String should be anonymized
        let text = body["text"].as_str().unwrap();
        assert!(text.contains("[EMAIL_ADDRESS_"));
    }

    /// Test that generic mode rejects non-JSON request bodies
    #[tokio::test]
    async fn test_generic_non_json_rejected() {
        let state = Arc::new(ProxyState::new(
            "http://localhost:0".to_string(),
            0.0,
            std::env::temp_dir().join("anon-test-generic-non-json"),
            Provider::Generic,
        ));

        // Non-JSON body (plain text)
        let body = b"This is plain text with john@example.com";
        let req = Request::builder()
            .method("POST")
            .uri("/v1/generate")
            .body(Body::from(body.to_vec()))
            .unwrap();

        let resp = handle_messages(State(state), HeaderMap::new(), req).await;

        assert_eq!(
            resp.status(),
            StatusCode::BAD_REQUEST,
            "Generic mode should reject non-JSON bodies"
        );
    }

    /// Test that rejected generic non-JSON bodies are not forwarded upstream
    #[tokio::test]
    async fn test_generic_non_json_rejected_without_upstream_call() {
        let calls = Arc::new(AtomicUsize::new(0));
        let captured_body = Arc::new(tokio::sync::Mutex::new(Vec::new()));
        let upstream =
            spawn_counting_upstream(Arc::clone(&calls), Arc::clone(&captured_body)).await;

        let state = Arc::new(ProxyState::new(
            upstream,
            0.0,
            std::env::temp_dir().join("anon-test-generic-non-json-not-forwarded"),
            Provider::Generic,
        ));

        let req = Request::builder()
            .method("POST")
            .uri("/v1/generate")
            .body(Body::from("plain text with john@example.com"))
            .unwrap();

        let resp = handle_messages(State(state), HeaderMap::new(), req).await;

        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            calls.load(Ordering::SeqCst),
            0,
            "Rejected generic request must not be forwarded upstream"
        );
        assert!(captured_body.lock().await.is_empty());
    }

    /// Test that valid generic JSON is still anonymized before forwarding
    #[tokio::test]
    async fn test_generic_json_forwarded_anonymized() {
        let calls = Arc::new(AtomicUsize::new(0));
        let captured_body = Arc::new(tokio::sync::Mutex::new(Vec::new()));
        let upstream =
            spawn_counting_upstream(Arc::clone(&calls), Arc::clone(&captured_body)).await;

        let state = Arc::new(ProxyState::new(
            upstream,
            0.0,
            std::env::temp_dir().join("anon-test-generic-json-anonymized"),
            Provider::Generic,
        ));

        let req = Request::builder()
            .method("POST")
            .uri("/v1/generate")
            .body(Body::from(
                r#"{"prompt":"Contact john@example.com","stream":false}"#,
            ))
            .unwrap();

        let resp = handle_messages(State(state), HeaderMap::new(), req).await;

        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(calls.load(Ordering::SeqCst), 1);

        let forwarded_body = captured_body.lock().await.clone();
        let forwarded_json: serde_json::Value = serde_json::from_slice(&forwarded_body).unwrap();
        let prompt = forwarded_json["prompt"].as_str().unwrap();
        assert!(
            prompt.contains("[EMAIL_ADDRESS_"),
            "Generic JSON should anonymize before forwarding, got: {prompt}"
        );
        assert!(
            !prompt.contains("john@example.com"),
            "Generic JSON forwarded original PII"
        );
    }

    /// Test that generic fallback paths also reject non-JSON bodies
    #[tokio::test]
    async fn test_generic_passthrough_non_json_rejected_without_upstream_call() {
        let calls = Arc::new(AtomicUsize::new(0));
        let captured_body = Arc::new(tokio::sync::Mutex::new(Vec::new()));
        let upstream =
            spawn_counting_upstream(Arc::clone(&calls), Arc::clone(&captured_body)).await;

        let state = Arc::new(
            ProxyState::new(
                upstream,
                0.0,
                std::env::temp_dir().join("anon-test-generic-passthrough-non-json"),
                Provider::Generic,
            )
            .with_generic_allowed_path_prefixes(["/api/"])
            .unwrap(),
        );

        let req = Request::builder()
            .method("POST")
            .uri("/api/generate")
            .body(Body::from("plain text with john@example.com"))
            .unwrap();

        let resp = passthrough(State(state), req).await;

        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            calls.load(Ordering::SeqCst),
            0,
            "Rejected generic fallback request must not be forwarded upstream"
        );
        assert!(captured_body.lock().await.is_empty());
    }

    /// Test that generic fallback paths anonymize valid JSON before forwarding
    #[tokio::test]
    async fn test_generic_passthrough_json_forwarded_anonymized() {
        let calls = Arc::new(AtomicUsize::new(0));
        let captured_body = Arc::new(tokio::sync::Mutex::new(Vec::new()));
        let captured_method = Arc::new(tokio::sync::Mutex::new(None));
        let upstream = spawn_recording_upstream(
            Arc::clone(&calls),
            Arc::clone(&captured_body),
            Arc::clone(&captured_method),
        )
        .await;

        let state = Arc::new(
            ProxyState::new(
                upstream,
                0.0,
                std::env::temp_dir().join("anon-test-generic-passthrough-json"),
                Provider::Generic,
            )
            .with_generic_allowed_path_prefixes(["/api/"])
            .unwrap(),
        );

        let req = Request::builder()
            .method("PATCH")
            .uri("/api/generate")
            .body(Body::from(r#"{"prompt":"Contact john@example.com"}"#))
            .unwrap();

        let resp = passthrough(State(state), req).await;

        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(captured_method.lock().await.as_deref(), Some("PATCH"));

        let forwarded_body = captured_body.lock().await.clone();
        let forwarded_json: serde_json::Value = serde_json::from_slice(&forwarded_body).unwrap();
        let prompt = forwarded_json["prompt"].as_str().unwrap();
        assert!(
            prompt.contains("[EMAIL_ADDRESS_"),
            "Generic fallback JSON should anonymize before forwarding, got: {prompt}"
        );
        assert!(
            !prompt.contains("john@example.com"),
            "Generic fallback forwarded original PII"
        );
    }

    /// Test that generic fallback paths preserve empty-body methods
    #[tokio::test]
    async fn test_generic_passthrough_get_empty_body_preserves_method() {
        let calls = Arc::new(AtomicUsize::new(0));
        let captured_body = Arc::new(tokio::sync::Mutex::new(Vec::new()));
        let captured_method = Arc::new(tokio::sync::Mutex::new(None));
        let upstream = spawn_recording_upstream(
            Arc::clone(&calls),
            Arc::clone(&captured_body),
            Arc::clone(&captured_method),
        )
        .await;

        let state = Arc::new(
            ProxyState::new(
                upstream,
                0.0,
                std::env::temp_dir().join("anon-test-generic-passthrough-get"),
                Provider::Generic,
            )
            .with_generic_allowed_path_prefixes(["/api/"])
            .unwrap(),
        );

        let req = Request::builder()
            .method("GET")
            .uri("/api/tags")
            .body(Body::empty())
            .unwrap();

        let resp = passthrough(State(state), req).await;

        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(captured_method.lock().await.as_deref(), Some("GET"));
        assert!(captured_body.lock().await.is_empty());
    }

    /// Test that generic fallback detects SSE from response headers
    #[tokio::test]
    async fn test_generic_passthrough_get_sse_response_detected_from_headers() {
        let calls = Arc::new(AtomicUsize::new(0));
        let upstream = spawn_hanging_sse_upstream(Arc::clone(&calls)).await;

        let state = Arc::new(
            ProxyState::new(
                upstream,
                0.0,
                std::env::temp_dir().join("anon-test-generic-passthrough-get-sse"),
                Provider::Generic,
            )
            .with_generic_allowed_path_prefixes(["/api/"])
            .unwrap(),
        );

        let req = Request::builder()
            .method("GET")
            .uri("/api/events")
            .body(Body::empty())
            .unwrap();

        let resp = tokio::time::timeout(
            std::time::Duration::from_millis(500),
            passthrough(State(state), req),
        )
        .await
        .expect("SSE passthrough should return headers without waiting for EOF");

        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(
            resp.headers()
                .get(axum::http::header::CONTENT_TYPE)
                .unwrap(),
            "text/event-stream"
        );
    }

    /// Test that generic fallback payload methods still reject empty bodies
    #[tokio::test]
    async fn test_generic_passthrough_post_empty_body_rejected() {
        let calls = Arc::new(AtomicUsize::new(0));
        let captured_body = Arc::new(tokio::sync::Mutex::new(Vec::new()));
        let upstream =
            spawn_counting_upstream(Arc::clone(&calls), Arc::clone(&captured_body)).await;

        let state = Arc::new(
            ProxyState::new(
                upstream,
                0.0,
                std::env::temp_dir().join("anon-test-generic-passthrough-post-empty"),
                Provider::Generic,
            )
            .with_generic_allowed_path_prefixes(["/api/"])
            .unwrap(),
        );

        let req = Request::builder()
            .method("POST")
            .uri("/api/generate")
            .body(Body::empty())
            .unwrap();

        let resp = passthrough(State(state), req).await;

        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert!(captured_body.lock().await.is_empty());
    }

    /// Test that non-generic providers reject non-JSON request bodies
    #[tokio::test]
    async fn test_non_generic_rejects_non_json() {
        let state = Arc::new(ProxyState::new(
            "http://localhost:0".to_string(),
            0.0,
            std::env::temp_dir().join("anon-test-anthropic-non-json"),
            Provider::Anthropic,
        ));

        // Non-JSON body (plain text)
        let body = b"This is plain text";
        let req = Request::builder()
            .method("POST")
            .uri("/v1/messages")
            .body(Body::from(body.to_vec()))
            .unwrap();

        let resp = handle_messages(State(state), HeaderMap::new(), req).await;

        // Anthropic provider should reject non-JSON bodies
        assert_eq!(
            resp.status(),
            StatusCode::BAD_REQUEST,
            "Anthropic provider should reject non-JSON bodies"
        );
    }

    // ============================================================================
    // INTEGRATION TESTS: ANTHROPIC PROVIDER (REGRESSION)
    // ============================================================================

    /// Anthropic: test that system string gets anonymized
    #[test]
    fn test_anthropic_integration_system_string_anonymized() {
        let mut anonymizer = crate::detection::Anonymizer::new(0.0);
        let mut body = serde_json::json!({
            "model": "claude-sonnet-4-20250514",
            "max_tokens": 1024,
            "system": "Contact support at admin@company.com or call +1 555-123-4567",
            "messages": [
                {"role": "user", "content": "Hello"}
            ]
        });

        anthropic::anonymize_request(&mut body, &mut anonymizer);

        let system = body["system"].as_str().unwrap();
        assert!(
            system.contains("[EMAIL_ADDRESS_"),
            "Anthropic system: email should be anonymized, got: {system}"
        );
        assert!(
            !system.contains("admin@company.com"),
            "Anthropic system: original email should not appear"
        );
    }

    /// Anthropic: test that system array of content blocks gets anonymized
    #[test]
    fn test_anthropic_integration_system_array_anonymized() {
        let mut anonymizer = crate::detection::Anonymizer::new(0.0);
        let mut body = serde_json::json!({
            "model": "claude-sonnet-4-20250514",
            "max_tokens": 1024,
            "system": [
                {"type": "text", "text": "Admin email: admin@company.com"},
                {"type": "text", "text": "Server IP: 192.168.1.100"}
            ],
            "messages": [
                {"role": "user", "content": "Hello"}
            ]
        });

        anthropic::anonymize_request(&mut body, &mut anonymizer);

        let text0 = body["system"][0]["text"].as_str().unwrap();
        assert!(
            text0.contains("[EMAIL_ADDRESS_"),
            "Anthropic system array: email should be anonymized, got: {text0}"
        );

        let text1 = body["system"][1]["text"].as_str().unwrap();
        assert!(
            text1.contains("[IP_ADDRESS_"),
            "Anthropic system array: IP should be anonymized, got: {text1}"
        );
    }

    /// Anthropic: test tool_result content string anonymization
    #[test]
    fn test_anthropic_integration_tool_result_string_anonymized() {
        let mut anonymizer = crate::detection::Anonymizer::new(0.0);
        let mut body = serde_json::json!({
            "model": "claude-sonnet-4-20250514",
            "max_tokens": 1024,
            "messages": [
                {
                    "role": "user",
                    "content": [
                        {
                            "type": "tool_result",
                            "tool_use_id": "toolu_123",
                            "content": "Found user john@example.com at 10.0.0.42"
                        }
                    ]
                }
            ]
        });

        anthropic::anonymize_request(&mut body, &mut anonymizer);

        let content = body["messages"][0]["content"][0]["content"]
            .as_str()
            .unwrap();
        assert!(
            content.contains("[EMAIL_ADDRESS_"),
            "Anthropic tool_result: email should be anonymized, got: {content}"
        );
        assert!(
            content.contains("[IP_ADDRESS_"),
            "Anthropic tool_result: IP should be anonymized, got: {content}"
        );
    }

    /// Anthropic: test tool_result content array anonymization
    #[test]
    fn test_anthropic_integration_tool_result_array_anonymized() {
        let mut anonymizer = crate::detection::Anonymizer::new(0.0);
        let mut body = serde_json::json!({
            "model": "claude-sonnet-4-20250514",
            "max_tokens": 1024,
            "messages": [
                {
                    "role": "user",
                    "content": [
                        {
                            "type": "tool_result",
                            "tool_use_id": "toolu_123",
                            "content": [
                                {"type": "text", "text": "Email: secret@hidden.org"}
                            ]
                        }
                    ]
                }
            ]
        });

        anthropic::anonymize_request(&mut body, &mut anonymizer);

        let text = body["messages"][0]["content"][0]["content"][0]["text"]
            .as_str()
            .unwrap();
        assert!(
            text.contains("[EMAIL_ADDRESS_"),
            "Anthropic tool_result array: email should be anonymized, got: {text}"
        );
    }

    /// Anthropic: end-to-end anonymize -> restore roundtrip
    #[test]
    fn test_anthropic_integration_roundtrip() {
        let mut anonymizer = crate::detection::Anonymizer::new(0.0);
        let original_email = "roundtrip@test.com";
        let original_ip = "172.16.0.1";

        let mut body = serde_json::json!({
            "model": "claude-sonnet-4-20250514",
            "messages": [
                {"role": "user", "content": format!("Contact {} at {}", original_email, original_ip)}
            ]
        });

        anthropic::anonymize_request(&mut body, &mut anonymizer);

        // Build a mock response with the tokens
        let anon_content = body["messages"][0]["content"].as_str().unwrap();
        let mut response = serde_json::json!({
            "content": [
                {"type": "text", "text": format!("I see {}", anon_content)}
            ]
        });

        anthropic::restore_response(&mut response, &anonymizer.mapping);

        let restored = response["content"][0]["text"].as_str().unwrap();
        assert!(
            restored.contains(original_email),
            "Anthropic roundtrip: email should be restored, got: {restored}"
        );
        assert!(
            restored.contains(original_ip),
            "Anthropic roundtrip: IP should be restored, got: {restored}"
        );
    }

    // ============================================================================
    // INTEGRATION TESTS: OPENAI PROVIDER
    // ============================================================================

    /// OpenAI: test multiple tool_calls in a single message
    #[test]
    fn test_openai_integration_multiple_tool_calls() {
        let mut anonymizer = crate::detection::Anonymizer::new(0.0);
        let mut body = serde_json::json!({
            "model": "gpt-4",
            "messages": [
                {
                    "role": "assistant",
                    "content": null,
                    "tool_calls": [
                        {
                            "id": "call_1",
                            "type": "function",
                            "function": {
                                "name": "get_user",
                                "arguments": "{\"email\": \"john@example.com\"}"
                            }
                        },
                        {
                            "id": "call_2",
                            "type": "function",
                            "function": {
                                "name": "get_server",
                                "arguments": "{\"ip\": \"192.168.1.100\"}"
                            }
                        }
                    ]
                }
            ]
        });

        openai::anonymize_request(&mut body, &mut anonymizer);

        let args1 = body["messages"][0]["tool_calls"][0]["function"]["arguments"]
            .as_str()
            .unwrap();
        assert!(
            args1.contains("[EMAIL_ADDRESS_"),
            "OpenAI multiple tool_calls: first email should be anonymized, got: {args1}"
        );

        let args2 = body["messages"][0]["tool_calls"][1]["function"]["arguments"]
            .as_str()
            .unwrap();
        assert!(
            args2.contains("[IP_ADDRESS_"),
            "OpenAI multiple tool_calls: second IP should be anonymized, got: {args2}"
        );
    }

    /// OpenAI: test nested tool parameters descriptions
    #[test]
    fn test_openai_integration_nested_tool_parameters() {
        let mut anonymizer = crate::detection::Anonymizer::new(0.0);
        let mut body = serde_json::json!({
            "model": "gpt-4",
            "messages": [{"role": "user", "content": "Hi"}],
            "tools": [
                {
                    "type": "function",
                    "function": {
                        "name": "complex_tool",
                        "parameters": {
                            "type": "object",
                            "properties": {
                                "config": {
                                    "type": "object",
                                    "description": "Contact admin@support.com for help",
                                    "properties": {
                                        "endpoint": {
                                            "type": "string",
                                            "description": "Server at 10.0.0.42"
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            ]
        });

        openai::anonymize_request(&mut body, &mut anonymizer);

        let config_desc =
            body["tools"][0]["function"]["parameters"]["properties"]["config"]["description"]
                .as_str()
                .unwrap();
        assert!(
            config_desc.contains("[EMAIL_ADDRESS_"),
            "OpenAI nested params: top-level description should be anonymized, got: {config_desc}"
        );

        let endpoint_desc = body["tools"][0]["function"]["parameters"]["properties"]["config"]
            ["properties"]["endpoint"]["description"]
            .as_str()
            .unwrap();
        assert!(
            endpoint_desc.contains("[IP_ADDRESS_"),
            "OpenAI nested params: nested description should be anonymized, got: {endpoint_desc}"
        );
    }

    /// OpenAI: end-to-end anonymize -> restore roundtrip
    #[test]
    fn test_openai_integration_roundtrip() {
        let mut anonymizer = crate::detection::Anonymizer::new(0.0);
        let original_email = "openai-roundtrip@test.com";

        let mut request = serde_json::json!({
            "model": "gpt-4",
            "messages": [
                {"role": "user", "content": format!("My email is {}", original_email)}
            ]
        });

        openai::anonymize_request(&mut request, &mut anonymizer);

        // Build a mock response echoing the token
        let anon_content = request["messages"][0]["content"].as_str().unwrap();
        let mut response = serde_json::json!({
            "id": "chatcmpl-test",
            "choices": [
                {
                    "index": 0,
                    "message": {
                        "role": "assistant",
                        "content": format!("Got your email: {}", anon_content)
                    },
                    "finish_reason": "stop"
                }
            ]
        });

        openai::restore_response(&mut response, &anonymizer.mapping);

        let restored = response["choices"][0]["message"]["content"]
            .as_str()
            .unwrap();
        assert!(
            restored.contains(original_email),
            "OpenAI roundtrip: email should be restored, got: {restored}"
        );
    }

    /// OpenAI: SSE streaming content delta restoration
    #[test]
    fn test_openai_integration_sse_streaming_content() {
        let mut mapping = crate::mapping::Mapping::new();
        mapping.mappings.insert(
            "[EMAIL_ADDRESS_stream123]".to_string(),
            "stream@test.com".to_string(),
        );
        mapping.rebuild_caches();
        let mut token_buffer = sse::TokenBuffer::new(mapping);

        // Simulate streaming deltas split across events
        let mut output = String::new();

        // First chunk: partial token
        let line1 = r#"data: {"id":"chatcmpl-abc","choices":[{"index":0,"delta":{"content":"Your email is [EMAIL_"},"finish_reason":null}]}"#;
        process_sse_line(line1, &mut token_buffer, &mut output, Provider::OpenAi);

        // Second chunk: rest of token
        let line2 = r#"data: {"id":"chatcmpl-abc","choices":[{"index":0,"delta":{"content":"ADDRESS_stream123]"},"finish_reason":null}]}"#;
        process_sse_line(line2, &mut token_buffer, &mut output, Provider::OpenAi);

        assert!(
            output.contains("stream@test.com"),
            "OpenAI SSE streaming: token should be restored across chunks, got: {output}"
        );
    }

    /// OpenAI: SSE streaming tool_calls arguments restoration
    #[test]
    fn test_openai_integration_sse_streaming_tool_calls() {
        let mut mapping = crate::mapping::Mapping::new();
        mapping.mappings.insert(
            "[IP_ADDRESS_toolcall1]".to_string(),
            "10.20.30.40".to_string(),
        );
        mapping.rebuild_caches();
        let mut token_buffer = sse::TokenBuffer::new(mapping);
        let mut output = String::new();

        let line = r#"data: {"id":"chatcmpl-abc","choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"function":{"arguments":"[IP_ADDRESS_toolcall1]"}}]},"finish_reason":null}]}"#;
        process_sse_line(line, &mut token_buffer, &mut output, Provider::OpenAi);

        assert!(
            output.contains("10.20.30.40"),
            "OpenAI SSE tool_calls: IP should be restored, got: {output}"
        );
    }

    // ============================================================================
    // INTEGRATION TESTS: GENERIC PROVIDER
    // ============================================================================

    /// Generic: deeply nested objects are fully anonymized
    #[test]
    fn test_generic_integration_deep_nesting() {
        let mut anonymizer = crate::detection::Anonymizer::new(0.0);
        let mut body = serde_json::json!({
            "level1": {
                "level2": {
                    "level3": {
                        "level4": {
                            "secret": "Deep email: deep@nested.com"
                        }
                    }
                }
            }
        });

        generic::anonymize_request(&mut body, &mut anonymizer);

        let secret = body["level1"]["level2"]["level3"]["level4"]["secret"]
            .as_str()
            .unwrap();
        assert!(
            secret.contains("[EMAIL_ADDRESS_"),
            "Generic deep nesting: email should be anonymized, got: {secret}"
        );
    }

    /// Generic: mixed arrays and objects are fully anonymized
    #[test]
    fn test_generic_integration_mixed_structure() {
        let mut anonymizer = crate::detection::Anonymizer::new(0.0);
        let mut body = serde_json::json!({
            "users": [
                {
                    "emails": ["user1@test.com", "user1-alt@test.com"],
                    "ips": ["192.168.1.1", "192.168.1.2"]
                },
                {
                    "emails": ["user2@test.com"],
                    "ips": ["10.0.0.1"]
                }
            ]
        });

        generic::anonymize_request(&mut body, &mut anonymizer);

        // Check all emails are anonymized
        let email00 = body["users"][0]["emails"][0].as_str().unwrap();
        assert!(
            email00.contains("[EMAIL_ADDRESS_"),
            "Generic mixed: first user first email should be anonymized, got: {email00}"
        );

        let email01 = body["users"][0]["emails"][1].as_str().unwrap();
        assert!(
            email01.contains("[EMAIL_ADDRESS_"),
            "Generic mixed: first user second email should be anonymized, got: {email01}"
        );

        let email10 = body["users"][1]["emails"][0].as_str().unwrap();
        assert!(
            email10.contains("[EMAIL_ADDRESS_"),
            "Generic mixed: second user email should be anonymized, got: {email10}"
        );

        // Check all IPs are anonymized
        let ip00 = body["users"][0]["ips"][0].as_str().unwrap();
        assert!(
            ip00.contains("[IP_ADDRESS_"),
            "Generic mixed: first user first IP should be anonymized, got: {ip00}"
        );
    }

    /// Generic: end-to-end roundtrip with complex structure
    #[test]
    fn test_generic_integration_roundtrip() {
        let mut anonymizer = crate::detection::Anonymizer::new(0.0);
        let original_email = "generic-roundtrip@test.com";
        let original_ip = "203.0.113.42";

        let mut request = serde_json::json!({
            "data": {
                "contact": original_email,
                "server": original_ip
            }
        });

        generic::anonymize_request(&mut request, &mut anonymizer);

        // Build mock response with tokens
        let anon_email = request["data"]["contact"].as_str().unwrap();
        let anon_ip = request["data"]["server"].as_str().unwrap();

        let mut response = serde_json::json!({
            "result": {
                "processed_contact": anon_email,
                "processed_server": anon_ip
            }
        });

        generic::restore_response(&mut response, &anonymizer.mapping);

        let restored_email = response["result"]["processed_contact"].as_str().unwrap();
        assert!(
            restored_email.contains(original_email),
            "Generic roundtrip: email should be restored, got: {restored_email}"
        );

        let restored_ip = response["result"]["processed_server"].as_str().unwrap();
        assert!(
            restored_ip.contains(original_ip),
            "Generic roundtrip: IP should be restored, got: {restored_ip}"
        );
    }

    /// Generic: SSE streaming with unknown format (fallback to line-based restore)
    #[test]
    fn test_generic_integration_sse_unknown_format() {
        let mut mapping = crate::mapping::Mapping::new();
        mapping.mappings.insert(
            "[EMAIL_ADDRESS_unknown1]".to_string(),
            "unknown@format.com".to_string(),
        );
        mapping.rebuild_caches();
        let mut token_buffer = sse::TokenBuffer::new(mapping);
        let mut output = String::new();

        // Non-standard SSE format (not OpenAI or Anthropic schema)
        let line = r#"data: {"custom_field": "Value is [EMAIL_ADDRESS_unknown1]"}"#;
        process_sse_line(line, &mut token_buffer, &mut output, Provider::Generic);

        assert!(
            output.contains("unknown@format.com"),
            "Generic SSE unknown format: token should be restored, got: {output}"
        );
    }

    // ============================================================================
    // ERROR CASE TESTS
    // ============================================================================

    /// Test empty body handling for Anthropic provider
    #[tokio::test]
    async fn test_anthropic_empty_body_returns_error() {
        let state = Arc::new(ProxyState::new(
            "http://localhost:0".to_string(),
            0.0,
            std::env::temp_dir().join("anon-test-anthropic-empty"),
            Provider::Anthropic,
        ));

        let req = Request::builder()
            .method("POST")
            .uri("/v1/messages")
            .body(Body::empty())
            .unwrap();

        let resp = handle_messages(State(state), HeaderMap::new(), req).await;

        // Empty body should return BAD_REQUEST for schema-based providers
        assert_eq!(
            resp.status(),
            StatusCode::BAD_REQUEST,
            "Anthropic: empty body should return 400 Bad Request"
        );
    }

    /// Test empty body handling for OpenAI provider
    #[tokio::test]
    async fn test_openai_empty_body_returns_error() {
        let state = Arc::new(ProxyState::new(
            "http://localhost:0".to_string(),
            0.0,
            std::env::temp_dir().join("anon-test-openai-empty"),
            Provider::OpenAi,
        ));

        let req = Request::builder()
            .method("POST")
            .uri("/v1/chat/completions")
            .body(Body::empty())
            .unwrap();

        let resp = handle_messages(State(state), HeaderMap::new(), req).await;

        // Empty body should return BAD_REQUEST for schema-based providers
        assert_eq!(
            resp.status(),
            StatusCode::BAD_REQUEST,
            "OpenAI: empty body should return 400 Bad Request"
        );
    }

    /// Test empty body handling for Generic provider
    #[tokio::test]
    async fn test_generic_empty_body_returns_error() {
        let state = Arc::new(ProxyState::new(
            "http://localhost:0".to_string(),
            0.0,
            std::env::temp_dir().join("anon-test-generic-empty"),
            Provider::Generic,
        ));

        let req = Request::builder()
            .method("POST")
            .uri("/v1/messages")
            .body(Body::empty())
            .unwrap();

        let resp = handle_messages(State(state), HeaderMap::new(), req).await;

        assert_eq!(
            resp.status(),
            StatusCode::BAD_REQUEST,
            "Generic: empty body should return 400 Bad Request"
        );
    }

    /// Test malformed JSON handling for Generic provider
    #[tokio::test]
    async fn test_generic_malformed_json_returns_error() {
        let state = Arc::new(ProxyState::new(
            "http://localhost:0".to_string(),
            0.0,
            std::env::temp_dir().join("anon-test-generic-malformed-json"),
            Provider::Generic,
        ));

        let req = Request::builder()
            .method("POST")
            .uri("/v1/generate")
            .body(Body::from(r#"{"prompt": "unterminated""#))
            .unwrap();

        let resp = handle_messages(State(state), HeaderMap::new(), req).await;

        assert_eq!(
            resp.status(),
            StatusCode::BAD_REQUEST,
            "Generic: malformed JSON should return 400 Bad Request"
        );
    }

    /// Test malformed JSON handling
    #[tokio::test]
    async fn test_malformed_json_returns_error() {
        let state = Arc::new(ProxyState::new(
            "http://localhost:0".to_string(),
            0.0,
            std::env::temp_dir().join("anon-test-malformed-json"),
            Provider::Anthropic,
        ));

        // Malformed JSON: missing closing brace
        let body = br#"{"model": "claude", "messages": ["#;
        let req = Request::builder()
            .method("POST")
            .uri("/v1/messages")
            .body(Body::from(body.to_vec()))
            .unwrap();

        let resp = handle_messages(State(state), HeaderMap::new(), req).await;

        assert_eq!(
            resp.status(),
            StatusCode::BAD_REQUEST,
            "Malformed JSON should return 400 Bad Request"
        );

        let body_bytes = to_bytes(resp.into_body(), 1024).await.unwrap();
        let text = String::from_utf8_lossy(&body_bytes);
        assert!(
            text.to_lowercase().contains("json") || text.to_lowercase().contains("parse"),
            "Error message should mention JSON parsing issue: {text}"
        );
    }

    /// Test header forwarding: OpenAI headers NOT forwarded to Anthropic provider
    #[test]
    fn test_header_forwarding_openai_headers_blocked_for_anthropic() {
        let client = reqwest::Client::new();
        let mut headers = HeaderMap::new();
        headers.insert("openai-organization", HeaderValue::from_static("org-123"));
        headers.insert("openai-project", HeaderValue::from_static("proj-456"));
        headers.insert("x-api-key", HeaderValue::from_static("sk-ant-test"));

        let builder = client.post("http://localhost/test");
        let filtered = filter_headers_for_upstream(&headers, builder, Provider::Anthropic);
        let req = filtered.build().unwrap();
        let fwd_headers = req.headers();

        // OpenAI headers should NOT be forwarded to Anthropic
        assert!(
            fwd_headers.get("openai-organization").is_none(),
            "openai-organization should not be forwarded to Anthropic"
        );
        assert!(
            fwd_headers.get("openai-project").is_none(),
            "openai-project should not be forwarded to Anthropic"
        );

        // Anthropic headers SHOULD be forwarded
        assert_eq!(
            fwd_headers.get("x-api-key").unwrap(),
            "sk-ant-test",
            "x-api-key should be forwarded to Anthropic"
        );
    }

    /// Test header forwarding: Anthropic headers NOT forwarded to OpenAI provider
    #[test]
    fn test_header_forwarding_anthropic_headers_blocked_for_openai() {
        let client = reqwest::Client::new();
        let mut headers = HeaderMap::new();
        headers.insert("x-api-key", HeaderValue::from_static("sk-ant-test"));
        headers.insert("anthropic-version", HeaderValue::from_static("2024-01-01"));
        headers.insert("authorization", HeaderValue::from_static("Bearer sk-test"));

        let builder = client.post("http://localhost/test");
        let filtered = filter_headers_for_upstream(&headers, builder, Provider::OpenAi);
        let req = filtered.build().unwrap();
        let fwd_headers = req.headers();

        // Anthropic headers should NOT be forwarded to OpenAI
        assert!(
            fwd_headers.get("x-api-key").is_none(),
            "x-api-key should not be forwarded to OpenAI"
        );
        assert!(
            fwd_headers.get("anthropic-version").is_none(),
            "anthropic-version should not be forwarded to OpenAI"
        );

        // Standard headers SHOULD be forwarded
        assert_eq!(
            fwd_headers.get("authorization").unwrap(),
            "Bearer sk-test",
            "authorization should be forwarded to OpenAI"
        );
    }

    /// Test header forwarding: Generic provider blocks provider-specific headers by default
    #[test]
    fn test_header_forwarding_generic_blocks_provider_headers_by_default() {
        let client = reqwest::Client::new();
        let mut headers = HeaderMap::new();
        headers.insert("x-api-key", HeaderValue::from_static("sk-ant-test"));
        headers.insert("anthropic-version", HeaderValue::from_static("2024-01-01"));
        headers.insert("anthropic-beta", HeaderValue::from_static("tools-2024"));
        headers.insert("openai-organization", HeaderValue::from_static("org-123"));
        headers.insert("openai-project", HeaderValue::from_static("proj-456"));
        headers.insert("authorization", HeaderValue::from_static("Bearer sk-test"));

        let builder = client.post("http://localhost/test");
        let filtered = filter_headers_for_upstream(&headers, builder, Provider::Generic);
        let req = filtered.build().unwrap();
        let fwd_headers = req.headers();

        assert!(
            fwd_headers.get("x-api-key").is_none(),
            "x-api-key should not be forwarded for Generic by default"
        );
        assert!(
            fwd_headers.get("anthropic-version").is_none(),
            "anthropic-version should not be forwarded for Generic by default"
        );
        assert!(
            fwd_headers.get("anthropic-beta").is_none(),
            "anthropic-beta should not be forwarded for Generic by default"
        );
        assert!(
            fwd_headers.get("openai-organization").is_none(),
            "openai-organization should not be forwarded for Generic by default"
        );
        assert!(
            fwd_headers.get("openai-project").is_none(),
            "openai-project should not be forwarded for Generic by default"
        );
        assert_eq!(
            fwd_headers.get("authorization").unwrap(),
            "Bearer sk-test",
            "authorization should be forwarded for Generic"
        );
    }

    /// Test header forwarding: Generic provider forwards provider-specific headers only by explicit opt-in
    #[test]
    fn test_header_forwarding_generic_explicitly_allows_provider_headers() {
        let client = reqwest::Client::new();
        let mut headers = HeaderMap::new();
        headers.insert("x-api-key", HeaderValue::from_static("sk-ant-test"));
        headers.insert("anthropic-version", HeaderValue::from_static("2024-01-01"));
        headers.insert("anthropic-beta", HeaderValue::from_static("tools-2024"));
        headers.insert("openai-organization", HeaderValue::from_static("org-123"));
        headers.insert("openai-project", HeaderValue::from_static("proj-456"));
        headers.insert("authorization", HeaderValue::from_static("Bearer sk-test"));

        let builder = client.post("http://localhost/test");
        let filtered =
            filter_headers_for_upstream_with_options(&headers, builder, Provider::Generic, true);
        let req = filtered.build().unwrap();
        let fwd_headers = req.headers();

        assert_eq!(fwd_headers.get("x-api-key").unwrap(), "sk-ant-test");
        assert_eq!(fwd_headers.get("anthropic-version").unwrap(), "2024-01-01");
        assert_eq!(fwd_headers.get("anthropic-beta").unwrap(), "tools-2024");
        assert_eq!(fwd_headers.get("openai-organization").unwrap(), "org-123");
        assert_eq!(fwd_headers.get("openai-project").unwrap(), "proj-456");
        assert_eq!(fwd_headers.get("authorization").unwrap(), "Bearer sk-test");
    }
}
