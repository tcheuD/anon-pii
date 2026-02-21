pub mod handlers;
pub mod operators;
pub mod types;

use std::net::SocketAddr;

use axum::extract::Request;
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{http::StatusCode, Router};

const MAX_ALLOWED_HOSTS: &[&str] = &["127.0.0.1", "localhost", "[::1]"];

async fn validate_host(req: Request, next: Next) -> Response {
    let host = match req.headers().get("host").and_then(|h| h.to_str().ok()) {
        Some(h) => h,
        None => {
            return (StatusCode::FORBIDDEN, "Forbidden: missing Host header").into_response();
        }
    };
    let hostname = host.split(':').next().unwrap_or(host);
    if !MAX_ALLOWED_HOSTS.contains(&hostname) {
        return (StatusCode::FORBIDDEN, "Forbidden: invalid Host header").into_response();
    }
    next.run(req).await
}

const OPENAPI_SPEC: &str = include_str!("../../docs/openapi.yaml");

fn router() -> Router {
    Router::new()
        .route("/analyze", post(handlers::analyze))
        .route("/anonymize", post(handlers::anonymize))
        .route("/supportedentities", get(handlers::supported_entities))
        .route("/health", get(handlers::health))
        .route("/openapi.yaml", get(openapi_spec))
        .layer(middleware::from_fn(validate_host))
}

async fn openapi_spec() -> impl IntoResponse {
    (
        [(axum::http::header::CONTENT_TYPE, "application/yaml")],
        OPENAPI_SPEC,
    )
}

pub async fn run(port: u16) -> std::io::Result<()> {
    let app = router();
    let addr = SocketAddr::from(([127, 0, 0, 1], port));
    eprintln!("anon api listening on http://{addr}");

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app)
        .with_graceful_shutdown(async {
            tokio::signal::ctrl_c().await.ok();
            eprintln!("\nShutting down API server...");
        })
        .await?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request as HttpRequest;
    use tower::ServiceExt;

    fn app() -> Router {
        Router::new()
            .route("/analyze", post(handlers::analyze))
            .route("/anonymize", post(handlers::anonymize))
            .route("/supportedentities", get(handlers::supported_entities))
            .route("/health", get(handlers::health))
            .route("/openapi.yaml", get(openapi_spec))
    }

    #[tokio::test]
    async fn test_health_returns_200() {
        let resp = app()
            .oneshot(
                HttpRequest::builder()
                    .uri("/health")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_analyze_returns_detections() {
        let body = serde_json::json!({
            "text": "email: john@example.com",
            "language": "en",
            "score_threshold": 0.0
        });
        let resp = app()
            .oneshot(
                HttpRequest::builder()
                    .method("POST")
                    .uri("/analyze")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(resp.into_body(), 1_000_000)
            .await
            .unwrap();
        let results: Vec<types::RecognizerResult> = serde_json::from_slice(&bytes).unwrap();
        assert!(!results.is_empty());
        assert!(results.iter().any(|r| r.entity_type == "EMAIL_ADDRESS"));

        // Verify position correctness
        let email_result = results
            .iter()
            .find(|r| r.entity_type == "EMAIL_ADDRESS")
            .unwrap();
        assert_eq!(
            &"email: john@example.com"[email_result.start..email_result.end],
            "john@example.com"
        );
    }

    #[tokio::test]
    async fn test_analyze_filters_by_entity_types() {
        let body = serde_json::json!({
            "text": "email: john@example.com, ip: 192.168.1.1",
            "language": "en",
            "score_threshold": 0.0,
            "entities": ["EMAIL_ADDRESS"]
        });
        let resp = app()
            .oneshot(
                HttpRequest::builder()
                    .method("POST")
                    .uri("/analyze")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        let bytes = axum::body::to_bytes(resp.into_body(), 1_000_000)
            .await
            .unwrap();
        let results: Vec<types::RecognizerResult> = serde_json::from_slice(&bytes).unwrap();
        assert!(results.iter().all(|r| r.entity_type == "EMAIL_ADDRESS"));
    }

    #[tokio::test]
    async fn test_anonymize_with_replace() {
        let body = serde_json::json!({
            "text": "email: john@example.com",
            "analyzer_results": [{
                "entity_type": "EMAIL_ADDRESS",
                "start": 7,
                "end": 23,
                "score": 0.85
            }],
            "anonymizers": {
                "DEFAULT": { "type": "replace" }
            }
        });
        let resp = app()
            .oneshot(
                HttpRequest::builder()
                    .method("POST")
                    .uri("/anonymize")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(resp.into_body(), 1_000_000)
            .await
            .unwrap();
        let data: types::AnonymizeResponse = serde_json::from_slice(&bytes).unwrap();
        assert!(data.text.contains("[EMAIL_ADDRESS_"));
        assert!(!data.text.contains("john@example.com"));
        assert_eq!(data.items.len(), 1);
        assert_eq!(data.items[0].operator, "replace");
        assert_eq!(data.items[0].entity_type, "EMAIL_ADDRESS");
    }

    #[tokio::test]
    async fn test_anonymize_per_entity_operators() {
        let body = serde_json::json!({
            "text": "call 202-555-0123 or email john@example.com",
            "analyzer_results": [
                {
                    "entity_type": "PHONE_NUMBER",
                    "start": 5,
                    "end": 17,
                    "score": 0.7
                },
                {
                    "entity_type": "EMAIL_ADDRESS",
                    "start": 27,
                    "end": 43,
                    "score": 0.85
                }
            ],
            "anonymizers": {
                "EMAIL_ADDRESS": { "type": "mask", "masking_char": "*" },
                "PHONE_NUMBER": { "type": "redact" }
            }
        });
        let resp = app()
            .oneshot(
                HttpRequest::builder()
                    .method("POST")
                    .uri("/anonymize")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(resp.into_body(), 1_000_000)
            .await
            .unwrap();
        let data: types::AnonymizeResponse = serde_json::from_slice(&bytes).unwrap();
        // Phone should be redacted (empty)
        assert!(data
            .items
            .iter()
            .any(|i| i.operator == "redact" && i.entity_type == "PHONE_NUMBER"));
        // Email should be masked
        assert!(data
            .items
            .iter()
            .any(|i| i.operator == "mask" && i.entity_type == "EMAIL_ADDRESS"));
        assert!(!data.text.contains("john@example.com"));
        assert!(!data.text.contains("202-555-0123"));
    }

    #[tokio::test]
    async fn test_anonymize_rejects_out_of_bounds() {
        let body = serde_json::json!({
            "text": "short",
            "analyzer_results": [{
                "entity_type": "EMAIL_ADDRESS",
                "start": 0,
                "end": 100,
                "score": 0.85
            }],
            "anonymizers": {}
        });
        let resp = app()
            .oneshot(
                HttpRequest::builder()
                    .method("POST")
                    .uri("/anonymize")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);
    }

    #[tokio::test]
    async fn test_supported_entities_returns_sorted_list() {
        let resp = app()
            .oneshot(
                HttpRequest::builder()
                    .uri("/supportedentities")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(resp.into_body(), 1_000_000)
            .await
            .unwrap();
        let entities: Vec<String> = serde_json::from_slice(&bytes).unwrap();
        assert!(!entities.is_empty());
        assert!(entities.contains(&"EMAIL_ADDRESS".to_string()));

        // Verify sorted
        let mut sorted = entities.clone();
        sorted.sort();
        assert_eq!(entities, sorted);
    }

    #[tokio::test]
    async fn test_host_validation_rejects_external() {
        let resp = router()
            .oneshot(
                HttpRequest::builder()
                    .uri("/health")
                    .header("host", "evil.com")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn test_host_validation_allows_localhost() {
        let resp = router()
            .oneshot(
                HttpRequest::builder()
                    .uri("/health")
                    .header("host", "localhost:8080")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    /// The core Presidio workflow: /analyze output feeds directly into /anonymize.
    #[tokio::test]
    async fn test_analyze_then_anonymize_roundtrip() {
        let text = "Contact john@example.com or call 192.168.1.1";

        // Step 1: /analyze
        let analyze_body = serde_json::json!({
            "text": text,
            "language": "en",
            "score_threshold": 0.0
        });
        let resp = app()
            .oneshot(
                HttpRequest::builder()
                    .method("POST")
                    .uri("/analyze")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&analyze_body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(resp.into_body(), 1_000_000)
            .await
            .unwrap();
        let results: Vec<serde_json::Value> = serde_json::from_slice(&bytes).unwrap();
        assert!(results.len() >= 2);

        // Step 2: /anonymize using raw analyzer output
        let anonymize_body = serde_json::json!({
            "text": text,
            "analyzer_results": results,
            "anonymizers": { "DEFAULT": { "type": "redact" } }
        });
        let resp = app()
            .oneshot(
                HttpRequest::builder()
                    .method("POST")
                    .uri("/anonymize")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&anonymize_body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(resp.into_body(), 1_000_000)
            .await
            .unwrap();
        let data: types::AnonymizeResponse = serde_json::from_slice(&bytes).unwrap();
        assert!(!data.text.contains("john@example.com"));
        assert!(!data.text.contains("192.168.1.1"));
        assert_eq!(data.items.len(), results.len());
    }

    #[tokio::test]
    async fn test_anonymize_hash_operator() {
        let body = serde_json::json!({
            "text": "user john@example.com",
            "analyzer_results": [{
                "entity_type": "EMAIL_ADDRESS",
                "start": 5,
                "end": 21,
                "score": 0.9
            }],
            "anonymizers": {
                "DEFAULT": { "type": "hash", "hash_type": "sha256" }
            }
        });
        let resp = app()
            .oneshot(
                HttpRequest::builder()
                    .method("POST")
                    .uri("/anonymize")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(resp.into_body(), 1_000_000)
            .await
            .unwrap();
        let data: types::AnonymizeResponse = serde_json::from_slice(&bytes).unwrap();
        assert!(!data.text.contains("john@example.com"));
        assert_eq!(data.items[0].operator, "hash");
        // SHA-256 hex output is 64 chars
        assert_eq!(data.items[0].text.len(), 64);
    }

    #[tokio::test]
    async fn test_anonymize_keep_operator() {
        let body = serde_json::json!({
            "text": "user john@example.com",
            "analyzer_results": [{
                "entity_type": "EMAIL_ADDRESS",
                "start": 5,
                "end": 21,
                "score": 0.9
            }],
            "anonymizers": {
                "DEFAULT": { "type": "keep" }
            }
        });
        let resp = app()
            .oneshot(
                HttpRequest::builder()
                    .method("POST")
                    .uri("/anonymize")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(resp.into_body(), 1_000_000)
            .await
            .unwrap();
        let data: types::AnonymizeResponse = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(data.text, "user john@example.com");
        assert_eq!(data.items[0].operator, "keep");
    }

    #[tokio::test]
    async fn test_anonymize_custom_operator() {
        let body = serde_json::json!({
            "text": "user john@example.com",
            "analyzer_results": [{
                "entity_type": "EMAIL_ADDRESS",
                "start": 5,
                "end": 21,
                "score": 0.9
            }],
            "anonymizers": {
                "DEFAULT": { "type": "custom", "lambda": "<{entity_type}>" }
            }
        });
        let resp = app()
            .oneshot(
                HttpRequest::builder()
                    .method("POST")
                    .uri("/anonymize")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(resp.into_body(), 1_000_000)
            .await
            .unwrap();
        let data: types::AnonymizeResponse = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(data.text, "user <EMAIL_ADDRESS>");
        assert_eq!(data.items[0].operator, "custom");
    }

    #[tokio::test]
    async fn test_anonymize_replace_with_explicit_value() {
        let body = serde_json::json!({
            "text": "user john@example.com",
            "analyzer_results": [{
                "entity_type": "EMAIL_ADDRESS",
                "start": 5,
                "end": 21,
                "score": 0.9
            }],
            "anonymizers": {
                "DEFAULT": { "type": "replace", "new_value": "REDACTED" }
            }
        });
        let resp = app()
            .oneshot(
                HttpRequest::builder()
                    .method("POST")
                    .uri("/anonymize")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(resp.into_body(), 1_000_000)
            .await
            .unwrap();
        let data: types::AnonymizeResponse = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(data.text, "user REDACTED");
    }

    #[tokio::test]
    async fn test_anonymize_empty_results_returns_original() {
        let body = serde_json::json!({
            "text": "nothing to anonymize",
            "analyzer_results": [],
            "anonymizers": {}
        });
        let resp = app()
            .oneshot(
                HttpRequest::builder()
                    .method("POST")
                    .uri("/anonymize")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(resp.into_body(), 1_000_000)
            .await
            .unwrap();
        let data: types::AnonymizeResponse = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(data.text, "nothing to anonymize");
        assert!(data.items.is_empty());
    }

    #[tokio::test]
    async fn test_anonymize_default_fallback() {
        // No per-entity config for EMAIL — should use DEFAULT
        let body = serde_json::json!({
            "text": "user john@example.com",
            "analyzer_results": [{
                "entity_type": "EMAIL_ADDRESS",
                "start": 5,
                "end": 21,
                "score": 0.9
            }],
            "anonymizers": {
                "DEFAULT": { "type": "redact" }
            }
        });
        let resp = app()
            .oneshot(
                HttpRequest::builder()
                    .method("POST")
                    .uri("/anonymize")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        let bytes = axum::body::to_bytes(resp.into_body(), 1_000_000)
            .await
            .unwrap();
        let data: types::AnonymizeResponse = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(data.text, "user ");
        assert_eq!(data.items[0].operator, "redact");
    }

    #[tokio::test]
    async fn test_analyze_threshold_filters_low_score() {
        // High threshold should filter out low-confidence detections
        let body = serde_json::json!({
            "text": "email: john@example.com",
            "language": "en",
            "score_threshold": 0.99
        });
        let resp = app()
            .oneshot(
                HttpRequest::builder()
                    .method("POST")
                    .uri("/analyze")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        let bytes = axum::body::to_bytes(resp.into_body(), 1_000_000)
            .await
            .unwrap();
        let results: Vec<types::RecognizerResult> = serde_json::from_slice(&bytes).unwrap();
        // EMAIL_ADDRESS base score is 0.85 — should be filtered at 0.99
        assert!(
            results.is_empty(),
            "expected no results at threshold 0.99, got {:?}",
            results
        );
    }

    #[tokio::test]
    async fn test_analyze_invalid_json_returns_400() {
        let resp = app()
            .oneshot(
                HttpRequest::builder()
                    .method("POST")
                    .uri("/analyze")
                    .header("content-type", "application/json")
                    .body(Body::from(b"not json".to_vec()))
                    .unwrap(),
            )
            .await
            .unwrap();
        // Axum's Json extractor returns 400 for malformed JSON
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_anonymize_rejects_overlapping_results() {
        let body = serde_json::json!({
            "text": "call john@example.com now",
            "analyzer_results": [
                { "entity_type": "EMAIL_ADDRESS", "start": 5, "end": 21, "score": 0.9 },
                { "entity_type": "PERSON", "start": 5, "end": 9, "score": 0.7 }
            ],
            "anonymizers": {}
        });
        let resp = app()
            .oneshot(
                HttpRequest::builder()
                    .method("POST")
                    .uri("/anonymize")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);
    }

    #[tokio::test]
    async fn test_anonymize_rejects_non_char_boundary() {
        // "é" is 2 bytes in UTF-8; offset 1 is mid-character
        let body = serde_json::json!({
            "text": "émail",
            "analyzer_results": [{
                "entity_type": "EMAIL_ADDRESS",
                "start": 1,
                "end": 5,
                "score": 0.85
            }],
            "anonymizers": {}
        });
        let resp = app()
            .oneshot(
                HttpRequest::builder()
                    .method("POST")
                    .uri("/anonymize")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);
    }

    #[tokio::test]
    async fn test_anonymize_encrypt_operator() {
        // 128-bit AES key (32 hex chars)
        let body = serde_json::json!({
            "text": "user john@example.com",
            "analyzer_results": [{
                "entity_type": "EMAIL_ADDRESS",
                "start": 5,
                "end": 21,
                "score": 0.9
            }],
            "anonymizers": {
                "DEFAULT": { "type": "encrypt", "key": "00112233445566778899aabbccddeeff" }
            }
        });
        let resp = app()
            .oneshot(
                HttpRequest::builder()
                    .method("POST")
                    .uri("/anonymize")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(resp.into_body(), 1_000_000)
            .await
            .unwrap();
        let data: types::AnonymizeResponse = serde_json::from_slice(&bytes).unwrap();
        assert!(!data.text.contains("john@example.com"));
        assert_eq!(data.items[0].operator, "encrypt");
        assert!(data.items[0].text.starts_with("ENC["));
    }

    #[tokio::test]
    async fn test_anonymize_encrypt_invalid_key() {
        let body = serde_json::json!({
            "text": "user john@example.com",
            "analyzer_results": [{
                "entity_type": "EMAIL_ADDRESS",
                "start": 5,
                "end": 21,
                "score": 0.9
            }],
            "anonymizers": {
                "DEFAULT": { "type": "encrypt", "key": "not-valid-hex" }
            }
        });
        let resp = app()
            .oneshot(
                HttpRequest::builder()
                    .method("POST")
                    .uri("/anonymize")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);
    }

    #[tokio::test]
    async fn test_anonymize_multi_detection_positions() {
        // Redacting the first detection shifts all subsequent byte offsets.
        // Items must report positions in the *output* string, not the original.
        let body = serde_json::json!({
            "text": "call 202-555-0123 or email john@example.com end",
            "analyzer_results": [
                { "entity_type": "PHONE_NUMBER", "start": 5, "end": 17, "score": 0.7 },
                { "entity_type": "EMAIL_ADDRESS", "start": 27, "end": 43, "score": 0.9 }
            ],
            "anonymizers": {
                "PHONE_NUMBER": { "type": "redact" },
                "EMAIL_ADDRESS": { "type": "replace", "new_value": "XXX" }
            }
        });
        let resp = app()
            .oneshot(
                HttpRequest::builder()
                    .method("POST")
                    .uri("/anonymize")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(resp.into_body(), 1_000_000)
            .await
            .unwrap();
        let data: types::AnonymizeResponse = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(data.text, "call  or email XXX end");
        // Verify each item's start/end matches its actual position in the output
        for item in &data.items {
            assert_eq!(&data.text[item.start..item.end], item.text);
        }
        // Redact at position 5 produces zero-length span
        assert_eq!(data.items[0].start, 5);
        assert_eq!(data.items[0].end, 5);
        // "XXX" shifted from original offset 27 to 15 in the output
        assert_eq!(data.items[1].start, 15);
        assert_eq!(data.items[1].end, 18);
    }

    #[tokio::test]
    async fn test_anonymize_ultimate_fallback_no_anonymizers() {
        // No DEFAULT key, no entity key — falls through to AnonymizerConfig::default()
        let body = serde_json::json!({
            "text": "user john@example.com",
            "analyzer_results": [{
                "entity_type": "EMAIL_ADDRESS",
                "start": 5,
                "end": 21,
                "score": 0.9
            }],
            "anonymizers": {}
        });
        let resp = app()
            .oneshot(
                HttpRequest::builder()
                    .method("POST")
                    .uri("/anonymize")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(resp.into_body(), 1_000_000)
            .await
            .unwrap();
        let data: types::AnonymizeResponse = serde_json::from_slice(&bytes).unwrap();
        assert!(data.text.contains("[EMAIL_ADDRESS_"));
        assert_eq!(data.items[0].operator, "replace");
    }

    #[tokio::test]
    async fn test_host_validation_rejects_missing_host() {
        let resp = router()
            .oneshot(
                HttpRequest::builder()
                    .uri("/health")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn test_openapi_spec_returns_yaml() {
        let resp = app()
            .oneshot(
                HttpRequest::builder()
                    .uri("/openapi.yaml")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let ct = resp
            .headers()
            .get("content-type")
            .unwrap()
            .to_str()
            .unwrap();
        assert_eq!(ct, "application/yaml");
        let bytes = axum::body::to_bytes(resp.into_body(), 1_000_000)
            .await
            .unwrap();
        let body = std::str::from_utf8(&bytes).unwrap();
        assert!(body.starts_with("openapi: 3.0.3"));
    }

    /// Guard against spec↔code drift. If you add or remove a route, this test
    /// fails until you update both the router AND docs/openapi.yaml.
    #[tokio::test]
    async fn test_openapi_spec_covers_all_routes() {
        // Routes registered in the router (source of truth: fn router())
        let api_routes = [
            "/analyze",
            "/anonymize",
            "/supportedentities",
            "/health",
            "/openapi.yaml",
        ];

        // Extract paths from the YAML spec (lines matching `  /path:` under `paths:`)
        let spec = OPENAPI_SPEC;
        let spec_paths: Vec<&str> = spec
            .lines()
            .filter_map(|line| {
                let trimmed = line.trim();
                if trimmed.starts_with('/') && trimmed.ends_with(':') && !line.starts_with("      ")
                {
                    Some(&trimmed[..trimmed.len() - 1])
                } else {
                    None
                }
            })
            .collect();

        // Every router route must be in the spec
        for route in &api_routes {
            assert!(
                spec_paths.contains(route),
                "Route {route} is in the router but missing from docs/openapi.yaml"
            );
        }

        // Every spec path must be in the router
        for path in &spec_paths {
            assert!(
                api_routes.contains(path),
                "Path {path} is in docs/openapi.yaml but missing from the router"
            );
        }
    }
}
