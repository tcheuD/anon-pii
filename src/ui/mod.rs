use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::OnceLock;
use std::time::Instant;

use axum::extract::Request;
use axum::http::{StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};

use crate::detection::Anonymizer;
use crate::format::{DetectedFormat, detect_format, detect_json_indent};
use crate::mapping::Mapping;
use crate::patterns::MAX_INPUT_SIZE;

// ─── NER capability detection ────────────────────────────────────────────────

/// Test ML NER runtime availability (model + ONNX Runtime).
/// Called once at startup; result is cached.
fn probe_ml_ner() -> bool {
    #[cfg(feature = "ner")]
    {
        use crate::ner::{NerConfig, download::model_exists, ml::MlNerDetector};
        let config = NerConfig::default();
        if !model_exists(&config) {
            eprintln!("warning: NER model not downloaded, run `anon download-model`");
            return false;
        }
        match std::panic::catch_unwind(|| MlNerDetector::new(&config)) {
            Ok(Ok(_)) => {
                eprintln!("NER: ML (DistilBERT) available");
                return true;
            }
            Ok(Err(e)) => eprintln!("warning: ML NER init failed: {e}"),
            Err(_) => eprintln!("warning: ONNX Runtime not found, set ORT_DYLIB_PATH"),
        }
    }
    false
}

/// Create an Anonymizer with the requested NER mode, falling back gracefully.
/// Returns (anonymizer, actual_ner_mode).
#[allow(unused_variables)]
fn make_anonymizer(
    threshold: f64,
    ner_mode: &str,
    ml_available: bool,
) -> (Anonymizer, &'static str) {
    #[allow(unused_mut)]
    let mut anonymizer = Anonymizer::new(threshold);

    match ner_mode {
        #[cfg(feature = "ner")]
        "ml" if ml_available => {
            use crate::ner::{NerConfig, ml::MlNerDetector};
            let config = NerConfig::default();
            if let Ok(Ok(det)) = std::panic::catch_unwind(|| MlNerDetector::new(&config)) {
                anonymizer.set_ner_detector(Box::new(det));
                return (anonymizer, "ml");
            }
            return (anonymizer, "off");
        }
        #[cfg(feature = "ner-lite")]
        "heuristic" => {
            use crate::ner::heuristic::HeuristicNerDetector;
            anonymizer.set_ner_detector(Box::new(HeuristicNerDetector::new()));
            return (anonymizer, "heuristic");
        }
        _ => {}
    }

    (anonymizer, "off")
}

/// Available NER modes based on compiled features AND runtime availability.
#[allow(unused_variables)]
fn available_ner_modes(ml_available: bool) -> Vec<&'static str> {
    #[allow(unused_mut)]
    let mut modes = vec!["off"];
    #[cfg(feature = "ner-lite")]
    modes.push("heuristic");
    #[cfg(feature = "ner")]
    if ml_available {
        modes.push("ml");
    }
    modes
}

/// Default NER mode: heuristic is preferred (fast, good coverage).
/// ML is available as an option but not default (slow, marginal gains).
#[allow(unused_variables)]
fn default_ner_mode(ml_available: bool) -> &'static str {
    #[cfg(feature = "ner-lite")]
    {
        return "heuristic";
    }
    #[cfg(all(feature = "ner", not(feature = "ner-lite")))]
    if ml_available {
        return "ml";
    }
    #[allow(unreachable_code)]
    "off"
}

const INDEX_HTML: &str = include_str!("index.html");
const MAX_ALLOWED_HOSTS: &[&str] = &["127.0.0.1", "localhost", "[::1]"];

/// Cached result of ML NER probe (tested once at first use).
static ML_NER_AVAILABLE: OnceLock<bool> = OnceLock::new();

fn is_ml_available() -> bool {
    *ML_NER_AVAILABLE.get_or_init(probe_ml_ner)
}

// ─── Mapping persistence (same path as CLI) ─────────────────────────────────

fn mapping_dir() -> PathBuf {
    dirs::home_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".anon-pii")
}

fn mapping_path() -> PathBuf {
    mapping_dir().join("mapping.json")
}

fn save_mapping(mapping: &Mapping) {
    let dir = mapping_dir();
    if let Err(e) = std::fs::create_dir_all(&dir) {
        eprintln!("Warning: could not create mapping dir: {e}");
        return;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700));
    }

    let json = match serde_json::to_string_pretty(mapping) {
        Ok(j) => j,
        Err(e) => {
            eprintln!("Warning: could not serialize mapping: {e}");
            return;
        }
    };

    let tmp = dir.join(".mapping.json.tmp");
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&tmp);
        match file {
            Ok(mut f) => {
                if let Err(e) = f.write_all(json.as_bytes()).and_then(|_| f.sync_all()) {
                    eprintln!("Warning: could not write mapping: {e}");
                    return;
                }
            }
            Err(e) => {
                eprintln!("Warning: could not create mapping file: {e}");
                return;
            }
        }
    }
    #[cfg(not(unix))]
    {
        if let Err(e) = std::fs::write(&tmp, &json) {
            eprintln!("Warning: could not write mapping: {e}");
            return;
        }
    }

    if let Err(e) = std::fs::rename(&tmp, mapping_path()) {
        eprintln!("Warning: could not rename mapping file: {e}");
    }
}

fn load_mapping() -> Option<Mapping> {
    let path = mapping_path();
    let content = std::fs::read_to_string(&path).ok()?;
    let mut mapping: Mapping = serde_json::from_str(&content).ok()?;
    mapping.rebuild_caches();
    Some(mapping)
}

// ─── Request / Response types ────────────────────────────────────────────────

#[derive(Deserialize)]
struct AnonymizeRequest {
    text: String,
    format: Option<String>,
    threshold: Option<f64>,
    ner: Option<String>,
}

#[derive(Serialize, Deserialize)]
struct DetectionItem {
    entity_type: String,
    original: String,
    score: f64,
}

#[derive(Serialize, Deserialize)]
struct AnonymizeResponse {
    result: String,
    detections: Vec<DetectionItem>,
    mapping: HashMap<String, String>,
    compute_time_ms: f64,
    io_time_ms: f64,
    server_time_ms: f64,
    ner_mode: String,
}

#[derive(Deserialize)]
struct RestoreRequest {
    text: String,
    mapping: Option<HashMap<String, String>>,
}

#[derive(Serialize, Deserialize)]
struct RestoreResponse {
    result: String,
}

#[derive(Serialize)]
struct MappingResponse {
    mapping: HashMap<String, String>,
    session_id: String,
    created_at: String,
}

// ─── Handlers ────────────────────────────────────────────────────────────────

async fn index() -> impl IntoResponse {
    (
        [
            (header::CONTENT_TYPE, "text/html; charset=utf-8"),
            (
                header::CONTENT_SECURITY_POLICY,
                "default-src 'self'; script-src 'unsafe-inline'; style-src 'unsafe-inline' https://fonts.googleapis.com; font-src https://fonts.gstatic.com",
            ),
        ],
        INDEX_HTML,
    )
}

async fn anonymize(Json(req): Json<AnonymizeRequest>) -> Response {
    if req.text.len() as u64 > MAX_INPUT_SIZE {
        return (StatusCode::PAYLOAD_TOO_LARGE, "Input too large").into_response();
    }

    let server_start = Instant::now();

    let threshold = req.threshold.unwrap_or(0.5).clamp(0.0, 1.0);
    let format = req.format.as_deref().unwrap_or("auto");
    let ml = is_ml_available();
    let ner_mode = req.ner.as_deref().unwrap_or(default_ner_mode(ml));
    let (mut anonymizer, actual_ner) = make_anonymizer(threshold, ner_mode, ml);

    let (parsed_json, format_name) = match format {
        "json" => match serde_json::from_str::<serde_json::Value>(req.text.trim()) {
            Ok(v) => (Some(v), "json"),
            Err(_) => return (StatusCode::BAD_REQUEST, "Invalid JSON input").into_response(),
        },
        "sql" => (None, "sql"),
        "csv" => (None, "csv"),
        "text" => (None, "text"),
        _ => match detect_format(&req.text) {
            DetectedFormat::Json(v) => (Some(v), "json"),
            DetectedFormat::Sql => (None, "sql"),
            DetectedFormat::Csv => (None, "csv"),
            DetectedFormat::Text => (None, "text"),
        },
    };

    let compute_start = Instant::now();
    let (result, detections) = if let Some(parsed) = parsed_json {
        let indent = detect_json_indent(&req.text);
        let (anon_value, dets) = anonymizer.anonymize_json_value(&parsed);
        let indent_bytes = b" ".repeat(indent);
        let formatter = serde_json::ser::PrettyFormatter::with_indent(&indent_bytes);
        let mut buf = Vec::new();
        let mut ser = serde_json::Serializer::with_formatter(&mut buf, formatter);
        serde::Serialize::serialize(&anon_value, &mut ser).unwrap();
        (String::from_utf8(buf).unwrap(), dets)
    } else if format_name == "csv" {
        anonymizer.anonymize_csv(&req.text)
    } else if format_name == "sql" {
        anonymizer.anonymize_sql(&req.text)
    } else {
        anonymizer.anonymize_text(&req.text)
    };
    let compute_time_ms = compute_start.elapsed().as_secs_f64() * 1000.0;

    let detection_items: Vec<DetectionItem> = detections
        .iter()
        .map(|d| DetectionItem {
            entity_type: d.entity_type.to_string(),
            original: d.original.clone(),
            score: d.score,
        })
        .collect();

    // Persist mapping to ~/.anon-pii/mapping.json (same as CLI)
    let io_start = Instant::now();
    save_mapping(&anonymizer.mapping);
    let io_time_ms = io_start.elapsed().as_secs_f64() * 1000.0;

    let server_time_ms = server_start.elapsed().as_secs_f64() * 1000.0;

    Json(AnonymizeResponse {
        result,
        detections: detection_items,
        mapping: anonymizer.mapping.mappings.clone(),
        compute_time_ms,
        io_time_ms,
        server_time_ms,
        ner_mode: actual_ner.to_string(),
    })
    .into_response()
}

async fn restore(Json(req): Json<RestoreRequest>) -> Response {
    if req.text.len() as u64 > MAX_INPUT_SIZE {
        return (StatusCode::PAYLOAD_TOO_LARGE, "Input too large").into_response();
    }

    // Use provided mapping, or fall back to last saved mapping
    let mut mapping = Mapping::new();
    if let Some(m) = req.mapping {
        mapping.mappings = m;
    } else if let Some(saved) = load_mapping() {
        mapping = saved;
    } else {
        return (StatusCode::BAD_REQUEST, "Aucune correspondance disponible").into_response();
    }
    mapping.rebuild_caches();
    let result = mapping.restore(&req.text);

    Json(RestoreResponse { result }).into_response()
}

async fn get_mapping() -> Response {
    match load_mapping() {
        Some(m) => Json(MappingResponse {
            mapping: m.mappings,
            session_id: m.session_id,
            created_at: m.created_at,
        })
        .into_response(),
        None => (StatusCode::NOT_FOUND, "Aucune correspondance sauvegardée").into_response(),
    }
}

async fn capabilities() -> impl IntoResponse {
    let ml = is_ml_available();
    #[derive(Serialize)]
    struct Capabilities {
        ner_modes: Vec<&'static str>,
        default_ner: &'static str,
    }
    Json(Capabilities {
        ner_modes: available_ner_modes(ml),
        default_ner: default_ner_mode(ml),
    })
}

// ─── Host validation middleware ──────────────────────────────────────────────

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

// ─── Server ──────────────────────────────────────────────────────────────────

pub async fn run(port: u16) -> std::io::Result<()> {
    let app = Router::new()
        .route("/", get(index))
        .route("/api/anonymize", post(anonymize))
        .route("/api/restore", post(restore))
        .route("/api/mapping", get(get_mapping))
        .route("/api/capabilities", get(capabilities))
        .layer(middleware::from_fn(validate_host));

    let addr = SocketAddr::from(([127, 0, 0, 1], port));
    eprintln!("anon ui listening on http://{addr}");

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app)
        .with_graceful_shutdown(async {
            tokio::signal::ctrl_c().await.ok();
            eprintln!("\nShutting down UI server...");
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

    #[test]
    fn test_mapping_dir_uses_anon_pii() {
        // UI mapping_dir should use ~/.anon-pii/ (not ~/.anon/)
        // to match the package rename from #144
        let dir = mapping_dir();
        let dir_name = dir.file_name().unwrap().to_str().unwrap();
        assert_eq!(dir_name, ".anon-pii", "UI mapping dir should be .anon-pii");
    }

    fn app() -> Router {
        Router::new()
            .route("/", get(index))
            .route("/api/anonymize", post(anonymize))
            .route("/api/restore", post(restore))
            .route("/api/mapping", get(get_mapping))
            .route("/api/capabilities", get(capabilities))
    }

    #[tokio::test]
    async fn test_index_serves_html() {
        let resp = app()
            .oneshot(HttpRequest::builder().uri("/").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        let ct = resp
            .headers()
            .get("content-type")
            .unwrap()
            .to_str()
            .unwrap();
        assert!(ct.contains("text/html"));
    }

    #[tokio::test]
    async fn test_anonymize_text() {
        let body = serde_json::json!({
            "text": "contact john@example.com please",
            "format": "text",
            "threshold": 0.0
        });

        let resp = app()
            .oneshot(
                HttpRequest::builder()
                    .method("POST")
                    .uri("/api/anonymize")
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
        let data: AnonymizeResponse = serde_json::from_slice(&bytes).unwrap();
        assert!(data.result.contains("[EMAIL_ADDRESS_"));
        assert!(!data.detections.is_empty());
        assert!(!data.mapping.is_empty());
    }

    #[tokio::test]
    async fn test_restore_roundtrip() {
        let body = serde_json::json!({
            "text": "email: test@example.org",
            "format": "text",
            "threshold": 0.0
        });

        let resp = app()
            .oneshot(
                HttpRequest::builder()
                    .method("POST")
                    .uri("/api/anonymize")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        let bytes = axum::body::to_bytes(resp.into_body(), 1_000_000)
            .await
            .unwrap();
        let anon_data: AnonymizeResponse = serde_json::from_slice(&bytes).unwrap();

        let restore_body = serde_json::json!({
            "text": anon_data.result,
            "mapping": anon_data.mapping
        });

        let resp = app()
            .oneshot(
                HttpRequest::builder()
                    .method("POST")
                    .uri("/api/restore")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&restore_body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(resp.into_body(), 1_000_000)
            .await
            .unwrap();
        let data: RestoreResponse = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(data.result, "email: test@example.org");
    }

    #[tokio::test]
    async fn test_restore_without_mapping_uses_saved() {
        // Anonymize first (saves mapping to disk)
        let body = serde_json::json!({
            "text": "email: saved@example.org",
            "format": "text",
            "threshold": 0.0
        });

        let resp = app()
            .oneshot(
                HttpRequest::builder()
                    .method("POST")
                    .uri("/api/anonymize")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        let bytes = axum::body::to_bytes(resp.into_body(), 1_000_000)
            .await
            .unwrap();
        let anon_data: AnonymizeResponse = serde_json::from_slice(&bytes).unwrap();

        // Re-save the mapping right before restore to avoid race with parallel tests
        let mut mapping = Mapping::new();
        mapping.mappings = anon_data.mapping.clone();
        mapping.rebuild_caches();
        save_mapping(&mapping);

        // Restore WITHOUT providing mapping — should use saved one
        let restore_body = serde_json::json!({
            "text": anon_data.result
        });

        let resp = app()
            .oneshot(
                HttpRequest::builder()
                    .method("POST")
                    .uri("/api/restore")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&restore_body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(resp.into_body(), 1_000_000)
            .await
            .unwrap();
        let data: RestoreResponse = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(data.result, "email: saved@example.org");
    }
}
