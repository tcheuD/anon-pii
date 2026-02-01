pub mod anthropic;
pub mod handler;
pub mod sse;

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use axum::extract::Request;
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::any;
use axum::Router;
use tokio::sync::Mutex;

use crate::detection::Anonymizer;
use crate::mapping::Mapping;

pub const DEFAULT_UPSTREAM: &str = "https://api.anthropic.com";
const MAX_ALLOWED_HOSTS: &[&str] = &["127.0.0.1", "localhost", "[::1]"];
const DEFAULT_MAX_MAPPING_ENTRIES: usize = 10_000;

pub struct ProxyState {
    pub client: reqwest::Client,
    pub anonymizer: Mutex<Anonymizer>,
    pub upstream: String,
    pub session_dir: PathBuf,
}

impl ProxyState {
    pub fn new(upstream: String, threshold: f64, session_dir: PathBuf) -> Self {
        let mut anonymizer = Anonymizer::new(threshold);
        anonymizer.mapping = anonymizer.mapping.with_max_entries(DEFAULT_MAX_MAPPING_ENTRIES);

        // Auto-enable NER based on compiled features
        #[cfg(feature = "ner")]
        {
            use crate::ner::{NerConfig, download::model_exists, ml::MlNerDetector};
            let config = NerConfig::default();
            if model_exists(&config) {
                match std::panic::catch_unwind(|| MlNerDetector::new(&config)) {
                    Ok(Ok(det)) => {
                        anonymizer.set_ner_detector(Box::new(det));
                        eprintln!("NER: ML (DistilBERT) enabled");
                    }
                    Ok(Err(e)) => eprintln!("warning: ML NER init failed: {e}"),
                    Err(_) => eprintln!("warning: ONNX Runtime not found, set ORT_DYLIB_PATH"),
                }
            } else {
                eprintln!("warning: NER model not downloaded, run `anon download-model`");
            }
        }
        #[cfg(all(feature = "ner-lite", not(feature = "ner")))]
        {
            use crate::ner::heuristic::HeuristicNerDetector;
            anonymizer.set_ner_detector(Box::new(HeuristicNerDetector::new()));
            eprintln!("NER: heuristic (ner-lite) enabled");
        }

        Self {
            client: reqwest::Client::new(),
            anonymizer: Mutex::new(anonymizer),
            upstream,
            session_dir,
        }
    }

    /// Dump mapping to disk atomically via temp-file-then-rename.
    /// Uses a unique temp file per call to prevent concurrent dump races.
    pub async fn dump_mapping(&self) -> std::io::Result<()> {
        // Hold lock only for serialization, then drop before I/O
        let mapping_json = {
            let anonymizer = self.anonymizer.lock().await;
            serde_json::to_string_pretty(&anonymizer.mapping)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?
        };

        let path = self.session_dir.join("mapping.json");
        let suffix = crate::mapping::crypto_random_hex(4);
        let tmp_path = self.session_dir.join(format!(".mapping.json.{suffix}.tmp"));

        // Write to unique temp file, then atomic rename
        #[cfg(unix)]
        {
            let mut file = tokio::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&tmp_path)
                .await?;
            tokio::io::AsyncWriteExt::write_all(&mut file, mapping_json.as_bytes()).await?;
            tokio::io::AsyncWriteExt::flush(&mut file).await?;
            file.sync_all().await?;
        }
        #[cfg(not(unix))]
        {
            tokio::fs::write(&tmp_path, &mapping_json).await?;
        }

        tokio::fs::rename(&tmp_path, &path).await?;
        Ok(())
    }

    pub async fn get_mapping_snapshot(&self) -> Mapping {
        let anonymizer = self.anonymizer.lock().await;
        // Clone the mapping data we need for restoration
        let mut snapshot = Mapping::new();
        snapshot.mappings = anonymizer.mapping.mappings.clone();
        snapshot.reverse = anonymizer.mapping.reverse.clone();
        snapshot
    }
}

// Host header validation middleware — DNS rebinding defense
async fn validate_host(req: Request, next: Next) -> Response {
    let host = match req.headers().get("host").and_then(|h| h.to_str().ok()) {
        Some(h) => h,
        None => {
            return (
                axum::http::StatusCode::FORBIDDEN,
                "Forbidden: missing Host header",
            )
                .into_response();
        }
    };
    // Strip port
    let hostname = host.split(':').next().unwrap_or(host);
    if !MAX_ALLOWED_HOSTS.contains(&hostname) {
        return (
            axum::http::StatusCode::FORBIDDEN,
            "Forbidden: invalid Host header",
        )
            .into_response();
    }
    next.run(req).await
}

pub async fn run(state: Arc<ProxyState>, port: u16) -> std::io::Result<()> {
    // Ensure session dir exists with restricted permissions
    // Use create_dir (not create_dir_all) so it fails if the path already
    // exists — prevents symlink race where an attacker pre-creates the path.
    match tokio::fs::create_dir(&state.session_dir).await {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            // If the user explicitly passed --session-dir, allow reuse
            // but verify it's actually a directory (not a symlink to elsewhere).
            let meta = tokio::fs::symlink_metadata(&state.session_dir).await?;
            if !meta.is_dir() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::AlreadyExists,
                    format!(
                        "session dir {:?} exists but is not a directory",
                        state.session_dir
                    ),
                ));
            }
        }
        Err(e) => return Err(e),
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        tokio::fs::set_permissions(
            &state.session_dir,
            std::fs::Permissions::from_mode(0o700),
        )
        .await?;
    }

    let app = Router::new()
        .route("/v1/messages", any(handler::handle_messages))
        .fallback(handler::passthrough)
        .layer(middleware::from_fn(validate_host))
        .with_state(state.clone());

    let addr = SocketAddr::from(([127, 0, 0, 1], port));
    eprintln!("anon proxy listening on http://{addr}");
    eprintln!("upstream: {}", state.upstream);
    eprintln!("session dir: {}", state.session_dir.display());

    let listener = tokio::net::TcpListener::bind(addr).await?;

    // Graceful shutdown on Ctrl+C
    let state_shutdown = state.clone();
    axum::serve(listener, app)
        .with_graceful_shutdown(async move {
            tokio::signal::ctrl_c().await.ok();
            eprintln!("\nShutting down proxy...");
            if let Err(e) = state_shutdown.dump_mapping().await {
                eprintln!("Warning: failed to save final mapping: {e}");
            } else {
                eprintln!(
                    "Mapping saved to {}",
                    state_shutdown.session_dir.join("mapping.json").display()
                );
            }
        })
        .await?;

    Ok(())
}
