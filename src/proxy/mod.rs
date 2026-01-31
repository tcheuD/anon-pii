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

pub struct ProxyState {
    pub client: reqwest::Client,
    pub anonymizer: Mutex<Anonymizer>,
    pub upstream: String,
    pub session_dir: PathBuf,
}

impl ProxyState {
    pub fn new(upstream: String, threshold: f64, session_dir: PathBuf) -> Self {
        Self {
            client: reqwest::Client::new(),
            anonymizer: Mutex::new(Anonymizer::new(threshold)),
            upstream,
            session_dir,
        }
    }

    pub async fn dump_mapping(&self) -> std::io::Result<()> {
        let anonymizer = self.anonymizer.lock().await;
        let mapping_json = serde_json::to_string_pretty(&anonymizer.mapping)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;

        let path = self.session_dir.join("mapping.json");
        tokio::fs::write(&path, &mapping_json).await?;
        Ok(())
    }

    pub async fn get_mapping_snapshot(&self) -> Mapping {
        let anonymizer = self.anonymizer.lock().await;
        // Clone the mapping data we need for restoration
        let mut snapshot = Mapping::new();
        snapshot.mappings = anonymizer.mapping.mappings.clone();
        snapshot.reverse = anonymizer.mapping.reverse.clone();
        snapshot.counters = anonymizer.mapping.counters.clone();
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
    // Ensure session dir exists
    tokio::fs::create_dir_all(&state.session_dir).await?;

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
