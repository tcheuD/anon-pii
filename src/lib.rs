#[cfg(feature = "proxy")]
pub mod api;
pub mod cli;
pub mod config;
mod csv;
pub mod detection;
mod encoding;
pub mod format;
#[cfg(feature = "image")]
pub mod image_redact;
pub mod mapping;
pub mod ner;
pub mod patterns;
#[cfg(feature = "pdf")]
pub mod pdf_redact;
#[cfg(feature = "proxy")]
pub mod proxy;
#[cfg(feature = "proxy")]
pub mod ui;
#[cfg(feature = "xlsx")]
pub mod xlsx;

#[cfg(target_arch = "wasm32")]
pub mod wasm;
