#![cfg(feature = "proxy")]

use anon_pii::cli::{Cli, Commands};
use anon_pii::proxy::{DEFAULT_UPSTREAM, Provider, ProxyState};
use clap::Parser;

fn mapping_file(dir: &std::path::Path) -> std::path::PathBuf {
    dir.join(["mapping", "json"].join("."))
}

#[tokio::test]
async fn proxy_keeps_mapping_in_memory_by_default() {
    let dir = tempfile::tempdir().unwrap();
    let state = ProxyState::new(
        DEFAULT_UPSTREAM.to_string(),
        0.5,
        dir.path().to_path_buf(),
        Provider::Anthropic,
    );

    {
        let mut anonymizer = state.anonymizer.lock().await;
        anonymizer
            .mapping
            .mappings
            .insert("[TOKEN_test]".to_string(), "stored value".to_string());
    }

    state.dump_mapping().await.unwrap();

    assert!(
        !mapping_file(dir.path()).exists(),
        "proxy should not write mappings unless persistence is explicitly enabled"
    );
}

#[tokio::test]
async fn proxy_can_persist_mapping_when_enabled() {
    let dir = tempfile::tempdir().unwrap();
    let state = ProxyState::new(
        DEFAULT_UPSTREAM.to_string(),
        0.5,
        dir.path().to_path_buf(),
        Provider::Anthropic,
    )
    .with_mapping_persistence(true);

    {
        let mut anonymizer = state.anonymizer.lock().await;
        anonymizer
            .mapping
            .mappings
            .insert("[TOKEN_test]".to_string(), "stored value".to_string());
    }

    state.dump_mapping().await.unwrap();

    let content = std::fs::read_to_string(mapping_file(dir.path())).unwrap();
    assert!(content.contains("stored value"));
}

#[test]
fn proxy_persistence_flag_is_opt_in() {
    let cli = Cli::parse_from(["anon-pii", "proxy"]);
    match cli.command {
        Some(Commands::Proxy {
            persist_mapping, ..
        }) => assert!(!persist_mapping),
        _ => panic!("expected proxy command"),
    }

    let cli = Cli::parse_from(["anon-pii", "proxy", "--persist-mapping"]);
    match cli.command {
        Some(Commands::Proxy {
            persist_mapping, ..
        }) => assert!(persist_mapping),
        _ => panic!("expected proxy command"),
    }
}

#[test]
fn ui_persistence_flag_is_opt_in() {
    let cli = Cli::parse_from(["anon-pii", "ui"]);
    match cli.command {
        Some(Commands::Ui {
            persist_mapping, ..
        }) => assert!(!persist_mapping),
        _ => panic!("expected ui command"),
    }

    let cli = Cli::parse_from(["anon-pii", "ui", "--persist-mapping"]);
    match cli.command {
        Some(Commands::Ui {
            persist_mapping, ..
        }) => assert!(persist_mapping),
        _ => panic!("expected ui command"),
    }
}
