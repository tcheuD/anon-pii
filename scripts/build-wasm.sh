#!/usr/bin/env bash
# Build the browser playground engine (docs/playground/pkg).
# Requires: rustup target add wasm32-unknown-unknown
#           cargo install wasm-bindgen-cli --version 0.2.108  (must match Cargo.lock)
set -euo pipefail
cd "$(dirname "$0")/.."
RUSTFLAGS='--cfg getrandom_backend="wasm_js"' \
  cargo build --release --target wasm32-unknown-unknown --features ner-lite
wasm-bindgen --target web --no-typescript \
  --out-dir docs/playground/pkg \
  target/wasm32-unknown-unknown/release/anon_pii.wasm
echo "playground engine: $(du -h docs/playground/pkg/anon_pii_bg.wasm | cut -f1)"
