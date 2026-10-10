#!/usr/bin/env bash
# Build the browser playground engine (docs/playground/pkg).
# Requires: rustup target add wasm32-unknown-unknown
# Install the wasm-bindgen-cli version printed below if it is missing or stale.
set -euo pipefail
cd "$(dirname "$0")/.."

wasm_bindgen_version=$(awk '
  $0 == "name = \"wasm-bindgen\"" { in_package = 1; next }
  in_package && $1 == "version" { gsub(/"/, "", $3); print $3; exit }
' Cargo.lock)
if [[ -z "$wasm_bindgen_version" ]]; then
  echo "Cannot find wasm-bindgen in Cargo.lock" >&2
  exit 1
fi
if ! command -v wasm-bindgen >/dev/null 2>&1 \
  || [[ "$(wasm-bindgen --version)" != "wasm-bindgen $wasm_bindgen_version" ]]; then
  echo "The browser bindings must match wasm-bindgen $wasm_bindgen_version in Cargo.lock." >&2
  echo "Run: cargo install wasm-bindgen-cli --version $wasm_bindgen_version --locked" >&2
  exit 1
fi

wasm_target_dir="${CARGO_TARGET_DIR:-target}"
RUSTFLAGS="${RUSTFLAGS:-} --cfg getrandom_backend=\"wasm_js\"" \
  cargo build --locked --release --lib --target wasm32-unknown-unknown \
    --no-default-features --features ner-lite --target-dir "$wasm_target_dir"
wasm-bindgen --target web --no-typescript \
  --out-dir docs/playground/pkg \
  "$wasm_target_dir/wasm32-unknown-unknown/release/anon_pii.wasm"
echo "playground engine: $(du -h docs/playground/pkg/anon_pii_bg.wasm | cut -f1)"
