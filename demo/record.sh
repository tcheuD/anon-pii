#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

if [[ -n "${ANON_PII_BIN:-}" ]]; then
    anon_pii=("$ANON_PII_BIN")
else
    anon_pii=(cargo run --quiet --)
fi
sleep_seconds="${DEMO_STEP_SLEEP:-0.4}"

work_dir="$(mktemp -d "${TMPDIR:-/tmp}/anon-pii-demo.XXXXXX")"
trap 'rm -rf "$work_dir"' EXIT

map_file="$work_dir/demo-map.json"
anonymized="$work_dir/support-ticket.anonymized.txt"

show() {
    printf '\n$ %s\n' "$*"
    sleep "$sleep_seconds"
}

show "cat demo/samples/support-ticket.txt"
cat demo/samples/support-ticket.txt
sleep "$sleep_seconds"

show "anon-pii -i demo/samples/support-ticket.txt --mapping <temp>/demo-map.json"
"${anon_pii[@]}" -i demo/samples/support-ticket.txt --mapping "$map_file" | tee "$anonymized"
sleep "$sleep_seconds"

show "anon-pii restore -i <anonymized-output> --mapping <same map>"
"${anon_pii[@]}" restore -i "$anonymized" --mapping "$map_file"
