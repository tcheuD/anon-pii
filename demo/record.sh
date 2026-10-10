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

show() {
    printf '\n$ %s\n' "$*"
    sleep "$sleep_seconds"
}

show "cat demo/samples/support-ticket.txt"
cat demo/samples/support-ticket.txt
sleep "$sleep_seconds"

show "anon-pii run --dry-run < demo/samples/support-ticket.txt"
"${anon_pii[@]}" run --dry-run < demo/samples/support-ticket.txt
sleep "$sleep_seconds"

show "anon-pii run -- cat < demo/samples/support-ticket.txt"
"${anon_pii[@]}" run -- cat < demo/samples/support-ticket.txt
printf '\ncat received tokens; the original values above were restored locally.\n'
printf 'No AI command was started and no mapping file was saved.\n'
