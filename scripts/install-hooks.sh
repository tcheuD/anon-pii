#!/bin/sh
# Install git hooks for anon development
set -e

HOOK_DIR="$(git rev-parse --git-dir)/hooks"
mkdir -p "$HOOK_DIR"

cat > "$HOOK_DIR/pre-commit" << 'HOOK'
#!/bin/sh
# Auto-update README.md when Rust source changes
if git diff --cached --name-only | grep -qE '\.(rs|toml)$'; then
    OUTPUT=$(cargo run --example update_readme --features ner-lite,proxy,image,pdf 2>&1)
    EXIT_CODE=$?
    if [ "$EXIT_CODE" -eq 1 ]; then
        git add README.md
        echo "README.md auto-updated and staged."
    elif [ "$EXIT_CODE" -ne 0 ]; then
        echo "warning: update_readme failed (exit $EXIT_CODE):"
        echo "$OUTPUT"
    fi
fi
HOOK

chmod +x "$HOOK_DIR/pre-commit"
echo "Pre-commit hook installed at $HOOK_DIR/pre-commit"
