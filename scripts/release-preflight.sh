#!/usr/bin/env bash
set -euo pipefail

fail() {
  printf 'release preflight failed: %s\n' "$1" >&2
  exit 1
}

tag_name="${1:-${GITHUB_REF_NAME:-}}"
release_ref="${2:-${GITHUB_SHA:-HEAD}}"
main_ref="${3:-origin/main}"
manifest_path="${4:-Cargo.toml}"

if [[ -z "$tag_name" ]]; then
  fail "missing tag name (pass vX.Y.Z or set GITHUB_REF_NAME)"
fi

# Cargo accepts SemVer versions. Keep release tags equally strict and require the
# conventional leading `v` used by the release workflow.
semver='(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?(\+[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?'
if [[ ! "$tag_name" =~ ^v${semver}$ ]]; then
  fail "tag '$tag_name' is not a v-prefixed semantic version"
fi

if ! tag_commit=$(git rev-parse --verify "refs/tags/${tag_name}^{commit}" 2>/dev/null); then
  fail "tag '$tag_name' does not resolve to a commit"
fi
if ! release_commit=$(git rev-parse --verify "${release_ref}^{commit}" 2>/dev/null); then
  fail "release ref '$release_ref' does not resolve to a commit"
fi
if ! main_commit=$(git rev-parse --verify "${main_ref}^{commit}" 2>/dev/null); then
  fail "main ref '$main_ref' does not resolve to a commit"
fi

if [[ "$tag_commit" != "$release_commit" ]]; then
  fail "tag '$tag_name' points to $tag_commit, not release commit $release_commit"
fi

if ! manifest=$(git show "${release_commit}:${manifest_path}" 2>/dev/null); then
  fail "cannot read '$manifest_path' from release commit $release_commit"
fi

package_version=$(
  printf '%s\n' "$manifest" | awk '
    /^\[package\][[:space:]]*$/ { in_package = 1; next }
    /^\[/ { if (in_package) exit; next }
    in_package && /^[[:space:]]*version[[:space:]]*=[[:space:]]*"[^"]+"/ {
      line = $0
      sub(/^[[:space:]]*version[[:space:]]*=[[:space:]]*"/, "", line)
      sub(/".*/, "", line)
      print line
      exit
    }
  '
)

if [[ -z "$package_version" ]]; then
  fail "could not read package.version from '$manifest_path'"
fi
if [[ "$tag_name" != "v${package_version}" ]]; then
  fail "tag '$tag_name' does not match package version 'v${package_version}'"
fi

# Containment is intentional: main may advance after a tag is pushed while the
# workflow is running. An ancestor check still rejects releases from side branches.
if ! git merge-base --is-ancestor "$release_commit" "$main_commit"; then
  fail "release commit $release_commit is not contained in '$main_ref' ($main_commit)"
fi

printf "release preflight passed: %s (%s) is version %s and is contained in %s\n" \
  "$tag_name" "$release_commit" "$package_version" "$main_ref"
