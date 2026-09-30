#!/usr/bin/env bash
# Regenerate the example's generated code: its sqlc queries and its OpenAPI
# server. scripts/generate.sh runs this with everything else, so CI's drift
# check covers it; it runs on its own too.
#
#   examples/projects/generate.sh
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "$here/../.." && pwd)"
cd "$here"

SQLC_IMAGE="sqlc/sqlc:1.31.1"

# Docker on Windows wants a Windows path for the mount.
mount="$root"
if command -v cygpath >/dev/null 2>&1; then mount="$(cygpath -w "$root")"; fi
rel="${here#"$root"/}"

echo "sqlc: $rel"
MSYS_NO_PATHCONV=1 docker run --rm -v "$mount:/src" -w "/src/$rel" "$SQLC_IMAGE" generate

echo "oapi-codegen: $rel"
go tool oapi-codegen -config oapi-codegen.yaml api/projects.yaml

gofmt -w internal
