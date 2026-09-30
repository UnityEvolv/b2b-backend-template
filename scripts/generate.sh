#!/usr/bin/env bash
# Regenerate every generated file: sqlc queries and the OpenAPI server of every
# service. CI runs this and fails if anything differs from what is committed,
# which is what stops a hand edit to generated code.
#
#   scripts/generate.sh
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$root"

SQLC_IMAGE="sqlc/sqlc:1.31.1"

# Docker on Windows wants a Windows path for the mount.
mount="$root"
if command -v cygpath >/dev/null 2>&1; then mount="$(cygpath -w "$root")"; fi

for config in services/*/sqlc.yaml; do
  service="$(dirname "$config")"
  echo "sqlc: $service"
  MSYS_NO_PATHCONV=1 docker run --rm -v "$mount:/src" -w "/src/$service" "$SQLC_IMAGE" generate
done

for config in services/*/oapi-codegen.yaml; do
  service="$(dirname "$config")"
  name="$(basename "$service")"
  echo "oapi-codegen: $service"
  (cd "$service" && go tool oapi-codegen -config oapi-codegen.yaml "../../api/$name.yaml")
done

gofmt -w services

# Generated code that lives outside services/ (a worked example, a product's
# own services kept in their own directory) comes with its own generate.sh
# beside it. Each one runs here too, so the drift check covers it; with none,
# nothing runs.
for extra in */*/generate.sh; do
  [ -f "$extra" ] || continue
  echo "generate: $(dirname "$extra")"
  bash "$extra"
done
