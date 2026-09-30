#!/usr/bin/env bash
# Prove the template stands on its own without examples/: copy the tree git
# knows about to a temporary directory, delete examples/, and build, vet and
# test what is left, and check that no module was needed only by the
# example. Nothing in the template may depend on the example product; this
# is what shows it. CI runs it on every pull request.
#
# The database tests skip in the copy (the TEST_* settings are cleared): the
# full run covers them, and nothing in them could need the example either.
#
#   scripts/without-examples.sh
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

# Tracked files and new ones not ignored, as they are in the working tree.
(cd "$root" && git ls-files -z --cached --others --exclude-standard |
  while IFS= read -r -d '' f; do [ -f "$f" ] && printf '%s\0' "$f"; done |
  tar --null -T - -cf -) | tar -xf - -C "$tmp"

rm -rf "$tmp/examples"
cd "$tmp"
echo "without examples/, in $tmp"

unset TEST_DATABASE_ADMIN_URL TEST_REDIS_URL TEST_S3_ENDPOINT TEST_S3_BUCKET TEST_S3_ACCESS_KEY TEST_S3_SECRET_KEY
go build ./...
go vet ./...
go mod tidy -diff
go test -count=1 ./...
echo "the template builds, vets and tests without examples/"
