#!/usr/bin/env bash
# Minimal integration smoke for sfutils-extvolumes.
# Runs dry-runs only — no S3 buckets, no IAM resources, no Snowflake DDL.
# Requires: snow CLI on PATH, uv, repo synced.
#
# Loads .env from repo root when present.
# AWS credentials are optional: dry-run falls back to <AWS_ACCOUNT_ID> placeholder.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

if [[ -f .env ]]; then
  set -a
  # shellcheck disable=SC1091
  source .env
  set +a
fi

echo "== snow connection test =="
snow connection test --format json | head -c 800
echo
echo

echo "== sfutils-extvolumes --help =="
uv run sfutils-extvolumes --help
echo

echo "== sfutils-extvolumes create --help =="
uv run sfutils-extvolumes create --help
echo

echo "== create --dry-run --no-prefix (text output; no AWS or Snowflake calls) =="
uv run sfutils-extvolumes \
  --no-prefix \
  create \
  --bucket smoke-test-bucket \
  --dry-run
echo

echo "== create --dry-run --no-prefix --output json =="
uv run sfutils-extvolumes \
  --no-prefix \
  create \
  --bucket smoke-test-bucket \
  --dry-run \
  --output json
echo

echo "== create --dry-run --no-prefix --no-writes (read-only volume) =="
uv run sfutils-extvolumes \
  --no-prefix \
  create \
  --bucket smoke-test-bucket \
  --no-writes \
  --dry-run
echo

echo "== check-setup --suggest --provider s3 (no DDL, reports credential env) =="
uv run check-setup --suggest --provider s3 || true
echo

echo "== smoke OK =="
