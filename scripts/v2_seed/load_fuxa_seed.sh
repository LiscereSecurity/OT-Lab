#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_FILE="${ROOT_DIR}/fuxa_openplc_seed_project.json"
FUXA_URL="${FUXA_URL:-http://localhost:1881}"

if [[ ! -f "${PROJECT_FILE}" ]]; then
  echo "Seed file not found: ${PROJECT_FILE}"
  exit 1
fi

echo "Loading FUXA seed project into ${FUXA_URL} ..."
HTTP_CODE="$(
  curl -sS -o /tmp/fuxa_seed_load.out -w "%{http_code}" \
    -X POST "${FUXA_URL}/api/project" \
    -H "Content-Type: application/json" \
    --data-binary @"${PROJECT_FILE}"
)"

if [[ "${HTTP_CODE}" != "200" && "${HTTP_CODE}" != "204" ]]; then
  echo "Failed to load project. HTTP ${HTTP_CODE}"
  cat /tmp/fuxa_seed_load.out
  exit 1
fi

echo "FUXA seed project loaded successfully."
