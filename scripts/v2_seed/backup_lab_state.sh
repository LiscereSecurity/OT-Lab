#!/usr/bin/env bash
set -euo pipefail

# Backup current OT Lab v2 runtime state (OpenPLC + FUXA) from Docker containers.
# Usage:
#   bash scripts/v2_seed/backup_lab_state.sh

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
STAMP="$(date +%Y%m%d_%H%M%S)"
BACKUP_DIR="${ROOT_DIR}/scripts/v2_seed/backups/${STAMP}"

mkdir -p "${BACKUP_DIR}"

echo "[backup] output dir: ${BACKUP_DIR}"

echo "[backup] exporting FUXA project JSON (API)..."
curl -fsS "http://localhost:1881/api/project" | python3 -m json.tool > "${BACKUP_DIR}/fuxa_project.json"

echo "[backup] copying FUXA project database..."
docker compose cp hmi:/usr/src/app/FUXA/server/_appdata/project.fuxap.db "${BACKUP_DIR}/project.fuxap.db"

echo "[backup] copying OpenPLC database..."
docker compose cp openplc:/root/OpenPLC_v3/webserver/openplc.db "${BACKUP_DIR}/openplc.db"

echo "[backup] copying OpenPLC active program pointer..."
docker compose cp openplc:/root/OpenPLC_v3/webserver/active_program "${BACKUP_DIR}/active_program"

ACTIVE_PROGRAM_FILE="$(tr -d '\r\n' < "${BACKUP_DIR}/active_program" || true)"
if [[ -n "${ACTIVE_PROGRAM_FILE}" ]]; then
  echo "[backup] active ST file: ${ACTIVE_PROGRAM_FILE}"
  docker compose cp "openplc:/root/OpenPLC_v3/webserver/st_files/${ACTIVE_PROGRAM_FILE}" "${BACKUP_DIR}/openplc_active_program.st" || true
fi

echo "[backup] copying OpenPLC generated variable map..."
docker compose cp openplc:/root/OpenPLC_v3/webserver/core/VARIABLES.csv "${BACKUP_DIR}/openplc_variables.csv" || true

cat > "${BACKUP_DIR}/README.txt" <<EOF
OT Lab v2 backup snapshot
Timestamp: ${STAMP}

Files:
- fuxa_project.json           -> FUXA import/export JSON (views + devices + tags)
- project.fuxap.db            -> FUXA full project database
- openplc.db                  -> OpenPLC runtime database
- active_program              -> active ST filename reference
- openplc_active_program.st   -> active ST source file (if found)
- openplc_variables.csv       -> OpenPLC generated variable map

Restore notes:
1) FUXA JSON restore:
   curl -X POST http://localhost:1881/api/project \\
     -H "Content-Type: application/json" \\
     --data-binary @fuxa_project.json

2) OpenPLC logic restore:
   Upload openplc_active_program.st (or your chosen .st) in OpenPLC web UI,
   then compile and start PLC.
EOF

echo "[backup] done."
echo "[backup] created files:"
ls -lh "${BACKUP_DIR}"
