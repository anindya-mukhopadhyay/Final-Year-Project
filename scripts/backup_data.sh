#!/usr/bin/env bash
# ============================================================
# AnswerChain Data Backup Utility (Phase 8)
# Creates a timestamped local backup of blockchain state,
# audit logs, and configuration without committing to Git.
# ============================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

BACKUP_TIMESTAMP="$(date +"%Y%m%d_%H%M%S")"
BACKUP_DIR="${PROJECT_ROOT}/backups/backup_${BACKUP_TIMESTAMP}"

mkdir -p "${BACKUP_DIR}/blockchain_data"
mkdir -p "${BACKUP_DIR}/data"
mkdir -p "${BACKUP_DIR}/config"

echo "=== AnswerChain System Backup ==="
echo "Target Backup Directory: ${BACKUP_DIR}"

# 1. Backup Blockchain Data
if compgen -G "${PROJECT_ROOT}/blockchain_data/*.json" > /dev/null; then
    cp -v "${PROJECT_ROOT}/blockchain_data"/*.json "${BACKUP_DIR}/blockchain_data/"
    echo "✓ Blockchain ledger files backed up."
else
    echo "! No blockchain files found in ${PROJECT_ROOT}/blockchain_data/"
fi

# 2. Backup Audit Logs
if [ -f "${PROJECT_ROOT}/data/audit_log.json" ]; then
    cp -v "${PROJECT_ROOT}/data/audit_log.json" "${BACKUP_DIR}/data/"
    echo "✓ Operational audit log backed up."
fi

if [ -f "${PROJECT_ROOT}/data/scripts_meta.json" ]; then
    cp -v "${PROJECT_ROOT}/data/scripts_meta.json" "${BACKUP_DIR}/data/"
    echo "✓ Scripts metadata backed up."
fi

# 3. Backup Configuration
if [ -f "${PROJECT_ROOT}/.env" ]; then
    cp -v "${PROJECT_ROOT}/.env" "${BACKUP_DIR}/config/"
    echo "✓ Environment configuration (.env) backed up."
fi
if [ -f "${PROJECT_ROOT}/.env.example" ]; then
    cp -v "${PROJECT_ROOT}/.env.example" "${BACKUP_DIR}/config/"
fi

# 4. Generate Checksums
echo "Generating SHA-256 manifest..."
if command -v shasum > /dev/null; then
    (cd "${BACKUP_DIR}" && find . -type f ! -name "manifest.sha256" -exec shasum -a 256 {} + > manifest.sha256)
elif command -v sha256sum > /dev/null; then
    (cd "${BACKUP_DIR}" && find . -type f ! -name "manifest.sha256" -exec sha256sum {} + > manifest.sha256)
fi

echo "=========================================="
echo "Backup Completed Successfully at: ${BACKUP_DIR}"
echo "Manifest: ${BACKUP_DIR}/manifest.sha256"
echo "=========================================="
