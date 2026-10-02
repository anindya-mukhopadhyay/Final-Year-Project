#!/usr/bin/env bash
# ============================================================
# AnswerChain Data Restore Utility (Phase 8)
# Restores blockchain state and audit logs from a backup folder.
# Usage: ./scripts/restore_data.sh <path_to_backup_folder>
# ============================================================

set -euo pipefail

if [ "$#" -lt 1 ]; then
    echo "Usage: $0 <path_to_backup_dir>"
    echo "Example: $0 backups/backup_20261002_064556"
    exit 1
fi

BACKUP_SOURCE="$1"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

if [ ! -d "${BACKUP_SOURCE}" ]; then
    echo "Error: Backup directory '${BACKUP_SOURCE}' does not exist."
    exit 1
fi

echo "=== AnswerChain System Restore ==="
echo "Source: ${BACKUP_SOURCE}"
echo "Target: ${PROJECT_ROOT}"

# Verify manifest if present
if [ -f "${BACKUP_SOURCE}/manifest.sha256" ]; then
    echo "Verifying backup integrity with SHA-256 manifest..."
    if command -v shasum > /dev/null; then
        (cd "${BACKUP_SOURCE}" && shasum -a 256 -c manifest.sha256)
    elif command -v sha256sum > /dev/null; then
        (cd "${BACKUP_SOURCE}" && sha256sum -c manifest.sha256)
    fi
    echo "✓ Integrity verification passed."
fi

# Restore Blockchain Data
if [ -d "${BACKUP_SOURCE}/blockchain_data" ]; then
    mkdir -p "${PROJECT_ROOT}/blockchain_data"
    cp -v "${BACKUP_SOURCE}/blockchain_data"/*.json "${PROJECT_ROOT}/blockchain_data/"
    echo "✓ Blockchain ledger files restored."
fi

# Restore Audit Logs
if [ -f "${BACKUP_SOURCE}/data/audit_log.json" ]; then
    mkdir -p "${PROJECT_ROOT}/data"
    cp -v "${BACKUP_SOURCE}/data/audit_log.json" "${PROJECT_ROOT}/data/"
    echo "✓ Operational audit log restored."
fi

echo "=========================================="
echo "Restore Completed Successfully."
echo "Please verify cluster synchronization via /network."
echo "=========================================="
