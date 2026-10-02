"""
AnswerChain Operational Audit Logging Service.

Maintains an off-chain operational audit trail for compliance, forensic tracing,
and administrative oversight without polluting the immutable public ledger with
private operational logs.
"""

import json
import os
import time
from typing import Any, Dict, List, Optional

PROJECT_ROOT = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..")
)

AUDIT_DIR = os.path.join(PROJECT_ROOT, "data")
os.makedirs(AUDIT_DIR, exist_ok=True)
AUDIT_FILE = os.path.join(AUDIT_DIR, "audit_log.json")

# In-memory buffer of audit events
_AUDIT_LOG: List[Dict[str, Any]] = []

def _load_audit_log() -> None:
    global _AUDIT_LOG
    if os.path.exists(AUDIT_FILE):
        try:
            with open(AUDIT_FILE, "r", encoding="utf-8") as f:
                loaded = json.load(f)
                if isinstance(loaded, list):
                    _AUDIT_LOG = loaded
        except Exception:
            _AUDIT_LOG = []

def _save_audit_log() -> None:
    try:
        temp_file = f"{AUDIT_FILE}.tmp"
        with open(temp_file, "w", encoding="utf-8") as f:
            json.dump(_AUDIT_LOG, f, indent=2, ensure_ascii=False)
        os.replace(temp_file, AUDIT_FILE)
    except Exception:
        pass

# Initialize on module import
_load_audit_log()

def log_audit_event(
    action: str,
    actor: str,
    actor_role: str,
    resource_id: Optional[str] = None,
    transaction_id: Optional[str] = None,
    status: str = "SUCCESS",
    reason: Optional[str] = None,
    details: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Append an operational security audit record.
    Sanitizes details to ensure no passwords or private keys are persisted.
    """
    _load_audit_log()

    # Sanitize details (remove any accidental password, token, or private key fields)
    sanitized_details: Dict[str, Any] = {}
    if details and isinstance(details, dict):
        for k, v in details.items():
            k_lower = k.lower()
            if any(s in k_lower for s in ("password", "private_key", "secret", "token")):
                sanitized_details[k] = "[REDACTED]"
            else:
                sanitized_details[k] = v

    normalized_status = status.upper()
    event = {
        "id": f"AUD-{int(time.time() * 1000)}-{len(_AUDIT_LOG) + 1}",
        "timestamp": time.time(),
        "action": action.upper(),
        "actor": actor,
        "actor_id": actor,
        "actor_role": actor_role.upper(),
        "resource_id": resource_id or "—",
        "transaction_id": transaction_id or "—",
        "status": normalized_status,
        "result": normalized_status,
        "reason": reason or ("—" if normalized_status == "SUCCESS" else "Operation failed"),
        "details": sanitized_details,
    }
    _AUDIT_LOG.append(event)
    _save_audit_log()
    return event

def get_audit_events(
    limit: int = 50,
    action: Optional[str] = None,
    actor: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Return filtered and chronologically descending audit records."""
    _load_audit_log()
    filtered = _AUDIT_LOG
    if action:
        filtered = [e for e in filtered if e.get("action") == action]
    if actor:
        filtered = [e for e in filtered if e.get("actor") == actor]

    # Return newest first
    return list(reversed(filtered))[:limit]
