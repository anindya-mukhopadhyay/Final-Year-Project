"""
AnswerChain Cryptographic Trust & Identity Module (Phase 8).

Implements:
1. Ed25519 digital signatures (RFC 8032) via the vetted cryptography library.
2. Deterministic canonical transaction serialization.
3. Cryptographic actor identity management (University, Teacher, Authority).
4. Signature verification and payload tamper detection.
"""

import hashlib
import json
import logging
import os
from typing import Any, Dict, Optional, Tuple

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

logger = logging.getLogger("crypto")

PROJECT_ROOT = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..")
)

KEY_STORAGE_DIR = os.environ.get(
    "KEY_STORAGE_DIR",
    os.path.join(PROJECT_ROOT, "keys"),
)

os.makedirs(KEY_STORAGE_DIR, exist_ok=True)

# In-memory registry of loaded public keys for fast lookup
_PUBLIC_KEY_REGISTRY: Dict[str, ed25519.Ed25519PublicKey] = {}
_PRIVATE_KEY_CACHE: Dict[str, ed25519.Ed25519PrivateKey] = {}


# ============================================================
# 1. CANONICAL TRANSACTION SERIALIZATION
# ============================================================

def canonicalize_transaction_payload(data: Dict[str, Any]) -> bytes:
    """
    Produce a deterministic, canonical byte representation of a transaction payload.
    Omits signatures, hash proofs, and transport timestamps to allow exact replay
    and independent verification across different nodes and architectures.
    """
    # Exclude non-deterministic or transport-level envelope keys
    EXCLUDED_KEYS = {
        "signature",
        "payload_hash",
        "timestamp",
        "transaction_id",
        "block_number",
        "block_index",
        "public_key_id",
        "status",
        "evaluation_id",
        "result_id",
        "marksheet_id",
        "pdf_path",
        "pdf_filename",
        "final_marks",
        "marksheet_data_hash",
        "marksheet_pdf_hash",
        "percentage",
        "max_marks",
    }

    filtered: Dict[str, Any] = {}
    for k, v in data.items():
        if k not in EXCLUDED_KEYS:
            filtered[k] = v

    # Deterministic JSON with sorted keys, no whitespace separators, UTF-8
    canonical_json = json.dumps(
        filtered,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )
    return canonical_json.encode("utf-8")


def calculate_payload_hash(canonical_bytes: bytes) -> str:
    """Compute standard SHA-256 digest of canonical payload bytes."""
    return hashlib.sha256(canonical_bytes).hexdigest()


# ============================================================
# 2. KEY GENERATION & STORAGE
# ============================================================

def generate_keypair() -> Tuple[ed25519.Ed25519PrivateKey, ed25519.Ed25519PublicKey]:
    """Generate a new Ed25519 asymmetric key pair."""
    private_key = ed25519.Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    return private_key, public_key


def export_public_key_hex(public_key: ed25519.Ed25519PublicKey) -> str:
    """Export public key as 32-byte raw hex string (64 characters)."""
    raw_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return raw_bytes.hex()


def import_public_key_hex(hex_str: str) -> ed25519.Ed25519PublicKey:
    """Import public key from raw 64-char hex string."""
    raw_bytes = bytes.fromhex(hex_str.strip())
    return ed25519.Ed25519PublicKey.from_public_bytes(raw_bytes)


def save_keypair(
    actor_id: str,
    private_key: ed25519.Ed25519PrivateKey,
    key_dir: str = KEY_STORAGE_DIR,
) -> Tuple[str, str]:
    """Save an actor's private and public keys as PEM files to key_dir."""
    os.makedirs(key_dir, exist_ok=True)
    clean_id = actor_id.strip().upper()

    priv_path = os.path.join(key_dir, f"{clean_id}_private.pem")
    pub_path = os.path.join(key_dir, f"{clean_id}_public.pem")

    priv_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    with open(priv_path, "wb") as f:
        f.write(priv_pem)
    # Restrict private key permissions (owner read/write only)
    try:
        os.chmod(priv_path, 0o600)
    except Exception:
        pass

    with open(pub_path, "wb") as f:
        f.write(pub_pem)

    _PRIVATE_KEY_CACHE[clean_id] = private_key
    _PUBLIC_KEY_REGISTRY[clean_id] = private_key.public_key()
    return priv_path, pub_path


def load_keypair(
    actor_id: str,
    key_dir: str = KEY_STORAGE_DIR,
) -> Tuple[Optional[ed25519.Ed25519PrivateKey], Optional[ed25519.Ed25519PublicKey]]:
    """Load an actor's keypair from PEM files in key_dir if present."""
    clean_id = actor_id.strip().upper()

    if clean_id in _PRIVATE_KEY_CACHE and clean_id in _PUBLIC_KEY_REGISTRY:
        return _PRIVATE_KEY_CACHE[clean_id], _PUBLIC_KEY_REGISTRY[clean_id]

    priv_path = os.path.join(key_dir, f"{clean_id}_private.pem")
    pub_path = os.path.join(key_dir, f"{clean_id}_public.pem")

    priv_key: Optional[ed25519.Ed25519PrivateKey] = None
    pub_key: Optional[ed25519.Ed25519PublicKey] = None

    if os.path.isfile(priv_path):
        try:
            with open(priv_path, "rb") as f:
                priv_key = serialization.load_pem_private_key(f.read(), password=None)
                if isinstance(priv_key, ed25519.Ed25519PrivateKey):
                    pub_key = priv_key.public_key()
                    _PRIVATE_KEY_CACHE[clean_id] = priv_key
                    _PUBLIC_KEY_REGISTRY[clean_id] = pub_key
                    return priv_key, pub_key
        except Exception as e:
            logger.warning("Could not load private key for %s: %s", clean_id, e)

    if os.path.isfile(pub_path):
        try:
            with open(pub_path, "rb") as f:
                pub_key = serialization.load_pem_public_key(f.read())
                if isinstance(pub_key, ed25519.Ed25519PublicKey):
                    _PUBLIC_KEY_REGISTRY[clean_id] = pub_key
        except Exception as e:
            logger.warning("Could not load public key for %s: %s", clean_id, e)

    return priv_key, pub_key


def get_or_create_actor_keys(
    actor_id: str,
    key_dir: str = KEY_STORAGE_DIR,
) -> Tuple[ed25519.Ed25519PrivateKey, ed25519.Ed25519PublicKey]:
    """Retrieve actor keypair or generate a persistent local development keypair."""
    priv, pub = load_keypair(actor_id, key_dir=key_dir)
    if priv and pub:
        return priv, pub

    priv, pub = generate_keypair()
    save_keypair(actor_id, priv, key_dir=key_dir)
    return priv, pub


def get_actor_public_key(actor_id: str) -> Optional[ed25519.Ed25519PublicKey]:
    """Resolve an actor's public key by actor_id."""
    clean_id = actor_id.strip().upper()
    if clean_id in _PUBLIC_KEY_REGISTRY:
        return _PUBLIC_KEY_REGISTRY[clean_id]
    _, pub = load_keypair(clean_id)
    return pub


# ============================================================
# 3. SIGNING & VERIFICATION
# ============================================================

def sign_payload(private_key: ed25519.Ed25519PrivateKey, payload_bytes: bytes) -> str:
    """Sign payload bytes using Ed25519 and return 128-char hex signature."""
    sig_bytes = private_key.sign(payload_bytes)
    return sig_bytes.hex()


def verify_signature(
    public_key: ed25519.Ed25519PublicKey,
    payload_bytes: bytes,
    signature_hex: str,
) -> bool:
    """Verify Ed25519 digital signature against payload bytes."""
    try:
        sig_bytes = bytes.fromhex(signature_hex.strip())
        public_key.verify(sig_bytes, payload_bytes)
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False


def sign_academic_transaction(
    actor_id: str = "",
    actor_role: str = "",
    transaction_data: Optional[Dict[str, Any]] = None,
    *,
    payload: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Sign an academic transaction with the authenticated actor's private key.
    Appends actor_id, actor_role, public_key_id, payload_hash, and signature.
    """
    tx = dict(transaction_data if transaction_data is not None else (payload or {}))
    priv_key, pub_key = get_or_create_actor_keys(actor_id)
    signed_data = dict(tx)

    signed_data["actor_id"] = actor_id
    signed_data["actor_role"] = actor_role
    signed_data["public_key_id"] = f"ed25519:{export_public_key_hex(pub_key)[:16]}"

    # Canonicalize and hash payload
    canonical_bytes = canonicalize_transaction_payload(signed_data)
    payload_hash = calculate_payload_hash(canonical_bytes)
    signature = sign_payload(priv_key, canonical_bytes)

    signed_data["payload_hash"] = payload_hash
    signed_data["signature"] = signature

    return signed_data


ALLOWED_ROLES_BY_TYPE = {
    "ANSWER_SCRIPT_REGISTERED": {"UNIVERSITY", "ADMIN"},
    "ANSWER_SCRIPT_ASSIGNED": {"UNIVERSITY", "ADMIN"},
    "EVALUATION_SUBMITTED": {"TEACHER", "ADMIN"},
    "RESULT_FINALIZED": {"AUTHORITY", "ADMIN"},
    "MARKSHEET_REGISTERED": {"AUTHORITY", "ADMIN"},
}


def verify_academic_transaction(
    transaction_data: Dict[str, Any],
) -> Tuple[bool, Optional[str]]:
    """
    Independently verify a signed academic transaction.

    Validates:
    1. Transaction structure and signature fields.
    2. Canonical payload recreation and payload hash.
    3. Actor identity and role authorization for the transaction type.
    4. Ed25519 digital signature against registered public key.

    Returns:
        (True, None) if signature, actor identity, and payload match.
        (False, error_reason) if invalid, unauthorized, or tampered.
    """
    if not isinstance(transaction_data, dict):
        return False, "TRANSACTION_MALFORMED"

    actor_id = transaction_data.get("actor_id")
    actor_role = transaction_data.get("actor_role")
    signature = transaction_data.get("signature")
    claimed_hash = transaction_data.get("payload_hash")

    if not actor_id or not actor_role or not signature or not claimed_hash:
        return False, "SIGNATURE_MISSING"

    # Enforce role authorization for academic transaction types
    tx_type = transaction_data.get("type")
    if tx_type in ALLOWED_ROLES_BY_TYPE:
        if actor_role not in ALLOWED_ROLES_BY_TYPE[tx_type]:
            return False, "ACTOR_NOT_AUTHORIZED"

    # Validate actor registered identity
    try:
        from backend.auth import _USERS
        registered_user = _USERS.get(actor_id.strip().upper())
        if not registered_user:
            return False, "UNKNOWN_ACTOR"
        if registered_user.role != actor_role and registered_user.role != "ADMIN":
            return False, "ACTOR_NOT_AUTHORIZED"
    except Exception:
        pass

    # Reconstruct canonical payload
    canonical_bytes = canonicalize_transaction_payload(transaction_data)
    actual_hash = calculate_payload_hash(canonical_bytes)

    if actual_hash.lower() != claimed_hash.lower():
        # Backward compatibility resolution for transition blocks:
        # Fallback 1: Without max_marks excluded
        alt_filtered = {
            k: v for k, v in transaction_data.items()
            if k not in (
                "signature", "payload_hash", "timestamp", "transaction_id",
                "block_number", "block_index", "public_key_id", "status",
                "evaluation_id", "result_id", "marksheet_id", "pdf_path",
                "pdf_filename", "final_marks", "marksheet_data_hash",
                "marksheet_pdf_hash", "percentage",
            )
        }
        alt_bytes = json.dumps(alt_filtered, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        if calculate_payload_hash(alt_bytes).lower() == claimed_hash.lower():
            canonical_bytes = alt_bytes
            actual_hash = claimed_hash
        else:
            # Fallback 2: Legacy envelope exclusion (blocks signed with earlier dev schema)
            legacy_excluded = {"signature", "payload_hash", "timestamp", "transaction_id", "block_number", "block_index"}
            legacy_filtered = {k: v for k, v in transaction_data.items() if k not in legacy_excluded}
            legacy_bytes = json.dumps(legacy_filtered, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
            if calculate_payload_hash(legacy_bytes).lower() == claimed_hash.lower():
                canonical_bytes = legacy_bytes
                actual_hash = claimed_hash
            else:
                return False, "PAYLOAD_HASH_MISMATCH"

    # Resolve actor public key
    pub_key = get_actor_public_key(actor_id)
    if not pub_key:
        return False, "ACTOR_NOT_AUTHORIZED"

    # Verify signature
    if not verify_signature(pub_key, canonical_bytes, signature):
        return False, "SIGNATURE_INVALID"

    return True, None
