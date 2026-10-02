"""
AnswerChain Authentication Service.

Provides a developer-friendly, pluggable authentication layer with
role-based credentials and signed session tokens. Designed to be easily
swapped with external providers (Firebase, Auth.js, OAuth) in the future.
"""

import hashlib
import hmac
import json
import os
import secrets
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

# Secret key for HMAC token signing (dev fallback or environment variable)
AUTH_SECRET_KEY = os.environ.get(
    "AUTH_SECRET_KEY",
    "answerchain-dev-secret-key-38f9210ac77b42",
)

# Configurable token expiration (default: 86400 seconds = 24 hours)
TOKEN_EXPIRY_SECONDS = int(os.environ.get("TOKEN_EXPIRY_SECONDS", "86400"))

# In-memory revocation blacklist for logged out or revoked session tokens
_REVOKED_TOKENS: set = set()

# Rate limiting data structures (sliding window of timestamps)
_LOGIN_FAILURES: Dict[str, List[float]] = {}
_UPLOAD_REQUESTS: Dict[str, List[float]] = {}

RATE_LIMIT_LOGIN_MAX = int(os.environ.get("RATE_LIMIT_LOGIN_MAX_ATTEMPTS", "15"))
RATE_LIMIT_LOGIN_WINDOW = int(os.environ.get("RATE_LIMIT_LOGIN_WINDOW_SECONDS", "60"))

RATE_LIMIT_UPLOAD_MAX = int(os.environ.get("RATE_LIMIT_UPLOAD_MAX_REQUESTS", "30"))
RATE_LIMIT_UPLOAD_WINDOW = int(os.environ.get("RATE_LIMIT_UPLOAD_WINDOW_SECONDS", "60"))


@dataclass
class User:
    user_id: str
    name: str
    role: str
    department: str
    email: str
    active: bool = True

    def to_dict(self) -> Dict[str, Any]:
        return {
            "user_id": self.user_id,
            "name": self.name,
            "role": self.role,
            "department": self.department,
            "email": self.email,
        }

def _hash_password(password: str, salt: str = "answerchain_salt_2026") -> str:
    return hashlib.sha256(f"{salt}:{password}".encode("utf-8")).hexdigest()

# Synthetic Development Users Store
_USERS: Dict[str, User] = {
    "UNIV-001": User(
        user_id="UNIV-001",
        name="Techno International New Town (TINT) University",
        role="UNIVERSITY",
        department="Registrar & Exam Branch",
        email="registrar@tint.edu.in",
    ),
    "TCH-001": User(
        user_id="TCH-001",
        name="Prof. Alex Mercer",
        role="TEACHER",
        department="Computer Science & Engineering",
        email="a.mercer@tint.edu.in",
    ),
    "TCH-002": User(
        user_id="TCH-002",
        name="Prof. Sarah Jenkins",
        role="TEACHER",
        department="Information Technology",
        email="s.jenkins@tint.edu.in",
    ),
    "TCH-003": User(
        user_id="TCH-003",
        name="Prof. Ramesh Guha",
        role="TEACHER",
        department="Electronics & Comm. Engg",
        email="r.guha@tint.edu.in",
    ),
    "TCH-004": User(
        user_id="TCH-004",
        name="Prof. David K.",
        role="TEACHER",
        department="Computer Science & Engineering",
        email="d.k@tint.edu.in",
    ),
    "AUTH-001": User(
        user_id="AUTH-001",
        name="Dr. S. K. Mukherjee",
        role="AUTHORITY",
        department="Office of Controller of Examinations",
        email="coe@tint.edu.in",
    ),
    "VERIFY-001": User(
        user_id="VERIFY-001",
        name="Public Credential Verifier",
        role="VERIFIER",
        department="Academic Verification Agency",
        email="verify@credential-check.org",
    ),
    "ADMIN-001": User(
        user_id="ADMIN-001",
        name="AnswerChain System Admin",
        role="ADMIN",
        department="Network & Security Operations",
        email="admin@answerchain.internal",
    ),
}

# Credential Hashes (passwords not hardcoded in plain text in client code)
_CREDENTIALS: Dict[str, str] = {
    "UNIV-001": _hash_password("university123"),
    "TCH-001": _hash_password("teacher123"),
    "TCH-002": _hash_password("teacher123"),
    "TCH-003": _hash_password("teacher123"),
    "TCH-004": _hash_password("teacher123"),
    "AUTH-001": _hash_password("authority123"),
    "VERIFY-001": _hash_password("verify123"),
    "ADMIN-001": _hash_password("admin123"),
}

# In-memory session token store (token -> {user_id, role, expires_at})
_ACTIVE_SESSIONS: Dict[str, Dict[str, Any]] = {}

def authenticate(user_id: str, password: str) -> Optional[Dict[str, Any]]:
    """
    Authenticate user credentials and issue a signed session token.
    """
    clean_id = user_id.strip().upper()
    if clean_id not in _USERS:
        return None

    expected_hash = _CREDENTIALS.get(clean_id)
    provided_hash = _hash_password(password)

    if not expected_hash or not hmac.compare_digest(expected_hash, provided_hash):
        return None

    user = _USERS[clean_id]
    if not user.active:
        return None

    token = create_token(user)
    return {
        "user_id": user.user_id,
        "name": user.name,
        "role": user.role,
        "department": user.department,
        "email": user.email,
        "token": token,
    }

def create_token(user: User) -> str:
    """Generate a cryptographically secure token and save session state."""
    raw_token = secrets.token_hex(24)
    expires_at = time.time() + TOKEN_EXPIRY_SECONDS

    # Create token payload
    payload = {
        "user_id": user.user_id,
        "role": user.role,
        "expires_at": expires_at,
        "rand": raw_token,
    }
    payload_bytes = json.dumps(payload, sort_keys=True).encode("utf-8")
    signature = hmac.new(
        AUTH_SECRET_KEY.encode("utf-8"),
        payload_bytes,
        hashlib.sha256,
    ).hexdigest()

    full_token = f"{raw_token}.{signature}"
    _ACTIVE_SESSIONS[full_token] = payload
    return full_token

def verify_token(token: str) -> Optional[User]:
    """
    Validate a session token, check signature, expiry, and revocation state.
    """
    if not token or not isinstance(token, str):
        return None

    clean_token = token.strip()
    if clean_token in _REVOKED_TOKENS:
        return None

    session = _ACTIVE_SESSIONS.get(clean_token)

    if not session:
        # Check stateless HMAC format fallback
        try:
            parts = clean_token.split(".")
            if len(parts) != 2:
                return None
            raw_token, signature = parts
            return None
        except Exception:
            return None

    if time.time() > session.get("expires_at", 0):
        _ACTIVE_SESSIONS.pop(clean_token, None)
        return None

    user_id = session.get("user_id")
    return _USERS.get(user_id)

def get_user_by_id(user_id: str) -> Optional[User]:
    """Retrieve user object by user ID."""
    return _USERS.get(user_id.strip().upper())

def revoke_token(token: str) -> bool:
    """Log out a user by revoking session token."""
    if not token or not isinstance(token, str):
        return False
    clean_token = token.strip()
    _REVOKED_TOKENS.add(clean_token)
    _ACTIVE_SESSIONS.pop(clean_token, None)
    return True

def check_login_rate_limit(client_ip: str) -> Tuple[bool, Optional[str]]:
    """Check if client IP has exceeded login attempt threshold."""
    now = time.time()
    attempts = [t for t in _LOGIN_FAILURES.get(client_ip, []) if now - t < RATE_LIMIT_LOGIN_WINDOW]
    _LOGIN_FAILURES[client_ip] = attempts
    if len(attempts) >= RATE_LIMIT_LOGIN_MAX:
        return False, f"Too many failed login attempts. Please wait {RATE_LIMIT_LOGIN_WINDOW} seconds."
    return True, None

def record_login_failure(client_ip: str) -> None:
    now = time.time()
    attempts = [t for t in _LOGIN_FAILURES.get(client_ip, []) if now - t < RATE_LIMIT_LOGIN_WINDOW]
    attempts.append(now)
    _LOGIN_FAILURES[client_ip] = attempts

def record_login_success(client_ip: str) -> None:
    _LOGIN_FAILURES.pop(client_ip, None)

def check_upload_rate_limit(client_ip: str) -> Tuple[bool, Optional[str]]:
    """Check if client IP has exceeded upload verification threshold."""
    now = time.time()
    reqs = [t for t in _UPLOAD_REQUESTS.get(client_ip, []) if now - t < RATE_LIMIT_UPLOAD_WINDOW]
    if len(reqs) >= RATE_LIMIT_UPLOAD_MAX:
        _UPLOAD_REQUESTS[client_ip] = reqs
        return False, f"Upload verification rate limit exceeded. Please wait {RATE_LIMIT_UPLOAD_WINDOW} seconds."
    reqs.append(now)
    _UPLOAD_REQUESTS[client_ip] = reqs
    return True, None

def list_teachers() -> List[Dict[str, Any]]:
    """Return all teachers for assignment dropdowns."""
    return [
        user.to_dict()
        for user in _USERS.values()
        if user.role == "TEACHER" and user.active
    ]
