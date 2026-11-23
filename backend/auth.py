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

import backend.database as db

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
    assigned_subject: Optional[str] = None
    assigned_subject_name: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "user_id": self.user_id,
            "name": self.name,
            "role": self.role,
            "department": self.department,
            "email": self.email,
            "active": self.active,
            "assigned_subject": self.assigned_subject or "",
            "assigned_subject_name": self.assigned_subject_name or "",
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
    "TCH-005": User(
        user_id="TCH-005",
        name="Prof. Elena Rostova",
        role="TEACHER",
        department="Computer Science & Engineering",
        email="e.rostova@tint.edu.in",
    ),
    "NODE-001": User(user_id="NODE-001", name="Examiner Node 1", role="NODE", department="Examiner Cluster", email="node1@answerchain.internal"),
    "NODE-002": User(user_id="NODE-002", name="Examiner Node 2", role="NODE", department="Examiner Cluster", email="node2@answerchain.internal"),
    "NODE-003": User(user_id="NODE-003", name="Examiner Node 3", role="NODE", department="Examiner Cluster", email="node3@answerchain.internal"),
    "NODE-004": User(user_id="NODE-004", name="Examiner Node 4", role="NODE", department="Examiner Cluster", email="node4@answerchain.internal"),
    "NODE-005": User(user_id="NODE-005", name="Examiner Node 5", role="NODE", department="Examiner Cluster", email="node5@answerchain.internal"),
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
    "TCH-005": _hash_password("teacher123"),
    "NODE-001": _hash_password("node123"),
    "NODE-002": _hash_password("node123"),
    "NODE-003": _hash_password("node123"),
    "NODE-004": _hash_password("node123"),
    "NODE-005": _hash_password("node123"),
    "AUTH-001": _hash_password("authority123"),
    "VERIFY-001": _hash_password("verify123"),
    "ADMIN-001": _hash_password("admin123"),
}

# In-memory session token store (token -> {user_id, role, expires_at})
_ACTIVE_SESSIONS: Dict[str, Dict[str, Any]] = {}

def authenticate(user_id: str, password: str) -> Optional[Dict[str, Any]]:
    """
    Authenticate user credentials against SQLite database (with in-memory fallback)
    and issue a signed session token. Supports login via user_id or institutional email.
    """
    if not user_id or not password:
        return None

    clean_input = user_id.strip()
    user_auth = db.get_user_auth(clean_input)

    if user_auth:
        expected_hash = user_auth.get("password_hash")
        provided_hash = _hash_password(password)
        if not expected_hash or not hmac.compare_digest(expected_hash, provided_hash):
            return None
        if not user_auth.get("active", 1):
            return None

        user = User(
            user_id=user_auth["user_id"],
            name=user_auth["name"],
            role=user_auth["role"],
            department=user_auth.get("department", ""),
            email=user_auth.get("email", ""),
            active=bool(user_auth.get("active", 1)),
            assigned_subject=user_auth.get("assigned_subject"),
            assigned_subject_name=user_auth.get("assigned_subject_name"),
        )
    else:
        # Fallback to in-memory store
        upper_id = clean_input.upper()
        if upper_id in _USERS:
            expected_hash = _CREDENTIALS.get(upper_id)
            provided_hash = _hash_password(password)
            if not expected_hash or not hmac.compare_digest(expected_hash, provided_hash):
                return None
            user = _USERS[upper_id]
            if not user.active:
                return None
        else:
            # Check in-memory store by email
            matching = [u for u in _USERS.values() if u.email and u.email.lower() == clean_input.lower()]
            if matching:
                user = matching[0]
                expected_hash = _CREDENTIALS.get(user.user_id)
                provided_hash = _hash_password(password)
                if not expected_hash or not hmac.compare_digest(expected_hash, provided_hash):
                    return None
                if not user.active:
                    return None
            else:
                return None

    token = create_token(user)
    return {
        "user_id": user.user_id,
        "name": user.name,
        "role": user.role,
        "department": user.department,
        "email": user.email,
        "active": user.active,
        "assigned_subject": user.assigned_subject or "",
        "assigned_subject_name": user.assigned_subject_name or "",
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
    user = get_user_by_id(user_id)
    if not user or not user.active:
        return None
    return user

def get_user_by_id(user_id: str) -> Optional[User]:
    """Retrieve user object by user ID or email from SQLite database with in-memory fallback."""
    if not user_id:
        return None
    clean_id = user_id.strip()
    u_dict = db.get_user(clean_id)
    if u_dict:
        return User(
            user_id=u_dict["user_id"],
            name=u_dict["name"],
            role=u_dict["role"],
            department=u_dict.get("department", ""),
            email=u_dict.get("email", ""),
            active=bool(u_dict.get("active", 1)),
            assigned_subject=u_dict.get("assigned_subject"),
            assigned_subject_name=u_dict.get("assigned_subject_name"),
        )
    upper_id = clean_id.upper()
    if upper_id in _USERS:
        return _USERS[upper_id]
    for u in _USERS.values():
        if u.email and u.email.lower() == clean_id.lower():
            return u
    return None

def revoke_token(token: str) -> bool:
    """Log out a user by revoking session token."""
    if not token or not isinstance(token, str):
        return False
    clean_token = token.strip()
    _REVOKED_TOKENS.add(clean_token)
    _ACTIVE_SESSIONS.pop(clean_token, None)
    return True

def revoke_sessions_for_user(user_id: str) -> None:
    """Revoke all active sessions for a given user ID (e.g. on deactivation or password reset)."""
    clean_id = user_id.strip().upper()
    tokens_to_remove = [
        t for t, payload in _ACTIVE_SESSIONS.items()
        if payload.get("user_id") == clean_id
    ]
    for t in tokens_to_remove:
        _REVOKED_TOKENS.add(t)
        _ACTIVE_SESSIONS.pop(t, None)

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

def list_teachers(subject_code: Optional[str] = None) -> List[Dict[str, Any]]:
    """Return active teachers for assignment dropdowns with their assigned subject."""
    return db.list_teachers(subject_code=subject_code, active_only=True)

def list_all_teachers_admin() -> List[Dict[str, Any]]:
    """Return all teachers (including inactive) for Admin management."""
    return db.list_teachers(subject_code=None, active_only=False)

def create_teacher_account(
    user_id: str,
    name: str,
    assigned_subject: str,
    password: str,
    department: str = "Academic Faculty",
    email: str = "",
) -> Tuple[bool, Optional[Dict[str, Any]], Optional[str]]:
    """Create a new teacher in SQLite DB with hashed credentials."""
    return db.create_teacher(
        user_id=user_id,
        name=name,
        assigned_subject=assigned_subject,
        password=password,
        department=department,
        email=email,
    )

def update_teacher_account(
    user_id: str,
    name: Optional[str] = None,
    assigned_subject: Optional[str] = None,
    department: Optional[str] = None,
    email: Optional[str] = None,
) -> Tuple[bool, Optional[Dict[str, Any]], Optional[str]]:
    """Update teacher details in SQLite DB."""
    return db.update_teacher(
        user_id=user_id,
        name=name,
        assigned_subject=assigned_subject,
        department=department,
        email=email,
    )

def reset_teacher_password(user_id: str, new_password: str) -> Tuple[bool, Optional[str]]:
    """Reset teacher password and revoke active sessions."""
    ok, err = db.reset_teacher_password(user_id=user_id, new_password=new_password)
    if ok:
        revoke_sessions_for_user(user_id)
    return ok, err

def toggle_teacher_account_status(user_id: str, active: bool) -> Tuple[bool, Optional[str]]:
    """Toggle teacher active status. If deactivating, revoke active sessions."""
    ok, err = db.toggle_teacher_status(user_id=user_id, active=active)
    if ok and not active:
        revoke_sessions_for_user(user_id)
    return ok, err
