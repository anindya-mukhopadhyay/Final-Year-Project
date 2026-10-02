"""
AnswerChain Authorization Middleware & Decorators.

Enforces server-side role-based access control (RBAC).
Endpoints cannot be accessed merely by manipulating client-side state.
"""

from functools import wraps
from typing import Any, Callable, List, Union

from flask import g, jsonify, request

from backend.auth import User, verify_token

def extract_token_from_request() -> str:
    """Extract Bearer token from Authorization header or cookie/query."""
    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Bearer "):
        return auth_header[7:].strip()
    # Support cookie or query param for downloads (e.g. PDF link)
    if "token" in request.args:
        return request.args.get("token", "").strip()
    return request.cookies.get("answerchain_token", "").strip()

def require_auth(f: Callable) -> Callable:
    """
    Decorator requiring a valid active session token.
    Populates Flask request context `g.current_user`.
    """
    @wraps(f)
    def decorated(*args: Any, **kwargs: Any) -> Any:
        token = extract_token_from_request()
        if not token:
            return jsonify({
                "error": "Unauthorized",
                "message": "Authentication token missing. Please log in.",
            }), 401

        user = verify_token(token)
        if not user:
            return jsonify({
                "error": "Unauthorized",
                "message": "Session expired or invalid token. Please log in again.",
            }), 401

        g.current_user = user
        return f(*args, **kwargs)

    return decorated

def require_role(allowed_roles: Union[str, List[str]]) -> Callable:
    """
    Decorator requiring the authenticated user to hold at least one of the specified roles.
    Must be used in combination with or after @require_auth.
    """
    if isinstance(allowed_roles, str):
        roles_set = {allowed_roles}
    else:
        roles_set = set(allowed_roles)

    def decorator(f: Callable) -> Callable:
        @wraps(f)
        def decorated(*args: Any, **kwargs: Any) -> Any:
            # Ensure require_auth has run
            user: User = getattr(g, "current_user", None)
            if not user:
                token = extract_token_from_request()
                if not token:
                    return jsonify({
                        "error": "Unauthorized",
                        "message": "Authentication token missing.",
                    }), 401
                user = verify_token(token)
                if not user:
                    return jsonify({
                        "error": "Unauthorized",
                        "message": "Invalid authentication token.",
                    }), 401
                g.current_user = user

            # Allow ADMIN to access admin-allowed endpoints or audit
            if user.role not in roles_set and user.role != "ADMIN":
                from backend.audit import log_audit_event
                log_audit_event(
                    action="AUTHORIZATION_DENIED",
                    actor=user.user_id,
                    actor_role=user.role,
                    status="DENIED",
                    reason=f"Role '{user.role}' not permitted. Required: {', '.join(sorted(roles_set))}",
                    details={"path": request.path, "method": request.method},
                )
                return jsonify({
                    "error": "Forbidden",
                    "message": (
                        f"Access forbidden: User with role '{user.role}' "
                        f"does not have permission. Required role(s): {', '.join(sorted(roles_set))}."
                    ),
                    "required_roles": sorted(list(roles_set)),
                    "user_role": user.role,
                }), 403

            return f(*args, **kwargs)

        return decorated

    return decorator

def get_current_user() -> User:
    """Helper to return current authenticated user from request context."""
    return getattr(g, "current_user", None)
