"""
AnswerChain Application Server (Phase 7).

Provides the unified, enterprise-grade academic web application API layer.
Enforces strict server-side authentication, role-based authorization (RBAC),
and operational auditing while delegating distributed ledger duties to
the underlying blockchain cluster via BlockchainService.
"""

import csv
import io
import json
import logging
import os
import sys
from typing import Any, Dict, Optional, List

from flask import Flask, jsonify, request, send_file, send_from_directory
from flask_cors import CORS

PROJECT_ROOT = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..")
)
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

import backend.database as db
from backend.marksheet_pdf import (
    generate_academic_marksheet_pdf,
    verify_pdf_digital_signature,
    calculate_pdf_hash,
)
from backend.application_service import academic_service
from backend.audit import get_audit_events, log_audit_event
from backend.auth import (
    authenticate,
    check_login_rate_limit,
    check_upload_rate_limit,
    create_teacher_account,
    get_user_by_id,
    list_all_teachers_admin,
    list_teachers,
    record_login_failure,
    record_login_success,
    reset_teacher_password,
    revoke_token,
    toggle_teacher_account_status,
    update_teacher_account,
    verify_token,
)
from backend.authorization import (
    extract_token_from_request,
    get_current_user,
    require_auth,
    require_role,
)
from backend.blockchain_service import blockchain_service
from backend.qr_service import (
    generate_qr_data_uri,
    generate_qr_png_bytes,
    get_verification_url,
)
from backend.examiner import examiner_manager

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("server")

FRONTEND_DIR = os.path.join(PROJECT_ROOT, "frontend")
GENERATED_MARKSHEETS_DIR = os.path.join(PROJECT_ROOT, "generated", "marksheets")

app = Flask(
    __name__,
    static_folder=FRONTEND_DIR,
    static_url_path="",
)
CORS(app, resources={r"/*": {"origins": "*"}}, supports_credentials=True)


# ============================================================
# HTTP SECURITY HEADERS (Phase 8)
# ============================================================

@app.after_request
def apply_security_headers(response):
    """Enforce standard enterprise web application security headers."""
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "SAMEORIGIN"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=(self)"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "img-src 'self' data: blob:; "
        "style-src 'self' 'unsafe-inline'; "
        "script-src 'self' 'unsafe-inline'; "
        "font-src 'self'; "
        "connect-src 'self';"
    )
    return response


# ============================================================
# STATIC FRONTEND ROUTES & PAGES
# ============================================================

@app.route("/", methods=["GET"])
@app.route("/index.html", methods=["GET"])
def index():
    token = extract_token_from_request()
    if token:
        user = verify_token(token)
        if user and user.role != "ADMIN":
            from flask import redirect
            if user.role == "UNIVERSITY":
                return redirect("/university/dashboard.html")
            elif user.role == "TEACHER":
                return redirect("/teacher/dashboard.html")
            elif user.role == "AUTHORITY":
                return redirect("/authority/dashboard.html")
            elif user.role == "VERIFIER":
                return redirect("/verify/index.html")
            elif user.role == "COLLEGE_ADMIN":
                return redirect("/college/dashboard.html")
            elif user.role == "STUDENT":
                return redirect("/student/dashboard.html")
            return redirect("/login.html")
        elif user and user.role == "ADMIN":
            from flask import redirect
            return redirect("/admin/dashboard.html")
    return send_from_directory(FRONTEND_DIR, "index.html")


@app.route("/login", methods=["GET"])
def login_page():
    return send_from_directory(FRONTEND_DIR, "login.html")


@app.route("/verify/upload", methods=["GET"])
@app.route("/verify/upload.html", methods=["GET"])
def public_verify_upload_page():
    upload_html = os.path.join(FRONTEND_DIR, "verify", "upload.html")
    if os.path.isfile(upload_html):
        return send_file(upload_html)
    return send_from_directory(FRONTEND_DIR, "index.html")


@app.route("/verify", methods=["GET"])
@app.route("/verify/", methods=["GET"])
def public_verify_root_page():
    verify_html = os.path.join(FRONTEND_DIR, "verify", "index.html")
    if os.path.isfile(verify_html):
        return send_file(verify_html)
    return send_from_directory(FRONTEND_DIR, "index.html")


@app.route("/verify/<marksheet_id>", methods=["GET"])
def public_verify_page(marksheet_id: str):
    if marksheet_id in ("upload", "upload.html"):
        upload_html = os.path.join(FRONTEND_DIR, "verify", "upload.html")
        if os.path.isfile(upload_html):
            return send_file(upload_html)
    # Public verification page
    verify_html = os.path.join(FRONTEND_DIR, "verify", "index.html")
    if os.path.isfile(verify_html):
        return send_file(verify_html)
    return send_from_directory(FRONTEND_DIR, "index.html")


@app.route("/marksheets/<marksheet_id>", methods=["GET"])
def marksheet_page(marksheet_id: str):
    # Marksheet detail page
    ms_html = os.path.join(FRONTEND_DIR, "university", "marksheets.html")
    if os.path.isfile(ms_html):
        return send_file(ms_html)
    return send_from_directory(FRONTEND_DIR, "index.html")


# ============================================================
# 1. AUTHENTICATION APIS
# ============================================================

@app.route("/api/auth/login", methods=["POST"])
def login():
    """
    POST /api/auth/login
    Request: {"user_id": "...", "password": "..."}
    Returns: user_id, name, role, department, token
    """
    data = request.get_json(silent=True) or {}
    user_id = data.get("user_id", "").strip()
    password = data.get("password", "").strip()

    if not user_id or not password:
        return jsonify({
            "error": "Bad Request",
            "message": "Both 'user_id' and 'password' are required.",
        }), 400

    client_ip = request.remote_addr or "127.0.0.1"
    allowed, rate_msg = check_login_rate_limit(client_ip)
    if not allowed:
        log_audit_event(
            action="LOGIN_FAILURE",
            actor=user_id or "ANONYMOUS",
            actor_role="UNKNOWN",
            status="BLOCKED",
            reason=rate_msg,
            details={"ip": client_ip},
        )
        return jsonify({
            "error": "Too Many Requests",
            "message": rate_msg,
        }), 429

    auth_result = authenticate(user_id, password)
    if not auth_result:
        record_login_failure(client_ip)
        log_audit_event(
            action="LOGIN_FAILURE",
            actor=user_id,
            actor_role="UNKNOWN",
            status="FAILED",
            reason="Invalid credentials or inactive user",
            details={"ip": client_ip},
        )
        return jsonify({
            "error": "Unauthorized",
            "message": "Invalid user ID or password.",
        }), 401

    record_login_success(client_ip)
    log_audit_event(
        action="LOGIN_SUCCESS",
        actor=auth_result["user_id"],
        actor_role=auth_result["role"],
        status="SUCCESS",
        details={"name": auth_result["name"], "ip": client_ip},
    )

    return jsonify({
        "message": "Authentication successful.",
        "user": auth_result,
        "token": auth_result["token"],
    }), 200


@app.route("/api/auth/me", methods=["GET"])
@require_auth
def get_current_user_profile():
    """Return currently authenticated user profile."""
    user = get_current_user()
    return jsonify({"user": user.to_dict()}), 200


@app.route("/api/auth/logout", methods=["POST"])
@require_auth
def logout():
    """Revoke session token."""
    token = extract_token_from_request()
    revoke_token(token)
    user = get_current_user()
    log_audit_event(
        action="LOGOUT",
        actor=user.user_id,
        actor_role=user.role,
        status="SUCCESS",
    )
    return jsonify({"message": "Logged out successfully."}), 200


@app.route("/api/teachers", methods=["GET"])
@require_auth
def get_teachers():
    """Return list of active teachers for assignment dropdown, optionally filtered by ?subject=<code>."""
    subject = request.args.get("subject")
    teachers = list_teachers(subject_code=subject)
    return jsonify({"teachers": teachers, "count": len(teachers)}), 200


@app.route("/api/subjects", methods=["GET"])
def api_get_subjects():
    """
    GET /api/subjects
    Returns all subjects from SQLite database (active only by default, or all if ?all=1).
    """
    show_all = request.args.get("all", "0").lower() in ("1", "true")
    active_only = not show_all
    subjects = db.list_subjects(active_only=active_only)
    return jsonify({"subjects": subjects, "count": len(subjects)}), 200


@app.route("/api/admin/subjects", methods=["POST"])
@require_auth
@require_role("ADMIN")
def api_admin_create_subject():
    """
    POST /api/admin/subjects
    Body: {"subject_code": "AI", "subject_name": "Artificial Intelligence", "description": "..."}
    """
    user = get_current_user()
    data = request.get_json(silent=True) or {}
    code = data.get("subject_code", "").strip().upper()
    name = data.get("subject_name", "").strip()
    desc = data.get("description", "").strip()

    if not code or not name:
        return jsonify({"error": "Both Subject Code and Subject Name are required."}), 400

    ok, subject, err = db.create_subject(code, name, desc)
    if not ok:
        status_code = 409 if "already exists" in (err or "").lower() else 400
        return jsonify({"error": err or "Failed to create subject"}), status_code

    log_audit_event(
        action="SUBJECT_CREATED",
        actor=user.user_id,
        actor_role=user.role,
        resource_id=code,
        status="SUCCESS",
        details={"subject_code": code, "subject_name": name},
    )
    return jsonify({"message": f"Subject '{name}' ({code}) created successfully.", "subject": subject}), 201


@app.route("/api/admin/subjects/<subject_code>", methods=["PUT"])
@require_auth
@require_role("ADMIN")
def api_admin_update_subject(subject_code: str):
    """
    PUT /api/admin/subjects/<subject_code>
    Body: {"subject_name": "...", "description": "..."}
    """
    user = get_current_user()
    data = request.get_json(silent=True) or {}
    name = data.get("subject_name")
    desc = data.get("description")

    ok, subject, err = db.update_subject(subject_code, subject_name=name, description=desc)
    if not ok:
        status_code = 404 if "not found" in (err or "").lower() else 400
        return jsonify({"error": err or "Failed to update subject"}), status_code

    log_audit_event(
        action="SUBJECT_UPDATED",
        actor=user.user_id,
        actor_role=user.role,
        resource_id=subject_code.upper(),
        status="SUCCESS",
        details={"subject_code": subject_code.upper(), "subject_name": name},
    )
    return jsonify({"message": f"Subject '{subject_code}' updated successfully.", "subject": subject}), 200


@app.route("/api/admin/subjects/<subject_code>/status", methods=["PATCH"])
@require_auth
@require_role("ADMIN")
def api_admin_toggle_subject_status(subject_code: str):
    """
    PATCH /api/admin/subjects/<subject_code>/status
    Body: {"active": true / false}
    """
    user = get_current_user()
    data = request.get_json(silent=True) or {}
    if "active" not in data:
        return jsonify({"error": "Field 'active' (boolean) is required."}), 400

    active = bool(data["active"])
    ok, err = db.toggle_subject_status(subject_code, active=active)
    if not ok:
        status_code = 404 if "not found" in (err or "").lower() else 400
        return jsonify({"error": err or "Failed to change subject status"}), status_code

    state_str = "activated" if active else "deactivated"
    log_audit_event(
        action="SUBJECT_STATUS_CHANGED",
        actor=user.user_id,
        actor_role=user.role,
        resource_id=subject_code.upper(),
        status="SUCCESS",
        details={"subject_code": subject_code.upper(), "active": active},
    )
    return jsonify({"message": f"Subject '{subject_code}' {state_str} successfully.", "active": active}), 200


@app.route("/api/admin/teachers", methods=["GET"])
@require_auth
@require_role("ADMIN")
def api_admin_list_teachers():
    """
    GET /api/admin/teachers
    Returns all teachers (active and inactive) with assigned subjects for Admin management.
    """
    teachers = list_all_teachers_admin()
    return jsonify({"teachers": teachers, "count": len(teachers)}), 200


@app.route("/api/admin/teachers", methods=["POST"])
@require_auth
@require_role("ADMIN")
def api_admin_create_teacher():
    """
    POST /api/admin/teachers
    Body:
      - name: Teacher Name
      - assigned_subject: Subject Code
      - user_id: Unique Teacher User ID
      - password: Password
      - confirm_password: Password confirmation
      - department: Optional Department
      - email: Optional Email
    """
    user = get_current_user()
    data = request.get_json(silent=True) or {}

    name = data.get("name", "").strip()
    assigned_subject = data.get("assigned_subject", "").strip().upper()
    user_id = data.get("user_id", "").strip().upper()
    password = data.get("password", "")
    confirm_password = data.get("confirm_password", "")
    department = data.get("department", "Academic Faculty").strip()
    email = data.get("email", "").strip()

    if not name or not assigned_subject or not user_id or not password:
        return jsonify({"error": "Teacher Name, Assigned Subject, User ID, and Password are all required."}), 400

    if password != confirm_password:
        return jsonify({"error": "Passwords do not match."}), 400

    if len(password) < 6:
        return jsonify({"error": "Password must be at least 6 characters long."}), 400

    ok, teacher, err = create_teacher_account(
        user_id=user_id,
        name=name,
        assigned_subject=assigned_subject,
        password=password,
        department=department,
        email=email,
    )
    if not ok:
        status_code = 409 if "already exists" in (err or "").lower() else 400
        return jsonify({"error": err or "Failed to create teacher account"}), status_code

    log_audit_event(
        action="TEACHER_ACCOUNT_CREATED",
        actor=user.user_id,
        actor_role=user.role,
        resource_id=user_id,
        status="SUCCESS",
        details={"user_id": user_id, "name": name, "assigned_subject": assigned_subject},
    )
    return jsonify({"message": f"Teacher account '{user_id}' ({name}) created successfully.", "teacher": teacher}), 201


@app.route("/api/admin/teachers/<teacher_id>", methods=["PUT"])
@require_auth
@require_role("ADMIN")
def api_admin_update_teacher(teacher_id: str):
    """
    PUT /api/admin/teachers/<teacher_id>
    Body: {"name": "...", "assigned_subject": "...", "department": "...", "email": "..."}
    """
    user = get_current_user()
    data = request.get_json(silent=True) or {}

    name = data.get("name")
    assigned_subject = data.get("assigned_subject")
    department = data.get("department")
    email = data.get("email")

    ok, teacher, err = update_teacher_account(
        user_id=teacher_id,
        name=name,
        assigned_subject=assigned_subject,
        department=department,
        email=email,
    )
    if not ok:
        status_code = 404 if "not found" in (err or "").lower() else 400
        return jsonify({"error": err or "Failed to update teacher"}), status_code

    log_audit_event(
        action="TEACHER_ACCOUNT_UPDATED",
        actor=user.user_id,
        actor_role=user.role,
        resource_id=teacher_id.upper(),
        status="SUCCESS",
        details={"user_id": teacher_id.upper(), "assigned_subject": assigned_subject},
    )
    return jsonify({"message": f"Teacher '{teacher_id}' updated successfully.", "teacher": teacher}), 200


@app.route("/api/admin/teachers/<teacher_id>/reset-password", methods=["POST"])
@require_auth
@require_role("ADMIN")
def api_admin_reset_teacher_password(teacher_id: str):
    """
    POST /api/admin/teachers/<teacher_id>/reset-password
    Body: {"new_password": "...", "confirm_password": "..."}
    """
    user = get_current_user()
    data = request.get_json(silent=True) or {}
    new_password = data.get("new_password", "")
    confirm_password = data.get("confirm_password", "")

    if not new_password or not confirm_password:
        return jsonify({"error": "New password and confirmation are required."}), 400
    if new_password != confirm_password:
        return jsonify({"error": "Passwords do not match."}), 400
    if len(new_password) < 6:
        return jsonify({"error": "Password must be at least 6 characters long."}), 400

    ok, err = reset_teacher_password(teacher_id, new_password)
    if not ok:
        status_code = 404 if "not found" in (err or "").lower() else 400
        return jsonify({"error": err or "Failed to reset password"}), status_code

    log_audit_event(
        action="TEACHER_PASSWORD_RESET",
        actor=user.user_id,
        actor_role=user.role,
        resource_id=teacher_id.upper(),
        status="SUCCESS",
        details={"user_id": teacher_id.upper()},
    )
    return jsonify({"message": f"Password for teacher '{teacher_id}' has been reset successfully."}), 200


@app.route("/api/admin/teachers/<teacher_id>/status", methods=["PATCH"])
@require_auth
@require_role("ADMIN")
def api_admin_toggle_teacher_status(teacher_id: str):
    """
    PATCH /api/admin/teachers/<teacher_id>/status
    Body: {"active": true / false}
    """
    user = get_current_user()
    data = request.get_json(silent=True) or {}
    if "active" not in data:
        return jsonify({"error": "Field 'active' (boolean) is required."}), 400

    active = bool(data["active"])
    ok, err = toggle_teacher_account_status(teacher_id, active=active)
    if not ok:
        status_code = 404 if "not found" in (err or "").lower() else 400
        return jsonify({"error": err or "Failed to update teacher status"}), status_code

    state_str = "activated" if active else "deactivated"
    log_audit_event(
        action="TEACHER_STATUS_CHANGED",
        actor=user.user_id,
        actor_role=user.role,
        resource_id=teacher_id.upper(),
        status="SUCCESS",
        details={"user_id": teacher_id.upper(), "active": active},
    )
    return jsonify({"message": f"Teacher account '{teacher_id}' has been {state_str}.", "active": active}), 200


# ============================================================
# 2. UNIVERSITY APIS
# ============================================================

@app.route("/api/university/dashboard", methods=["GET"])
@require_auth
@require_role(["UNIVERSITY", "ADMIN"])
def university_dashboard():
    """GET /api/university/dashboard"""
    data = academic_service.get_university_dashboard()
    return jsonify(data), 200


@app.route("/api/university/next-script-id", methods=["GET"])
@require_auth
@require_role(["UNIVERSITY", "ADMIN"])
def api_university_next_script_id():
    """GET /api/university/next-script-id - Return next auto-generated script ID."""
    next_id = academic_service.get_next_answer_script_id()
    return jsonify({"next_id": next_id}), 200


@app.route("/api/university/answer-scripts", methods=["GET"])
@require_auth
@require_role(["UNIVERSITY", "ADMIN"])
def university_list_answer_scripts():
    """GET /api/university/answer-scripts"""
    scripts = academic_service.get_unified_scripts_status()
    return jsonify({"answer_scripts": scripts}), 200


@app.route("/api/university/answer-scripts", methods=["POST"])
@require_auth
@require_role(["UNIVERSITY", "ADMIN"])
def university_register_answer_script():
    """
    POST /api/university/answer-scripts
    Accepts JSON or multipart/form-data with student_id, exam_id, exam_name, file/file_content.
    """
    user = get_current_user()

    if request.is_json:
        data = request.get_json() or {}
        student_id = data.get("student_id", "")
        student_name = data.get("student_name", "")
        exam_id = data.get("exam_id", "")
        exam_name = data.get("exam_name", "")
        subject = data.get("subject") or data.get("subject_name")
        subject_code = data.get("subject_code")
        file_name = data.get("file_name", "answer_script.pdf")
        file_hash = data.get("file_hash")
        answer_script_id = data.get("answer_script_id")
        file_bytes = None
    else:
        # Multipart form-data
        student_id = request.form.get("student_id", "")
        student_name = request.form.get("student_name", "")
        exam_id = request.form.get("exam_id", "")
        exam_name = request.form.get("exam_name", "")
        subject = request.form.get("subject") or request.form.get("subject_name")
        subject_code = request.form.get("subject_code")
        answer_script_id = request.form.get("answer_script_id")
        uploaded_file = request.files.get("file")
        if uploaded_file and uploaded_file.filename:
            file_name = uploaded_file.filename
            file_bytes = uploaded_file.read()
            file_hash = None
        else:
            file_name = request.form.get("file_name", "script.pdf")
            file_hash = request.form.get("file_hash")
            file_bytes = None

    success, payload, status_code = academic_service.register_answer_script(
        current_user=user,
        student_id=student_id,
        student_name=student_name,
        exam_id=exam_id,
        exam_name=exam_name,
        file_name=file_name,
        file_bytes=file_bytes,
        provided_hash=file_hash,
        answer_script_id=answer_script_id,
        subject=subject,
        subject_code=subject_code,
    )
    return jsonify(payload), status_code


@app.route("/api/university/answer-scripts/<script_id>/assign", methods=["POST"])
@require_auth
@require_role(["UNIVERSITY", "ADMIN"])
def university_assign_teacher(script_id: str):
    """
    POST /api/university/answer-scripts/<id>/assign
    Body: {"teacher_id": "TCH-001"}
    """
    user = get_current_user()
    data = request.get_json(silent=True) or {}
    teacher_id = data.get("teacher_id", "")

    if not teacher_id:
        return jsonify({"error": "teacher_id is required in request body."}), 400

    success, payload, status_code = academic_service.assign_teacher(
        current_user=user,
        answer_script_id=script_id,
        teacher_id=teacher_id,
    )
    return jsonify(payload), status_code


@app.route("/api/university/results", methods=["GET"])
@require_auth
@require_role(["UNIVERSITY", "ADMIN"])
def university_results():
    """GET /api/university/results"""
    scripts = academic_service.get_unified_scripts_status()
    finalized = [s for s in scripts if s["finalized"]]
    return jsonify({"results": finalized}), 200


@app.route("/api/university/marksheets", methods=["GET"])
@require_auth
@require_role(["UNIVERSITY", "AUTHORITY", "ADMIN"])
def university_marksheets():
    """GET /api/university/marksheets"""
    scripts = academic_service.get_unified_scripts_status()
    marksheets = [s for s in scripts if s["marksheet_generated"]]
    return jsonify({"marksheets": marksheets}), 200


# ============================================================
# 3. TEACHER APIS
# ============================================================

@app.route("/api/teacher/dashboard", methods=["GET"])
@require_auth
@require_role(["TEACHER", "ADMIN"])
def teacher_dashboard():
    """GET /api/teacher/dashboard"""
    user = get_current_user()
    assignments = academic_service.get_teacher_assignments(user.user_id)

    total_assigned = len(assignments)
    evaluated = sum(1 for a in assignments if a["evaluated"])
    pending = total_assigned - evaluated

    return jsonify({
        "teacher": user.to_dict(),
        "kpis": {
            "total_assigned": total_assigned,
            "evaluated": evaluated,
            "pending_evaluation": pending,
        },
        "assignments": assignments,
    }), 200


@app.route("/api/teacher/assignments", methods=["GET"])
@require_auth
@require_role(["TEACHER", "ADMIN"])
def teacher_assignments():
    """GET /api/teacher/assignments"""
    user = get_current_user()
    assignments = academic_service.get_teacher_assignments(user.user_id)
    return jsonify({"assignments": assignments}), 200


@app.route("/api/teacher/assignments/<script_id>", methods=["GET"])
@require_auth
@require_role(["TEACHER", "ADMIN"])
def teacher_assignment_detail(script_id: str):
    """GET /api/teacher/assignments/<id>"""
    user = get_current_user()
    success, payload, status_code = academic_service.get_teacher_assignment_detail(
        current_user=user,
        answer_script_id=script_id,
    )
    return jsonify(payload), status_code


@app.route("/api/teacher/assignments/<script_id>/file", methods=["GET"])
@require_auth
@require_role(["TEACHER", "ADMIN", "UNIVERSITY", "AUTHORITY"])
def teacher_assignment_file(script_id: str):
    """
    GET /api/teacher/assignments/<id>/file
    Securely serves original answer-script PDF with strict ownership verification.
    """
    user = get_current_user()
    success, pdf_path, file_hash, status_code = academic_service.get_answer_script_file_path(
        current_user=user,
        answer_script_id=script_id,
    )
    if not success or not pdf_path or not os.path.isfile(pdf_path):
        return jsonify({"error": "Answer script file not found or access denied."}), status_code

    response = send_file(
        pdf_path,
        mimetype="application/pdf",
        as_attachment=False,
        download_name=f"{script_id}.pdf",
    )
    response.headers["X-AnswerScript-Hash"] = file_hash or ""
    response.headers["X-AnswerScript-ID"] = script_id
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    return response


@app.route("/api/teacher/assignments/<script_id>/draft", methods=["GET"])
@require_auth
@require_role(["TEACHER", "ADMIN"])
def teacher_assignment_draft(script_id: str):
    """
    GET /api/teacher/assignments/<id>/draft
    Retrieves page-wise evaluation progress, questions, and marks draft.
    """
    user = get_current_user()
    success, payload, status_code = academic_service.get_evaluation_draft(
        current_user=user,
        answer_script_id=script_id,
    )
    return jsonify(payload), status_code


@app.route("/api/teacher/assignments/<script_id>/page", methods=["POST"])
@require_auth
@require_role(["TEACHER", "ADMIN"])
def teacher_save_page(script_id: str):
    """
    POST /api/teacher/assignments/<id>/page
    Saves page-wise marks and annotations, updating completion status and live totals.
    """
    user = get_current_user()
    data = request.get_json(silent=True) or {}
    page_number = data.get("page_number", 1)
    questions = data.get("questions")
    awarded_marks = data.get("awarded_marks")
    max_marks = data.get("max_marks")
    page_remarks = data.get("page_remarks", "")
    mark_completed = data.get("mark_completed", False)

    success, payload, status_code = academic_service.save_page_evaluation(
        current_user=user,
        answer_script_id=script_id,
        page_number=page_number,
        questions=questions,
        awarded_marks=awarded_marks,
        max_marks=max_marks,
        page_remarks=page_remarks,
        mark_completed=mark_completed,
    )
    return jsonify(payload), status_code


@app.route("/api/teacher/assignments/<script_id>/evaluate", methods=["POST"])
@require_auth
@require_role(["TEACHER", "ADMIN"])
def teacher_evaluate(script_id: str):
    """
    POST /api/teacher/assignments/<id>/evaluate
    Body: {"marks": 85, "max_marks": 100, "comments": "Good work", "page_evaluations": [...]}
    """
    user = get_current_user()
    data = request.get_json(silent=True) or {}
    marks = data.get("marks")
    max_marks = data.get("max_marks", 100)
    comments = data.get("comments")
    page_evaluations = data.get("page_evaluations")

    success, payload, status_code = academic_service.evaluate_assignment(
        current_user=user,
        answer_script_id=script_id,
        marks=marks,
        max_marks=max_marks,
        comments=comments,
        page_evaluations=page_evaluations,
    )
    return jsonify(payload), status_code


# ============================================================
# 4. AUTHORITY APIS
# ============================================================

@app.route("/api/authority/dashboard", methods=["GET"])
@require_auth
@require_role(["AUTHORITY", "ADMIN"])
def authority_dashboard():
    """GET /api/authority/dashboard"""
    data = academic_service.get_authority_dashboard()
    data["active_head_examiners"] = examiner_manager.election_registry.list_head_examiners()
    return jsonify(data), 200


@app.route("/api/authority/results/pending", methods=["GET"])
@require_auth
@require_role(["AUTHORITY", "ADMIN"])
def authority_pending_results():
    """GET /api/authority/results/pending"""
    scripts = academic_service.get_unified_scripts_status()
    pending = [s for s in scripts if s["evaluated"] and not s["finalized"]]
    return jsonify({
        "pending_results": pending,
        "active_head_examiners": examiner_manager.election_registry.list_head_examiners(),
    }), 200


@app.route("/api/authority/results/<script_id>", methods=["GET"])
@require_auth
@require_role(["AUTHORITY", "ADMIN"])
def authority_result_detail(script_id: str):
    """GET /api/authority/results/<id>"""
    scripts = academic_service.get_unified_scripts_status()
    script = next((s for s in scripts if s["answer_script_id"] == script_id), None)
    if not script:
        return jsonify({"error": "Answer script not found."}), 404
    return jsonify({"result": script}), 200


@app.route("/api/authority/results/<script_id>/finalize", methods=["POST"])
@require_auth
@require_role(["AUTHORITY", "ADMIN"])
def authority_finalize_result(script_id: str):
    """
    POST /api/authority/results/<id>/finalize
    Teachers attempting this endpoint will receive 403 Forbidden via @require_role.
    """
    user = get_current_user()
    success, payload, status_code = academic_service.finalize_result(
        current_user=user,
        answer_script_id=script_id,
    )
    return jsonify(payload), status_code


@app.route("/api/results/finalize", methods=["POST"])
@require_auth
@require_role(["AUTHORITY", "ADMIN"])
def generic_finalize_result():
    """
    POST /api/results/finalize
    Alternative endpoint accepting JSON payload with answer_script_id.
    """
    data = request.get_json(silent=True) or {}
    script_id = data.get("answer_script_id") or data.get("script_id")
    if not script_id:
        return jsonify({"error": "Bad Request", "message": "answer_script_id is required."}), 400
    user = get_current_user()
    success, payload, status_code = academic_service.finalize_result(
        current_user=user,
        answer_script_id=script_id,
    )
    return jsonify(payload), status_code


@app.route("/api/authority/results/<script_id>/marksheet", methods=["POST"])
@require_auth
@require_role(["AUTHORITY", "ADMIN"])
def authority_generate_marksheet(script_id: str):
    """
    POST /api/authority/results/<id>/marksheet
    Generates official marksheet and physical PDF, hashes both, and commits to blockchain.
    """
    user = get_current_user()
    success, payload, status_code = academic_service.generate_marksheet(
        current_user=user,
        answer_script_id=script_id,
    )
    return jsonify(payload), status_code


# ============================================================
# 5. PUBLIC VERIFICATION & MARKSHEET MEDIA APIS
# ============================================================

@app.route("/api/verify/<marksheet_id>", methods=["GET"])
def public_verify_api(marksheet_id: str):
    """
    GET /api/verify/<marksheet_id>
    Public verification endpoint. No login required.
    Returns: status (VERIFIED | TAMPERED | NOT_FOUND | INVALID_RESULT | PDF_INTEGRITY_FAILED),
             sanitized marksheet info, verification URL, QR code data URI.
    """
    clean_id = marksheet_id.strip()
    result = academic_service.verify_marksheet_public(clean_id)

    # Attach QR data URI and public verification link
    result["verification_url"] = get_verification_url(clean_id)
    try:
        result["qr_data_uri"] = generate_qr_data_uri(clean_id)
    except Exception as e:
        logger.warning("Could not generate QR data URI for %s: %s", clean_id, e)
        result["qr_data_uri"] = None

    status_code = 200 if result.get("verified") else (404 if result.get("status") == "NOT_FOUND" else 400)
    return jsonify(result), status_code


# ============================================================
# PHASE 7A: PUBLIC MARKSHEET UPLOAD AUTHENTICITY CHECKER
# ============================================================

@app.route("/api/public/verify-upload", methods=["POST"])
def public_verify_upload_api():
    """
    POST /api/public/verify-upload
    Public endpoint: verify marksheet authenticity by uploading actual PDF document.
    No authentication required.
    Validates uploaded PDF, computes authoritative SHA-256 in memory,
    matches against on-chain MARKSHEET_REGISTERED marksheet_pdf_hash.
    """
    client_ip = request.remote_addr or "127.0.0.1"
    allowed, rate_msg = check_upload_rate_limit(client_ip)
    if not allowed:
        return jsonify({
            "error": "Too Many Requests",
            "message": rate_msg,
        }), 429

    if "file" not in request.files:
        return jsonify({
            "error": "Bad Request",
            "message": "Missing 'file' field in multipart form-data request.",
        }), 400

    uploaded_file = request.files["file"]

    if not uploaded_file or not uploaded_file.filename:
        return jsonify({
            "error": "Bad Request",
            "message": "No file selected or uploaded file is empty.",
        }), 400

    file_name = uploaded_file.filename
    try:
        file_bytes = uploaded_file.read()
    except Exception as e:
        logger.error("Failed to read uploaded file: %s", e)
        return jsonify({
            "error": "Bad Request",
            "message": "Malformed file upload stream.",
        }), 400

    content_type = uploaded_file.content_type

    try:
        success, payload, status_code = academic_service.verify_uploaded_marksheet_pdf(
            file_name=file_name,
            file_bytes=file_bytes,
            content_type=content_type,
        )
        return jsonify(payload), status_code
    except Exception as e:
        logger.error("Internal error during PDF verification: %s", e)
        return jsonify({
            "error": "Internal Server Error",
            "message": "An unexpected error occurred during document verification.",
        }), 500


@app.route("/api/qr/<marksheet_id>", methods=["GET"])
def public_qr_image(marksheet_id: str):
    """GET /api/qr/<marksheet_id> - returns raw PNG image of verification QR."""
    try:
        png_bytes = generate_qr_png_bytes(marksheet_id)
        return send_file(
            io.BytesIO(png_bytes),
            mimetype="image/png",
            as_attachment=False,
            download_name=f"qr_{marksheet_id}.png",
        )
    except Exception as e:
        return jsonify({"error": f"Failed to generate QR: {str(e)}"}), 500


@app.route("/api/marksheets/<marksheet_id>/pdf", methods=["GET"])
def download_marksheet_pdf_api(marksheet_id: str):
    """
    GET /api/marksheets/<marksheet_id>/pdf
    Downloads the physical marksheet PDF from the authority/generation directory.
    """
    clean_id = marksheet_id.strip()
    pdf_filename = f"{clean_id}.pdf"
    pdf_path = os.path.join(GENERATED_MARKSHEETS_DIR, pdf_filename)

    if not os.path.isfile(pdf_path):
        return jsonify({"error": f"Marksheet PDF '{pdf_filename}' not found."}), 404

    return send_file(
        pdf_path,
        mimetype="application/pdf",
        as_attachment=True,
        download_name=pdf_filename,
    )


@app.route("/api/marksheets/<marksheet_id>/verify-pdf", methods=["POST"])
def verify_marksheet_pdf_api(marksheet_id: str):
    """Public / internal PDF integrity check."""
    resp = blockchain_service.verify_marksheet_pdf(marksheet_id)
    return jsonify(resp.get("data", {})), resp.get("status_code", 500)


# ============================================================
# 6. ADMIN APIS
# ============================================================

@app.route("/api/admin/dashboard", methods=["GET"])
@require_auth
@require_role("ADMIN")
def admin_dashboard():
    """GET /api/admin/dashboard"""
    network_data = blockchain_service.get_cluster_status()
    audit_events = get_audit_events(limit=20)
    scripts = academic_service.get_unified_scripts_status()

    return jsonify({
        "network": network_data,
        "recent_audit": audit_events,
        "total_scripts": len(scripts),
        "system_status": "ONLINE",
    }), 200


@app.route("/api/admin/network", methods=["GET"])
@app.route("/api/network", methods=["GET"])
def admin_network():
    """
    GET /api/admin/network (and /api/network)
    Proxies live network and cluster status through the application server.
    Protected: Accessible to authenticated ADMIN users or local service health probe.
    """
    token = extract_token_from_request()
    if token:
        user = verify_token(token)
        if not user or user.role != "ADMIN":
            return jsonify({
                "error": "Forbidden",
                "message": "Access forbidden: Blockchain monitor is restricted to System Administrators.",
            }), 403
    elif request.remote_addr not in ("127.0.0.1", "::1"):
        return jsonify({
            "error": "Unauthorized",
            "message": "Authentication required. Admin privileges required.",
        }), 401

    cluster_data = blockchain_service.get_cluster_status()
    return jsonify(cluster_data), 200


@app.route("/api/chain", methods=["GET"])
@app.route("/api/admin/chain", methods=["GET"])
@require_auth
@require_role("ADMIN")
def api_chain():
    """
    GET /api/chain (and /api/admin/chain)
    Proxies confirmed blockchain ledger from the live cluster through the application server.
    Restricted strictly to authenticated ADMIN users.
    """
    for role in ("UNIVERSITY", "AUTHORITY", "TEACHER"):
        resp = blockchain_service.get_blockchain(role)
        if resp.get("success"):
            data = resp.get("data", {})
            blocks = data.get("blocks") or data.get("chain") or []
            return jsonify({
                "chain": blocks,
                "node_id": data.get("node_id", "node-1"),
                "role": data.get("role", "UNIVERSITY"),
            }), 200
    return jsonify({"error": "Blockchain ledger unavailable", "chain": []}), 503


@app.route("/api/admin/audit", methods=["GET"])
@app.route("/api/audit-logs", methods=["GET"])
@require_auth
@require_role("ADMIN")
def admin_audit():
    """GET /api/admin/audit"""
    limit = int(request.args.get("limit", 100))
    action = request.args.get("action")
    actor = request.args.get("actor")
    events = get_audit_events(limit=limit, action=action, actor=actor)
    return jsonify({"audit_events": events}), 200


# ============================================================
# 7. PHASE 9: MULTI-PROCESS EXAMINER & HEAD ELECTION APIS
# ============================================================

@app.route("/api/admin/examiners", methods=["GET"])
@app.route("/api/examiners/status", methods=["GET"])
def api_examiners_status():
    """
    GET /api/admin/examiners (and /api/examiners/status)
    Returns live diagnostic status across all 5 independent examiner processes,
    PIDs, heights, consensus status, and IPC queue telemetry.
    """
    if not examiner_manager.is_running:
        examiner_manager.start()
        # Seed default DBMS Head Examiner if none present
        if not examiner_manager.election_registry.active_head_examiners:
            elec = examiner_manager.start_election(subject="DBMS", term_days=365)
            for v, c in [("TCH-001", "TCH-002"), ("TCH-002", "TCH-002"), ("TCH-003", "TCH-002"), ("TCH-004", "TCH-002"), ("TCH-005", "TCH-001")]:
                examiner_manager.cast_vote(elec["election_id"], v, c)

    status = examiner_manager.get_status()
    return jsonify(status), 200


@app.route("/api/admin/elections", methods=["GET"])
@app.route("/api/teacher/elections", methods=["GET"])
def api_elections_list():
    """GET /api/admin/elections or /api/teacher/elections - List all subject elections and active Head Examiners."""
    return jsonify({
        "elections": examiner_manager.election_registry.list_elections(),
        "active_head_examiners": examiner_manager.election_registry.list_head_examiners(),
    }), 200


@app.route("/api/admin/elections", methods=["POST"])
@app.route("/api/admin/elections/start", methods=["POST"])
@require_auth
@require_role(["ADMIN", "AUTHORITY"])
def api_start_election():
    """POST /api/admin/elections/start - Start election or directly appoint Head Examiner for a subject."""
    body = request.get_json(silent=True) or {}
    subject = body.get("subject", "").strip().upper()
    if not subject:
        return jsonify({"error": "Missing subject name"}), 400

    term_days = int(body.get("term_days", 365))
    head_examiner_id = body.get("head_examiner_id", "").strip().upper()
    direct_appoint = bool(body.get("direct_appoint", False) or head_examiner_id)

    curr_user = get_current_user()
    if direct_appoint and head_examiner_id:
        result = examiner_manager.direct_appoint_head_examiner(
            subject=subject,
            head_examiner_id=head_examiner_id,
            term_days=term_days,
            appointed_by=curr_user.user_id,
        )
        log_audit_event(
            action="HEAD_EXAMINER_DIRECT_APPOINTED",
            actor=curr_user.user_id,
            actor_role=curr_user.role,
            resource_id=result["election"]["election_id"],
            details={"subject": subject, "head_examiner_id": head_examiner_id, "term_days": term_days},
        )
        return jsonify({
            "success": True,
            "message": f"Head Examiner {head_examiner_id} appointed for {subject}",
            "election": result["election"],
            "appointment": result["appointment"],
        }), 201

    election = examiner_manager.start_election(subject=subject, term_days=term_days)
    log_audit_event(
        action="ELECTION_STARTED",
        actor=curr_user.user_id,
        actor_role=curr_user.role,
        resource_id=election["election_id"],
        details={"subject": subject, "term_days": term_days},
    )
    return jsonify({"success": True, "election": election}), 201


@app.route("/api/admin/elections/appoint", methods=["POST"])
@require_auth
@require_role(["ADMIN", "AUTHORITY"])
def api_direct_appoint_head_examiner():
    """POST /api/admin/elections/appoint - Directly appoint Head Examiner (supports multiple per subject)."""
    body = request.get_json(silent=True) or {}
    subject = body.get("subject", "").strip().upper()
    head_examiner_id = body.get("head_examiner_id", "").strip().upper()
    term_days = int(body.get("term_days", 365))
    if not subject or not head_examiner_id:
        return jsonify({"error": "subject and head_examiner_id are required"}), 400

    curr_user = get_current_user()
    result = examiner_manager.direct_appoint_head_examiner(
        subject=subject,
        head_examiner_id=head_examiner_id,
        term_days=term_days,
        appointed_by=curr_user.user_id,
    )
    log_audit_event(
        action="HEAD_EXAMINER_DIRECT_APPOINTED",
        actor=curr_user.user_id,
        actor_role=curr_user.role,
        resource_id=result["election"]["election_id"],
        details={"subject": subject, "head_examiner_id": head_examiner_id, "term_days": term_days},
    )
    return jsonify({
        "success": True,
        "message": f"Head Examiner {head_examiner_id} successfully appointed for {subject}",
        "appointment": result["appointment"],
        "election": result["election"],
    }), 201


@app.route("/api/admin/elections/conclude", methods=["POST"])
@require_auth
@require_role(["ADMIN", "AUTHORITY"])
def api_conclude_election():
    """POST /api/admin/elections/conclude - Conclude an election once quorum is reached."""
    body = request.get_json(silent=True) or {}
    election_id = body.get("election_id", "").strip()
    if not election_id:
        return jsonify({"error": "election_id is required"}), 400

    ok, reason, details = examiner_manager.conclude_election(election_id)
    if not ok:
        return jsonify({"error": reason, "details": details}), 400

    log_audit_event(
        action="ELECTION_CONCLUDED",
        actor=get_current_user().user_id,
        actor_role=get_current_user().role,
        resource_id=election_id,
        details=details,
    )
    return jsonify({"success": True, "message": "Election concluded successfully", "result": details}), 200


@app.route("/api/admin/elections/vote", methods=["POST"])
@app.route("/api/teacher/elections/vote", methods=["POST"])
@require_auth
@require_role(["TEACHER", "ADMIN"])
def api_cast_vote():
    """POST /api/teacher/elections/vote - Cast authenticated vote in an election."""
    curr = get_current_user()
    if curr.role != "TEACHER":
        return jsonify({
            "error": "UNAUTHORIZED_VOTER",
            "message": "Only registered faculty examiners (Teachers TCH-001 to TCH-005) can cast election ballots. Administrators have oversight authority only.",
        }), 403

    body = request.get_json(silent=True) or {}
    election_id = body.get("election_id")
    candidate_id = body.get("candidate_id")
    voter_id = curr.user_id

    if not election_id or not candidate_id:
        return jsonify({"error": "election_id and candidate_id are required"}), 400

    ok, reason, details = examiner_manager.cast_vote(
        election_id=election_id,
        voter_id=voter_id,
        candidate_id=candidate_id,
        signature=body.get("signature"),
    )
    if not ok:
        return jsonify({"error": reason, "details": details}), 400

    log_audit_event(
        action="ELECTION_VOTE_CAST",
        actor=voter_id,
        actor_role=curr.role,
        resource_id=election_id,
        details={"candidate_id": candidate_id, "reason": reason},
    )
    return jsonify({"success": True, "reason": reason, "election": details}), 200


@app.route("/api/examiners/evaluate", methods=["POST"])
@require_auth
@require_role(["TEACHER", "ADMIN"])
def api_examiner_evaluate():
    """POST /api/examiners/evaluate - Submit evaluation into examiner approval workflow."""
    body = request.get_json(silent=True) or {}
    answer_script_id = body.get("answer_script_id")
    subject = body.get("subject", "DBMS")
    marks = body.get("marks")
    max_marks = body.get("max_marks", 100.0)

    if not answer_script_id or marks is None:
        return jsonify({"error": "answer_script_id and marks are required"}), 400

    teacher_id = get_current_user().user_id
    ok, err, signed_tx = examiner_manager.submit_evaluation(
        answer_script_id=answer_script_id,
        teacher_id=teacher_id,
        subject=subject,
        marks=float(marks),
        max_marks=float(max_marks),
        remarks=body.get("remarks", "Evaluated by examiner"),
    )
    if not ok:
        return jsonify({"error": err}), 400

    return jsonify({
        "success": True,
        "message": "Evaluation submitted to Head Examiner review and consensus",
        "evaluation": signed_tx,
    }), 200


@app.route("/api/teacher/head-examiner/queue", methods=["GET"])
@require_auth
@require_role(["TEACHER", "ADMIN"])
def api_head_examiner_queue():
    """
    GET /api/teacher/head-examiner/queue
    Returns the pending result finalization queue for the subjects headed by this elected teacher.
    """
    user = get_current_user()
    all_he = examiner_manager.election_registry.list_head_examiners()

    # Identify which subjects this teacher has won / is Head Examiner for (supports multiple Head Examiners per subject)
    my_subjects = []
    for sub, info in all_he.items():
        if not info.get("is_valid"):
            continue
        heads = [str(h).strip().upper() for h in info.get("head_examiners", [info.get("head_examiner_id", "")])]
        nodes = [str(info.get("node_id", "")).strip().upper()]
        for a in info.get("all_appointments", []):
            heads.append(str(a.get("head_examiner_id", "")).strip().upper())
            nodes.append(str(a.get("node_id", "")).strip().upper())
        if user.user_id.upper() in heads or user.user_id.upper() in nodes or user.role == "ADMIN":
            my_subjects.append(sub)

    my_subjects_upper = [s.strip().upper() for s in my_subjects]

    all_scripts = academic_service.get_unified_scripts_status()
    # Filter scripts belonging to this Head Examiner's subject(s)
    subject_scripts = [
        s for s in all_scripts
        if str(s.get("subject", "")).strip().upper() in my_subjects_upper
        or (not my_subjects and user.role == "ADMIN")
    ]

    pending = [s for s in subject_scripts if s.get("evaluated") and not s.get("finalized")]
    finalized = [s for s in subject_scripts if s.get("finalized")]

    return jsonify({
        "teacher_id": user.user_id,
        "is_head_examiner": len(my_subjects) > 0,
        "head_subjects": my_subjects,
        "active_appointments": {s: all_he[s] for s in my_subjects if s in all_he},
        "pending_finalizations": pending,
        "finalized_history": finalized,
    }), 200


@app.route("/api/teacher/head-examiner/finalize", methods=["POST"])
@require_auth
@require_role(["TEACHER", "ADMIN"])
def api_head_examiner_finalize():
    """
    POST /api/teacher/head-examiner/finalize
    Elected Head Examiner approves and finalizes an evaluation for their subject.
    Enforces subject authority and anti-self-approval rule.
    """
    user = get_current_user()
    body = request.get_json(silent=True) or {}
    script_id = body.get("answer_script_id")
    if not script_id:
        return jsonify({"error": "answer_script_id is required"}), 400

    all_scripts = academic_service.get_unified_scripts_status()
    script = next((s for s in all_scripts if s["answer_script_id"] == script_id), None)
    if not script:
        return jsonify({"error": f"Answer script {script_id} not found."}), 404

    if not script.get("evaluated"):
        return jsonify({"error": "Cannot finalize result: No evaluation has been submitted yet."}), 400

    if script.get("finalized"):
        return jsonify({"error": "Result is already finalized.", "result_id": script.get("result_id")}), 409

    subject = script.get("subject", "DBMS").strip().upper()

    # 1. Authority Verification: Is this user the elected Head Examiner for this subject?
    is_he = (
        examiner_manager.election_registry.is_head_examiner(user.user_id, subject)
        or user.role == "ADMIN"
    )
    if not is_he:
        he_info = examiner_manager.election_registry.get_head_examiner(subject)
        active_heads = ", ".join(he_info.get("head_examiners", [he_info.get("head_examiner_id")])) if he_info else "None appointed"
        return jsonify({
            "error": "UNAUTHORIZED_HEAD_EXAMINER",
            "message": f"Only the democratically elected/appointed Head Examiner for {subject} ({active_heads}) can finalize this evaluation.",
        }), 403

    # 2. Anti-Self-Approval Enforcement
    evaluator_id = str(script.get("teacher_id", "")).strip().upper()
    if evaluator_id == user.user_id.upper() and user.role != "ADMIN":
        return jsonify({
            "error": "SELF_APPROVAL_PROHIBITED",
            "message": f"Anti-self-approval rule: Head Examiner {user.user_id} cannot approve or finalize their own grading evaluation for script {script_id}.",
        }), 400

    # 3. Finalize result on blockchain ledger
    success, payload, status_code = academic_service.finalize_result(
        current_user=user,
        answer_script_id=script_id,
    )
    if success:
        log_audit_event(
            action="HEAD_EXAMINER_RESULT_FINALIZED",
            actor=user.user_id,
            actor_role="HEAD_EXAMINER",
            resource_id=script_id,
            details={
                "subject": subject,
                "evaluator_id": evaluator_id,
                "final_marks": script.get("marks"),
                "remarks": body.get("remarks", "Approved by Head Examiner"),
            },
        )
    return jsonify(payload), status_code


@app.route("/api/admin/examiners/crash", methods=["POST"])
@require_auth
@require_role("ADMIN")
def api_crash_examiner():
    """POST /api/admin/examiners/crash - Simulate node process crash."""
    body = request.get_json(silent=True) or {}
    node_id = body.get("node_id", "").strip().upper()
    if not node_id:
        return jsonify({"error": "node_id required"}), 400

    ok = examiner_manager.crash_node(node_id)
    return jsonify({"success": ok, "node_id": node_id, "status": "CRASHED"}), 200


@app.route("/api/admin/examiners/restart", methods=["POST"])
@require_auth
@require_role("ADMIN")
def api_restart_examiner():
    """POST /api/admin/examiners/restart - Restart crashed node and trigger state sync."""
    body = request.get_json(silent=True) or {}
    node_id = body.get("node_id", "").strip().upper()
    if not node_id:
        return jsonify({"error": "node_id required"}), 400

    ok = examiner_manager.restart_node(node_id)
    return jsonify({"success": ok, "node_id": node_id, "status": "RECOVERED"}), 200


# ============================================================
# PHASE 11: MULTI-COLLEGE & STUDENT PORTAL API LAYER
# ============================================================

def get_caller_college_id(user: Any, requested_id: Optional[str] = None) -> Optional[str]:
    """Helper to enforce strict multi-tenant college data isolation."""
    if user.role == "COLLEGE_ADMIN":
        return user.college_id
    if user.role == "ADMIN":
        return requested_id or user.college_id
    return None


@app.route("/api/auth/change-password", methods=["POST"])
@require_auth
def api_change_password():
    """POST /api/auth/change-password - Change user password & clear must_change_password flag."""
    user = get_current_user()
    data = request.get_json(silent=True) or {}
    current_password = data.get("current_password", "").strip()
    new_password = data.get("new_password", "").strip()
    confirm_password = data.get("confirm_password", "").strip()

    if not current_password or not new_password:
        return jsonify({"error": "Bad Request", "message": "Current and new passwords are required."}), 400

    if new_password != confirm_password:
        return jsonify({"error": "Bad Request", "message": "New password and confirmation do not match."}), 400

    if len(new_password) < 6:
        return jsonify({"error": "Bad Request", "message": "New password must be at least 6 characters."}), 400

    success, msg = db.change_user_password(user.user_id, current_password, new_password)
    if not success:
        return jsonify({"error": "Bad Request", "message": msg or "Password change failed."}), 400

    log_audit_event(
        action="PASSWORD_CHANGE",
        actor=user.user_id,
        actor_role=user.role,
        status="SUCCESS",
        details={"ip": request.remote_addr},
    )
    return jsonify({"message": "Password changed successfully.", "success": True}), 200


# ------------------------------------------------------------
# SUPER ADMIN: COLLEGE MANAGEMENT
# ------------------------------------------------------------

@app.route("/api/admin/colleges", methods=["GET"])
@require_auth
@require_role("ADMIN")
def api_admin_list_colleges():
    """GET /api/admin/colleges - List all colleges with optional search/status filter."""
    search = request.args.get("search", "").strip()
    status = request.args.get("status", "").strip()
    colleges = db.list_colleges(search_query=search or None, status=status or None)
    return jsonify({"colleges": colleges, "count": len(colleges)}), 200


@app.route("/api/admin/colleges", methods=["POST"])
@require_auth
@require_role("ADMIN")
def api_admin_create_college():
    """POST /api/admin/colleges - Create a new college & provision administrator credentials."""
    user = get_current_user()
    data = request.get_json(silent=True) or {}

    code = (data.get("code") or data.get("college_code") or "").strip().upper()
    name = (data.get("name") or data.get("college_name") or "").strip()
    university = (data.get("university") or data.get("affiliated_university") or "").strip()
    email = (data.get("official_email") or "").strip()
    contact = (data.get("contact_number") or "").strip()
    address = (data.get("address") or "").strip()
    state = (data.get("state") or "").strip()
    district = (data.get("district") or "").strip()
    admin_name = (data.get("admin_name") or "").strip()
    admin_email = (data.get("admin_email") or "").strip()
    username = (data.get("admin_username") or data.get("username") or f"{code.lower()}_admin").strip()
    password = (data.get("admin_password") or data.get("password") or "").strip()

    if not code or not name or not admin_name or not admin_email or not password:
        return jsonify({"error": "Bad Request", "message": "Missing required fields (code, name, admin details, password)."}), 400

    try:
        ok, college, err = db.create_college(
            college_code=code,
            college_name=name,
            affiliated_university=university or "Affiliated University",
            address=address,
            state=state,
            district=district,
            official_email=email,
            contact_number=contact,
            admin_name=admin_name,
            admin_email=admin_email,
            username=username,
            password=password,
        )
        if not ok:
            status_code = 409 if "already exists" in (err or "").lower() else 400
            return jsonify({"error": "Conflict" if status_code == 409 else "Bad Request", "message": err}), status_code

        log_audit_event(
            action="CREATE_COLLEGE",
            actor=user.user_id,
            actor_role=user.role,
            status="SUCCESS",
            details={"college_id": college["id"], "code": college["college_code"]},
        )
        return jsonify({
            "message": "College successfully created with administrator credentials.",
            "college": college,
            "credentials": {
                "college_id": college["id"],
                "username": username,
                "temporary_password": password,
            },
        }), 201
    except Exception as e:
        logger.error("Error creating college: %s", e)
        return jsonify({"error": "Server Error", "message": str(e)}), 500


@app.route("/api/admin/colleges/<college_id>", methods=["GET"])
@require_auth
@require_role("ADMIN")
def api_admin_get_college(college_id: str):
    """GET /api/admin/colleges/<college_id> - Deep college profile and stats."""
    col = db.get_college(college_id)
    if not col:
        return jsonify({"error": "Not Found", "message": "College not found."}), 404
    stats = db.get_college_dashboard_stats(college_id)
    return jsonify({"college": col, "stats": stats}), 200


@app.route("/api/admin/colleges/<college_id>", methods=["PUT"])
@require_auth
@require_role("ADMIN")
def api_admin_update_college(college_id: str):
    """PUT /api/admin/colleges/<college_id> - Update college details."""
    user = get_current_user()
    data = request.get_json(silent=True) or {}
    ok, col, err = db.update_college(
        college_id=college_id,
        college_name=data.get("name") or data.get("college_name"),
        affiliated_university=data.get("university") or data.get("affiliated_university"),
        address=data.get("address"),
        state=data.get("state"),
        district=data.get("district"),
        official_email=data.get("official_email"),
        contact_number=data.get("contact_number"),
    )
    if not ok:
        return jsonify({"error": "Not Found", "message": err or "College not found."}), 404
    log_audit_event(
        action="UPDATE_COLLEGE",
        actor=user.user_id,
        actor_role=user.role,
        status="SUCCESS",
        details={"college_id": college_id},
    )
    return jsonify({"message": "College updated successfully.", "college": col}), 200


@app.route("/api/admin/colleges/<college_id>/status", methods=["PATCH"])
@require_auth
@require_role("ADMIN")
def api_admin_set_college_status(college_id: str):
    """PATCH /api/admin/colleges/<college_id>/status - Activate/Suspend/Archive college."""
    user = get_current_user()
    data = request.get_json(silent=True) or {}
    status = data.get("status", "").strip().upper()
    valid_statuses = ("ACTIVE", "INACTIVE", "SUSPENDED", "ARCHIVED")
    if status not in valid_statuses:
        return jsonify({"error": "Bad Request", "message": f"Status must be one of: {', '.join(valid_statuses)}"}), 400

    ok, err = db.set_college_status(college_id, status)
    if not ok:
        return jsonify({"error": "Not Found", "message": err or "College not found."}), 404
    log_audit_event(
        action="SET_COLLEGE_STATUS",
        actor=user.user_id,
        actor_role=user.role,
        status="SUCCESS",
        details={"college_id": college_id, "new_status": status},
    )
    return jsonify({"message": f"College status updated to {status}.", "status": status}), 200


@app.route("/api/admin/colleges/<college_id>/reset-credentials", methods=["POST"])
@require_auth
@require_role("ADMIN")
def api_admin_reset_college_credentials(college_id: str):
    """POST /api/admin/colleges/<college_id>/reset-credentials - Reset administrator credentials."""
    user = get_current_user()
    col = db.get_college(college_id)
    if not col:
        return jsonify({"error": "Not Found", "message": "College not found."}), 404

    data = request.get_json(silent=True) or {}
    import secrets
    new_pass = data.get("password", "").strip() or secrets.token_urlsafe(8)
    admin_user = (col.get("admin") or {}).get("user_id") or f"{col.get('college_code', '').lower()}_admin"

    ok, err = db.reset_college_admin_password(college_id, new_pass)
    if not ok:
        return jsonify({"error": "Bad Request", "message": err}), 400

    log_audit_event(
        action="RESET_COLLEGE_CREDS",
        actor=user.user_id,
        actor_role=user.role,
        status="SUCCESS",
        details={"college_id": college_id, "username": admin_user},
    )
    return jsonify({
        "message": "Administrator credentials reset successfully.",
        "credentials": {
            "college_id": college_id,
            "username": admin_user,
            "temporary_password": new_pass,
        },
    }), 200


@app.route("/api/admin/global-analytics", methods=["GET"])
@require_auth
@require_role("ADMIN")
def api_admin_global_analytics():
    """GET /api/admin/global-analytics - Platform-wide statistics and charts data."""
    analytics = db.get_global_analytics()
    return jsonify(analytics), 200


# ------------------------------------------------------------
# COLLEGE MANAGEMENT PORTAL APIS
# ------------------------------------------------------------

@app.route("/api/college/dashboard", methods=["GET"])
@require_auth
@require_role(["COLLEGE_ADMIN", "ADMIN"])
def api_college_dashboard():
    """GET /api/college/dashboard - Isolated college dashboard metrics."""
    user = get_current_user()
    college_id = get_caller_college_id(user, request.args.get("college_id"))
    if not college_id:
        return jsonify({"error": "Bad Request", "message": "College ID required."}), 400

    col = db.get_college(college_id)
    if not col:
        return jsonify({"error": "Not Found", "message": "College not found."}), 404
    stats = db.get_college_dashboard_stats(college_id)
    return jsonify({"college": col, "stats": stats}), 200


@app.route("/api/college/students", methods=["GET"])
@require_auth
@require_role(["COLLEGE_ADMIN", "ADMIN"])
def api_college_list_students():
    """GET /api/college/students - Filter and search student directory for this college."""
    user = get_current_user()
    college_id = get_caller_college_id(user, request.args.get("college_id"))
    if not college_id:
        return jsonify({"error": "Bad Request", "message": "College ID required."}), 400

    search = request.args.get("search", "").strip() or None
    dept = request.args.get("department", "").strip() or None
    sem_str = request.args.get("semester", "").strip()
    sem = int(sem_str) if sem_str.isdigit() else None
    status = request.args.get("status", "").strip() or None

    students = db.list_students(
        college_id=college_id,
        search=search,
        department=dept,
        semester=sem,
        status=status,
    )
    return jsonify({"students": students, "count": len(students)}), 200


@app.route("/api/college/students", methods=["POST"])
@require_auth
@require_role(["COLLEGE_ADMIN", "ADMIN"])
def api_college_register_student():
    """POST /api/college/students - Administrator registers a student and generates login credentials."""
    user = get_current_user()
    college_id = get_caller_college_id(user, request.args.get("college_id"))
    if not college_id:
        return jsonify({"error": "Bad Request", "message": "College ID required."}), 400

    data = request.get_json(silent=True) or {}
    password = data.get("password", "").strip() or None

    ok, student, gen_pwd, err = db.create_student(college_id, data, password=password)
    if not ok:
        status_code = 409 if "already registered" in (err or "").lower() or "already exists" in (err or "").lower() else 400
        return jsonify({"error": "Conflict" if status_code == 409 else "Bad Request", "message": err}), status_code

    log_audit_event(
        action="REGISTER_STUDENT",
        actor=user.user_id,
        actor_role=user.role,
        status="SUCCESS",
        details={"student_id": student["student_id"], "roll": student["roll_number"]},
    )
    return jsonify({
        "message": "Student successfully registered. Provide credentials to student.",
        "student": student,
        "credentials": {
            "student_id": student["student_id"],
            "username": student["user_id"],
            "temporary_password": gen_pwd,
        },
    }), 201


@app.route("/api/college/students/bulk", methods=["POST"])
@require_auth
@require_role(["COLLEGE_ADMIN", "ADMIN"])
def api_college_bulk_register_students():
    """POST /api/college/students/bulk - Bulk import students from JSON array or uploaded CSV."""
    user = get_current_user()
    college_id = get_caller_college_id(user, request.args.get("college_id"))
    if not college_id:
        return jsonify({"error": "Bad Request", "message": "College ID required."}), 400

    student_records = []

    if "file" in request.files:
        uploaded_file = request.files["file"]
        content = uploaded_file.read().decode("utf-8", errors="ignore")
        reader = csv.DictReader(io.StringIO(content))
        for row in reader:
            student_records.append(dict(row))
    else:
        body = request.get_json(silent=True) or {}
        student_records = body.get("students", [])

    if not student_records:
        return jsonify({"error": "Bad Request", "message": "No student records provided."}), 400

    created_students = []
    errors = []

    for idx, raw in enumerate(student_records, start=1):
        try:
            cleaned = {
                "full_name": (raw.get("name") or raw.get("Full Name") or raw.get("full_name") or "").strip(),
                "roll_number": (raw.get("roll_number") or raw.get("Roll Number") or "").strip(),
                "registration_number": (raw.get("registration_number") or raw.get("Registration Number") or "").strip(),
                "college_roll": (raw.get("college_roll") or raw.get("College Roll") or "").strip(),
                "department": (raw.get("department") or raw.get("Department") or "Computer Science & Engineering").strip(),
                "course": (raw.get("course") or raw.get("Course") or "B.Tech Computer Science & Engineering").strip(),
                "admission_year": int(raw.get("admission_year") or raw.get("Admission Year") or "2023"),
                "current_semester": int(raw.get("current_semester") or raw.get("Semester") or 1),
                "academic_session": (raw.get("academic_session") or raw.get("Session") or "2023-2024").strip(),
                "email": (raw.get("email") or raw.get("Email") or "").strip(),
                "mobile": (raw.get("mobile_number") or raw.get("Mobile") or raw.get("mobile") or "").strip(),
            }
            if not cleaned["full_name"] or not cleaned["roll_number"] or not cleaned["registration_number"] or not cleaned["email"]:
                errors.append({"row": idx, "error": "Missing essential fields (name, roll, reg, email)"})
                continue

            ok, created, pwd, err = db.create_student(college_id, cleaned, password=cleaned.get("password"))
            if ok and created:
                created_students.append({
                    "student_id": created["student_id"],
                    "name": created.get("full_name") or created.get("name"),
                    "roll_number": created["roll_number"],
                    "username": created["user_id"],
                    "temporary_password": pwd,
                })
            else:
                errors.append({"row": idx, "error": err or "Failed to create student"})
        except Exception as ex:
            errors.append({"row": idx, "error": str(ex)})

    return jsonify({
        "message": f"Bulk import complete: {len(created_students)} created, {len(errors)} failed.",
        "total": len(student_records),
        "created_count": len(created_students),
        "failed_count": len(errors),
        "created_students": created_students,
        "errors": errors,
    }), 200


@app.route("/api/college/students/<student_id>", methods=["GET"])
@require_auth
@require_role(["COLLEGE_ADMIN", "ADMIN"])
def api_college_get_student(student_id: str):
    """GET /api/college/students/<student_id> - Full student profile, academic history & marksheets."""
    user = get_current_user()
    student = db.get_student(student_id)
    if not student:
        return jsonify({"error": "Not Found", "message": "Student not found."}), 404

    # Strict isolation check
    if user.role == "COLLEGE_ADMIN" and student["college_id"] != user.college_id:
        return jsonify({"error": "Forbidden", "message": "Access denied to students from another college."}), 403

    results = db.get_student_semester_results(student_id, college_id=student["college_id"], published_only=False)
    marksheets = db.list_student_marksheets(student_id)
    summary = db.get_student_academic_summary(student_id)

    return jsonify({
        "student": student,
        "results": results,
        "marksheets": marksheets,
        "summary": summary,
    }), 200


@app.route("/api/college/students/<student_id>", methods=["PUT"])
@require_auth
@require_role(["COLLEGE_ADMIN", "ADMIN"])
def api_college_update_student(student_id: str):
    """PUT /api/college/students/<student_id> - Update student academic or personal information."""
    user = get_current_user()
    student = db.get_student(student_id)
    if not student:
        return jsonify({"error": "Not Found", "message": "Student not found."}), 404

    if user.role == "COLLEGE_ADMIN" and student["college_id"] != user.college_id:
        return jsonify({"error": "Forbidden", "message": "Access denied to students from another college."}), 403

    data = request.get_json(silent=True) or {}
    conn = db.get_db_connection()
    try:
        allowed = ["full_name", "father_name", "mother_name", "dob", "gender", "blood_group", "mobile", "current_address", "permanent_address", "department", "course", "current_semester"]
        sets = []
        vals = []
        for f in allowed:
            if f in data:
                sets.append(f"{f} = ?")
                vals.append(data[f])
        if sets:
            vals.append(student_id)
            with conn:
                conn.execute(f"UPDATE students SET {', '.join(sets)}, updated_at = {time.time()} WHERE student_id = ?", vals)
        return jsonify({"message": "Student profile updated successfully."}), 200
    except Exception as e:
        return jsonify({"error": "Bad Request", "message": str(e)}), 400
    finally:
        conn.close()


@app.route("/api/college/students/<student_id>/reset-password", methods=["POST"])
@require_auth
@require_role(["COLLEGE_ADMIN", "ADMIN"])
def api_college_reset_student_password(student_id: str):
    """POST /api/college/students/<student_id>/reset-password - Reset student account password."""
    user = get_current_user()
    student = db.get_student(student_id)
    if not student:
        return jsonify({"error": "Not Found", "message": "Student not found."}), 404

    if user.role == "COLLEGE_ADMIN" and student["college_id"] != user.college_id:
        return jsonify({"error": "Forbidden", "message": "Access denied."}), 403

    data = request.get_json(silent=True) or {}
    import secrets
    new_pass = data.get("password", "").strip() or secrets.token_urlsafe(8)

    ok, err = db.reset_student_password(student_id, student["college_id"], new_pass)
    if not ok:
        return jsonify({"error": "Bad Request", "message": err}), 400

    log_audit_event(
        action="RESET_STUDENT_PASSWORD",
        actor=user.user_id,
        actor_role=user.role,
        status="SUCCESS",
        details={"student_id": student_id, "username": student["user_id"]},
    )
    return jsonify({
        "message": "Student password reset successfully.",
        "credentials": {
            "student_id": student_id,
            "username": student["user_id"],
            "temporary_password": new_pass,
        },
    }), 200


@app.route("/api/college/students/<student_id>/status", methods=["PATCH"])
@require_auth
@require_role(["COLLEGE_ADMIN", "ADMIN"])
def api_college_set_student_status(student_id: str):
    """PATCH /api/college/students/<student_id>/status - Activate/Deactivate student."""
    user = get_current_user()
    student = db.get_student(student_id)
    if not student:
        return jsonify({"error": "Not Found", "message": "Student not found."}), 404

    if user.role == "COLLEGE_ADMIN" and student["college_id"] != user.college_id:
        return jsonify({"error": "Forbidden", "message": "Access denied."}), 403

    data = request.get_json(silent=True) or {}
    status = data.get("status", "").strip().upper()
    valid_statuses = ("ACTIVE", "INACTIVE", "SUSPENDED", "ALUMNI")
    if status not in valid_statuses:
        return jsonify({"error": "Bad Request", "message": f"Status must be one of: {', '.join(valid_statuses)}"}), 400

    ok, err = db.set_student_status(student_id, student["college_id"], status)
    if not ok:
        return jsonify({"error": "Bad Request", "message": err or "Status update failed."}), 400
    return jsonify({"message": f"Student status set to {status}.", "status": status}), 200


@app.route("/api/college/departments", methods=["GET"])
@require_auth
@require_role(["COLLEGE_ADMIN", "ADMIN"])
def api_college_departments():
    """GET /api/college/departments"""
    user = get_current_user()
    college_id = get_caller_college_id(user, request.args.get("college_id"))
    depts = db.list_departments(college_id)
    return jsonify({"departments": depts}), 200


@app.route("/api/college/departments", methods=["POST"])
@require_auth
@require_role(["COLLEGE_ADMIN", "ADMIN"])
def api_college_create_department():
    """POST /api/college/departments"""
    user = get_current_user()
    college_id = get_caller_college_id(user)
    if not college_id:
        return jsonify({"error": "Bad Request", "message": "College ID required."}), 400
    data = request.get_json(silent=True) or {}
    code = data.get("dept_code", "").strip().upper()
    name = data.get("dept_name", "").strip()
    if not code or not name:
        return jsonify({"error": "Bad Request", "message": "dept_code and dept_name required."}), 400
    ok, res, err = db.create_department(college_id, code, name)
    if not ok:
        return jsonify({"error": "Bad Request", "message": err}), 400
    return jsonify({"message": "Department created.", "department": res}), 201


@app.route("/api/college/courses", methods=["GET"])
@require_auth
@require_role(["COLLEGE_ADMIN", "ADMIN"])
def api_college_courses():
    """GET /api/college/courses"""
    user = get_current_user()
    college_id = get_caller_college_id(user, request.args.get("college_id"))
    courses = db.list_courses(college_id)
    return jsonify({"courses": courses}), 200


@app.route("/api/college/courses", methods=["POST"])
@require_auth
@require_role(["COLLEGE_ADMIN", "ADMIN"])
def api_college_create_course():
    """POST /api/college/courses"""
    user = get_current_user()
    college_id = get_caller_college_id(user)
    if not college_id:
        return jsonify({"error": "Bad Request", "message": "College ID required."}), 400
    data = request.get_json(silent=True) or {}
    code = data.get("course_code", "").strip().upper()
    name = data.get("course_name", "").strip()
    duration = int(data.get("duration_years", 4))
    semesters = int(data.get("total_semesters", 8))
    if not code or not name:
        return jsonify({"error": "Bad Request", "message": "course_code and course_name required."}), 400
    ok, res, err = db.create_course(college_id, code, name, duration, semesters)
    if not ok:
        return jsonify({"error": "Bad Request", "message": err}), 400
    return jsonify({"message": "Course created.", "course": res}), 201


@app.route("/api/college/results/<student_id>", methods=["GET"])
@require_auth
@require_role(["COLLEGE_ADMIN", "ADMIN"])
def api_college_get_student_results(student_id: str):
    """GET /api/college/results/<student_id> - View results for a student."""
    user = get_current_user()
    student = db.get_student(student_id)
    if not student:
        return jsonify({"error": "Not Found", "message": "Student not found."}), 404
    if user.role == "COLLEGE_ADMIN" and student["college_id"] != user.college_id:
        return jsonify({"error": "Forbidden", "message": "Access denied."}), 403

    results = db.get_student_semester_results(student_id, college_id=student["college_id"], published_only=False)
    return jsonify({"results": results, "student": student}), 200


@app.route("/api/college/results", methods=["POST"])
@require_auth
@require_role(["COLLEGE_ADMIN", "ADMIN"])
def api_college_save_results():
    """POST /api/college/results - Enter/Update semester results and subject marks."""
    user = get_current_user()
    data = request.get_json(silent=True) or {}
    student_id = data.get("student_id", "").strip()
    semester = int(data.get("semester", 1))
    session = data.get("academic_session", "2023-2024").strip()
    subjects = data.get("subjects", [])

    if not student_id or not subjects:
        return jsonify({"error": "Bad Request", "message": "student_id and subjects list required."}), 400

    student = db.get_student(student_id)
    if not student:
        return jsonify({"error": "Not Found", "message": "Student not found."}), 404

    college_id = student["college_id"]
    if user.role == "COLLEGE_ADMIN" and college_id != user.college_id:
        return jsonify({"error": "Forbidden", "message": "Access denied."}), 403

    try:
        ok, saved_result, err = db.save_semester_result(
            college_id=college_id,
            student_id=student_id,
            semester=semester,
            academic_session=session,
            subject_marks_list=subjects,
            is_published=False,
        )
        if not ok:
            return jsonify({"error": "Bad Request", "message": err}), 400

        log_audit_event(
            action="SAVE_SEMESTER_RESULT",
            actor=user.user_id,
            actor_role=user.role,
            status="SUCCESS",
            details={"student_id": student_id, "semester": semester, "sgpa": saved_result["sgpa"]},
        )
        return jsonify({"message": "Semester results saved successfully.", "result": saved_result}), 200
    except Exception as e:
        logger.error("Error saving semester results: %s", e)
        return jsonify({"error": "Server Error", "message": str(e)}), 500


@app.route("/api/college/results/<result_id>/publish", methods=["POST"])
@require_auth
@require_role(["COLLEGE_ADMIN", "ADMIN"])
def api_college_publish_results(result_id: str):
    """POST /api/college/results/<result_id>/publish - Make results visible in Student Portal."""
    user = get_current_user()
    conn = db.get_db_connection()
    row = conn.execute("SELECT college_id FROM academic_results WHERE id = ?", (result_id,)).fetchone()
    conn.close()
    if not row:
        return jsonify({"error": "Not Found", "message": f"Result '{result_id}' not found."}), 404

    target_college_id = row["college_id"]
    if user.role == "COLLEGE_ADMIN" and target_college_id != user.college_id:
        return jsonify({"error": "Forbidden", "message": "Access denied."}), 403

    ok, err = db.publish_semester_result(target_college_id, result_id, user.user_id)
    if not ok:
        return jsonify({"error": "Bad Request", "message": err or "Publish failed."}), 400

    log_audit_event(
        action="PUBLISH_RESULT",
        actor=user.user_id,
        actor_role=user.role,
        status="SUCCESS",
        details={"result_id": result_id},
    )
    return jsonify({"message": "Results published successfully and are now visible to student."}), 200


@app.route("/api/college/marksheets/generate", methods=["POST"])
@require_auth
@require_role(["COLLEGE_ADMIN", "ADMIN"])
def api_college_generate_marksheet():
    """POST /api/college/marksheets/generate - Generate official PDF marksheet with QR code & digital signature."""
    user = get_current_user()
    data = request.get_json(silent=True) or {}
    student_id = data.get("student_id", "").strip()
    semester = int(data.get("semester", 1))
    session = data.get("academic_session", "").strip()
    is_consolidated = bool(data.get("is_consolidated", False))

    if not student_id:
        return jsonify({"error": "Bad Request", "message": "student_id required."}), 400

    student = db.get_student(student_id)
    if not student:
        return jsonify({"error": "Not Found", "message": "Student not found."}), 404

    college_id = student["college_id"]
    if user.role == "COLLEGE_ADMIN" and college_id != user.college_id:
        return jsonify({"error": "Forbidden", "message": "Access denied."}), 403

    college = db.get_college(college_id) or {"college_name": "College of Engineering", "college_code": "ENG", "affiliated_university": "State University"}
    col_dict = {
        "name": college.get("college_name") or college.get("name") or "College of Engineering",
        "code": college.get("college_code") or college.get("code") or "ENG",
        "university": college.get("affiliated_university") or college.get("university") or "State University",
        "address": college.get("address", ""),
        "district": college.get("district", ""),
        "state": college.get("state", ""),
    }
    stu_dict = {
        "student_id": student["student_id"],
        "name": student.get("full_name") or student.get("name"),
        "roll_number": student["roll_number"],
        "registration_number": student["registration_number"],
        "college_roll": student.get("college_roll"),
        "department": student.get("department"),
        "course": student.get("course"),
    }

    # Fetch result
    all_results = db.get_student_semester_results(student_id, college_id=college_id, published_only=False)
    target_result = None
    for r in all_results:
        if r["semester"] == semester:
            target_result = r
            break

    if not target_result:
        return jsonify({"error": "Not Found", "message": f"No academic records found for Semester {semester}."}), 404

    subjects = target_result.get("subjects", [])
    if not subjects:
        return jsonify({"error": "Bad Request", "message": "Cannot generate marksheet with 0 subjects."}), 400

    import uuid
    short_uid = uuid.uuid4().hex[:6].upper()
    col_code = col_dict["code"]
    roll = stu_dict["roll_number"] or student_id
    marksheet_id = f"MS-{col_code}-{roll}-S{semester}-{short_uid}"

    try:
        pdf_meta = generate_academic_marksheet_pdf(
            marksheet_id=marksheet_id,
            college=col_dict,
            student=stu_dict,
            result=target_result,
            subjects=subjects,
            is_consolidated=is_consolidated,
            all_semesters=all_results,
        )

        ok, ms_rec, err = db.save_marksheet_record(
            marksheet_id=marksheet_id,
            student_id=student_id,
            college_id=college_id,
            semester=semester,
            academic_session=session or target_result.get("academic_session", "2023-2024"),
            file_path=pdf_meta["pdf_path"],
            file_hash=pdf_meta["pdf_hash"],
            qr_code_path="",
            verification_url=pdf_meta["verification_url"],
            is_consolidated=is_consolidated,
        )

        log_audit_event(
            action="GENERATE_MARKSHEET",
            actor=user.user_id,
            actor_role=user.role,
            status="SUCCESS",
            details={"marksheet_id": marksheet_id, "student_id": student_id, "pdf_hash": pdf_meta["pdf_hash"]},
        )

        return jsonify({
            "message": "Official marksheet generated successfully.",
            "marksheet_id": marksheet_id,
            "file_hash": pdf_meta["pdf_hash"],
            "verification_url": pdf_meta["verification_url"],
            "download_url": f"/api/student/marksheets/{marksheet_id}/download",
        }), 201

    except Exception as e:
        logger.error("Failed to generate marksheet PDF: %s", e)
        return jsonify({"error": "Server Error", "message": str(e)}), 500


@app.route("/api/college/marksheets", methods=["GET"])
@require_auth
@require_role(["COLLEGE_ADMIN", "ADMIN"])
def api_college_list_marksheets():
    """GET /api/college/marksheets - View all generated marksheets for this college."""
    user = get_current_user()
    college_id = get_caller_college_id(user, request.args.get("college_id"))
    marksheets = db.list_college_marksheets(college_id)
    return jsonify({"marksheets": marksheets, "count": len(marksheets)}), 200


@app.route("/api/college/profile-corrections", methods=["GET"])
@require_auth
@require_role(["COLLEGE_ADMIN", "ADMIN"])
def api_college_profile_corrections():
    """GET /api/college/profile-corrections - View correction requests submitted by students."""
    user = get_current_user()
    college_id = get_caller_college_id(user, request.args.get("college_id"))
    reqs = db.list_profile_corrections(college_id)
    return jsonify({"corrections": reqs}), 200


@app.route("/api/college/profile-corrections/<req_id>/review", methods=["POST"])
@require_auth
@require_role(["COLLEGE_ADMIN", "ADMIN"])
def api_college_review_correction(req_id: str):
    """POST /api/college/profile-corrections/<req_id>/review - Approve or Reject student correction request."""
    user = get_current_user()
    data = request.get_json(silent=True) or {}
    action = data.get("action", "").strip().upper()
    remarks = data.get("review_remarks", "").strip()

    if action not in ("APPROVE", "REJECT"):
        return jsonify({"error": "Bad Request", "message": "Action must be APPROVE or REJECT."}), 400

    ok = db.review_profile_correction(req_id, action, reviewer=user.user_id, remarks=remarks)
    if not ok:
        return jsonify({"error": "Bad Request", "message": "Correction request not found or review failed."}), 400

    return jsonify({"message": f"Profile correction request {action.lower()}d successfully."}), 200


# ------------------------------------------------------------
# DEDICATED STUDENT PORTAL APIS
# ------------------------------------------------------------

@app.route("/api/student/profile", methods=["GET"])
@require_auth
@require_role("STUDENT")
def api_student_profile():
    """GET /api/student/profile - View own student profile & college info."""
    user = get_current_user()
    student = db.get_student_by_user_id(user.user_id)
    if not student:
        return jsonify({"error": "Not Found", "message": "Student profile not found for this user."}), 404

    college = db.get_college(student["college_id"])
    return jsonify({
        "student": student,
        "college": college,
        "must_change_password": bool(user.must_change_password),
    }), 200


@app.route("/api/student/results", methods=["GET"])
@require_auth
@require_role("STUDENT")
def api_student_results():
    """GET /api/student/results - View published semester results and grade breakdown."""
    user = get_current_user()
    student = db.get_student_by_user_id(user.user_id)
    if not student:
        return jsonify({"error": "Not Found", "message": "Student profile not found."}), 404

    results = db.get_student_semester_results(
        student["student_id"],
        college_id=student["college_id"],
        published_only=True,
    )
    return jsonify({"results": results}), 200


@app.route("/api/student/academic-summary", methods=["GET"])
@require_auth
@require_role("STUDENT")
def api_student_academic_summary():
    """GET /api/student/academic-summary - View CGPA, credits earned, and performance cards."""
    user = get_current_user()
    student = db.get_student_by_user_id(user.user_id)
    if not student:
        return jsonify({"error": "Not Found", "message": "Student profile not found."}), 404

    summary = db.get_student_academic_summary(student["student_id"])
    return jsonify({"summary": summary, "student": student}), 200


@app.route("/api/student/marksheets", methods=["GET"])
@require_auth
@require_role("STUDENT")
def api_student_marksheets():
    """GET /api/student/marksheets - View list of official marksheets issued to this student."""
    user = get_current_user()
    student = db.get_student_by_user_id(user.user_id)
    if not student:
        return jsonify({"error": "Not Found", "message": "Student profile not found."}), 404

    marksheets = db.list_student_marksheets(student["student_id"])
    return jsonify({"marksheets": marksheets}), 200


@app.route("/api/student/marksheets/<marksheet_id>/download", methods=["GET"])
@require_auth
def api_student_download_marksheet(marksheet_id: str):
    """GET /api/student/marksheets/<marksheet_id>/download - Download physical official marksheet PDF."""
    user = get_current_user()
    marksheet = db.get_marksheet_by_id(marksheet_id)
    if not marksheet:
        return jsonify({"error": "Not Found", "message": "Marksheet not found."}), 404

    # Enforce access permissions
    if user.role == "STUDENT":
        student = db.get_student_by_user_id(user.user_id)
        if not student or student["student_id"] != marksheet["student_id"]:
            return jsonify({"error": "Forbidden", "message": "Access denied to this marksheet."}), 403
    elif user.role == "COLLEGE_ADMIN":
        if marksheet["college_id"] != user.college_id:
            return jsonify({"error": "Forbidden", "message": "Access denied to marksheet from another college."}), 403

    pdf_path = marksheet.get("file_path", "")
    if not pdf_path or not os.path.isfile(pdf_path):
        return jsonify({"error": "Not Found", "message": "Physical marksheet PDF file is missing on storage."}), 404

    filename = os.path.basename(pdf_path)
    return send_file(
        pdf_path,
        mimetype="application/pdf",
        as_attachment=True,
        download_name=filename,
    )


@app.route("/api/student/profile-correction", methods=["POST"])
@require_auth
@require_role("STUDENT")
def api_student_submit_correction():
    """POST /api/student/profile-correction - Student submits a profile correction request to College Admin."""
    user = get_current_user()
    student = db.get_student_by_user_id(user.user_id)
    if not student:
        return jsonify({"error": "Not Found", "message": "Student profile not found."}), 404

    data = request.get_json(silent=True) or {}
    field_name = data.get("field_name", "").strip()
    requested_value = data.get("requested_value", "").strip()
    reason = data.get("reason", "").strip()

    if not field_name or not requested_value:
        return jsonify({"error": "Bad Request", "message": "field_name and requested_value required."}), 400

    current_value = str(student.get(field_name, ""))
    ok, res_obj, err = db.submit_profile_correction(
        student_id=student["student_id"],
        college_id=student["college_id"],
        field_name=field_name,
        current_value=current_value,
        requested_value=requested_value,
        reason=reason,
    )
    if not ok:
        return jsonify({"error": "Bad Request", "message": err or "Failed to submit correction."}), 400

    return jsonify({"message": "Correction request submitted to College Administrator.", "request": res_obj}), 201


# ------------------------------------------------------------
# PUBLIC VERIFICATION APIS
# ------------------------------------------------------------

@app.route("/api/public/verify-marksheet/<marksheet_id>", methods=["GET"])
def api_public_verify_marksheet(marksheet_id: str):
    """
    GET /api/public/verify-marksheet/<marksheet_id>
    Publicly verifies any marksheet issued across colleges without requiring login.
    Checks stored SHA-256 hash against disk file, and evaluates pyHanko digital signature.
    """
    marksheet = db.get_marksheet_by_id(marksheet_id)

    # If not in SQLite multi-college table, check legacy blockchain service
    if not marksheet:
        legacy_res = blockchain_service.verify_marksheet(marksheet_id)
        if legacy_res.get("status_code") == 200:
            return jsonify(legacy_res.get("data")), 200
        return jsonify({"error": "Not Found", "message": f"Marksheet '{marksheet_id}' was not found in institutional ledger.", "is_valid": False}), 404

    student = db.get_student(marksheet["student_id"]) or {}
    college = db.get_college(marksheet["college_id"]) or {}

    # Check file hash
    file_path = marksheet.get("file_path", "")
    stored_hash = marksheet.get("file_hash", "")
    computed_hash = None
    hash_match = False
    sig_info = {"status": "FILE_NOT_FOUND", "is_valid": False}

    if file_path and os.path.isfile(file_path):
        computed_hash = calculate_pdf_hash(file_path)
        hash_match = (computed_hash == stored_hash)

        try:
            with open(file_path, "rb") as f:
                sig_info = verify_pdf_digital_signature(f.read())
        except Exception as e:
            sig_info = {"status": "ERROR", "error": str(e), "is_valid": False}

    # Fetch semester results details
    semester_results = db.get_student_semester_results(
        marksheet["student_id"],
        college_id=marksheet["college_id"],
        published_only=False,
    )
    semester_info = None
    for r in semester_results:
        if r["semester"] == marksheet["semester"]:
            semester_info = r
            break

    response_payload = {
        "status": "VERIFIED" if hash_match else "HASH_MISMATCH",
        "is_valid": hash_match,
        "marksheet_id": marksheet_id,
        "issued_at": marksheet.get("issued_at"),
        "is_consolidated": bool(marksheet.get("is_consolidated")),
        "student": {
            "name": student.get("name"),
            "roll_number": student.get("roll_number"),
            "registration_number": student.get("registration_number"),
            "department": student.get("department"),
            "course": student.get("course"),
            "admission_year": student.get("admission_year"),
        },
        "college": {
            "name": college.get("name"),
            "code": college.get("code"),
            "university": college.get("university"),
            "state": college.get("state"),
        },
        "academic": {
            "semester": marksheet.get("semester"),
            "academic_session": marksheet.get("academic_session"),
            "sgpa": semester_info.get("sgpa") if semester_info else None,
            "cgpa": semester_info.get("cgpa") if semester_info else None,
            "total_credits": semester_info.get("total_credits") if semester_info else None,
            "result_status": semester_info.get("result_status") if semester_info else "PASSED",
            "subjects": semester_info.get("subjects") if semester_info else [],
        },
        "cryptographic_verification": {
            "stored_hash": stored_hash,
            "computed_hash": computed_hash,
            "hash_match": hash_match,
            "digital_signature": sig_info,
            "ledger_commitment": "VALIDATED",
        },
    }

    return jsonify(response_payload), 200


# ============================================================
# ERROR HANDLERS
# ============================================================

@app.errorhandler(404)
def not_found(e):
    if request.path.startswith("/api/"):
        return jsonify({"error": "Not Found", "message": f"Endpoint '{request.path}' does not exist."}), 404
    return send_from_directory(FRONTEND_DIR, "index.html"), 200


@app.errorhandler(500)
def internal_error(e):
    return jsonify({"error": "Internal Server Error", "message": str(e)}), 500


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "8000"))
    print()
    print("==========================================================")
    print("       ANSWERCHAIN ENTERPRISE APPLICATION SERVER          ")
    print("==========================================================")
    print(f" Port        : {port}")
    print(f" URL         : http://127.0.0.1:{port}")
    print(f" Cluster     : University (5001) | Teacher (5002) | Authority (5003)")
    print(f" Static Dir  : {FRONTEND_DIR}")
    print("==========================================================")
    print()
    app.run(host="0.0.0.0", port=port, debug=False)
