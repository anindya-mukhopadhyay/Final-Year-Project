"""
AnswerChain Application Server (Phase 7).

Provides the unified, enterprise-grade academic web application API layer.
Enforces strict server-side authentication, role-based authorization (RBAC),
and operational auditing while delegating distributed ledger duties to
the underlying blockchain cluster via BlockchainService.
"""

import io
import logging
import os
import sys
from typing import Any, Dict

from flask import Flask, jsonify, request, send_file, send_from_directory
from flask_cors import CORS

PROJECT_ROOT = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..")
)
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from backend.application_service import academic_service
from backend.audit import get_audit_events, log_audit_event
from backend.auth import (
    authenticate,
    get_user_by_id,
    list_teachers,
    revoke_token,
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
# STATIC FRONTEND ROUTES & PAGES
# ============================================================

@app.route("/", methods=["GET"])
def index():
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

    auth_result = authenticate(user_id, password)
    if not auth_result:
        log_audit_event(
            action="LOGIN",
            actor=user_id,
            actor_role="UNKNOWN",
            status="FAILED",
            details={"reason": "Invalid credentials or inactive user"},
        )
        return jsonify({
            "error": "Unauthorized",
            "message": "Invalid user ID or password.",
        }), 401

    log_audit_event(
        action="LOGIN",
        actor=auth_result["user_id"],
        actor_role=auth_result["role"],
        status="SUCCESS",
        details={"name": auth_result["name"]},
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
    """Return list of active teachers for assignment dropdown."""
    teachers = list_teachers()
    return jsonify({"teachers": teachers}), 200


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


@app.route("/api/teacher/assignments/<script_id>/evaluate", methods=["POST"])
@require_auth
@require_role(["TEACHER", "ADMIN"])
def teacher_evaluate(script_id: str):
    """
    POST /api/teacher/assignments/<id>/evaluate
    Body: {"marks": 85, "max_marks": 100, "comments": "Good work"}
    """
    user = get_current_user()
    data = request.get_json(silent=True) or {}
    marks = data.get("marks")
    max_marks = data.get("max_marks", 100)
    comments = data.get("comments")

    success, payload, status_code = academic_service.evaluate_assignment(
        current_user=user,
        answer_script_id=script_id,
        marks=marks,
        max_marks=max_marks,
        comments=comments,
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
    return jsonify(data), 200


@app.route("/api/authority/results/pending", methods=["GET"])
@require_auth
@require_role(["AUTHORITY", "ADMIN"])
def authority_pending_results():
    """GET /api/authority/results/pending"""
    scripts = academic_service.get_unified_scripts_status()
    pending = [s for s in scripts if s["evaluated"] and not s["finalized"]]
    return jsonify({"pending_results": pending}), 200


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
    network_resp = blockchain_service.get_network_status("UNIVERSITY")
    network_data = network_resp.get("data", {}) if network_resp["success"] else {}
    audit_events = get_audit_events(limit=20)
    scripts = academic_service.get_unified_scripts_status()

    return jsonify({
        "network": network_data,
        "recent_audit": audit_events,
        "total_scripts": len(scripts),
        "system_status": "ONLINE",
    }), 200


@app.route("/api/admin/network", methods=["GET"])
@require_auth
@require_role("ADMIN")
def admin_network():
    """GET /api/admin/network"""
    network_resp = blockchain_service.get_network_status("UNIVERSITY")
    return jsonify(network_resp.get("data", {})), network_resp.get("status_code", 200)


@app.route("/api/admin/audit", methods=["GET"])
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
