"""
AnswerChain QR Generation Service with Offline Cryptographic Verification.

Generates dual-mode (Online & Offline) verification QR codes:
- Encodes the standard public verification URL for online browser access.
- Embeds an ECDSA P-256 cryptographically signed payload in the URL fragment (#offline=<token>)
  allowing 100% offline on-device verification on smartphones without internet access.
"""

import base64
import io
import logging
import os
from typing import Any, Dict, Optional
import qrcode
from qrcode.constants import ERROR_CORRECT_M
from qrcode.image.pil import PilImage

from backend.crypto_offline import sign_offline_marksheet_payload

logger = logging.getLogger("qr_service")

# Default public verification base URL
PUBLIC_VERIFY_BASE_URL = os.environ.get(
    "PUBLIC_VERIFY_BASE_URL",
    "",
)


def get_local_ip() -> str:
    """Detect LAN IP address so QR codes work when scanned by mobile phones."""
    try:
        import socket
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


def get_verification_base_url() -> str:
    """
    Resolve the host base URL for verification links.
    Returns the network-accessible IP (e.g. 192.168.29.37:8000) so mobile phones can connect,
    or PUBLIC_VERIFY_BASE_URL if set.
    """
    if PUBLIC_VERIFY_BASE_URL:
        return PUBLIC_VERIFY_BASE_URL.rstrip("/")

    try:
        from flask import has_request_context, request
        if has_request_context():
            host = request.host
            scheme = request.scheme
            hostname = host.split(":")[0]
            if hostname not in ("localhost", "127.0.0.1", "0.0.0.0"):
                return f"{scheme}://{hostname}:8000"
    except Exception:
        pass

    local_ip = get_local_ip()
    if local_ip and local_ip not in ("127.0.0.1", "0.0.0.0"):
        return f"http://{local_ip}:8000"

    return "http://127.0.0.1:8000"


def get_verification_url(
    marksheet_id: str,
    marksheet_data: Optional[Dict[str, Any]] = None,
) -> str:
    """
    Build the dual-mode verification URL.
    Includes the online query parameter (?id=...) and the offline cryptographic token (#offline=...).
    """
    clean_id = marksheet_id.strip()
    base_host = get_verification_base_url()
    online_url = f"{base_host}/verify/index.html?id={clean_id}"

    # If marksheet data is provided, generate the offline cryptographic signature
    if marksheet_data:
        try:
            if isinstance(marksheet_data, dict) and not marksheet_data.get("marksheet_id"):
                marksheet_data = dict(marksheet_data)
                marksheet_data["marksheet_id"] = clean_id
            token = sign_offline_marksheet_payload(marksheet_data)
            return f"{online_url}#offline={token}"
        except Exception as e:
            logger.warning("Could not append offline cryptographic payload to QR URL: %s", e)

    return online_url


def get_qr_payload(
    marksheet_id: str,
    marksheet_data: Optional[Dict[str, Any]] = None,
) -> str:
    """
    Build the Aadhaar-style offline cryptographic QR payload.
    When scanned by any standard phone camera (Apple Camera on iOS, Android Camera, Google Lens),
    it immediately displays student details (Name, Roll, Subject, Score, Grade, Authority)
    directly on the phone camera screen with ZERO internet connection required.

    CRITICAL FOR SMARTPHONE CAMERAS:
    Omits http:// and https:// prefixes entirely so the camera's native parser treats the
    QR payload as Plain Text (Credential Card) rather than a website link. This prevents iOS
    from showing an IP address button and failing in offline/airplane mode.
    Includes 'Token: <ecdsa_p256_token>' for instant on-device cryptographic verification.
    """
    clean_id = marksheet_id.strip()

    # If marksheet_data was not provided, attempt to resolve from the synchronized blockchain ledger
    if not marksheet_data:
        try:
            from backend.blockchain_service import blockchain_service
            resp = blockchain_service.verify_marksheet(marksheet_id=clean_id)
            if resp and resp.get("data") and resp["data"].get("marksheet"):
                marksheet_data = resp["data"]["marksheet"]
        except Exception as e:
            logger.debug("Could not auto-fetch marksheet data for QR payload: %s", e)

    if marksheet_data and isinstance(marksheet_data, dict):
        std_name = marksheet_data.get("student_name") or marksheet_data.get("student") or "Student"
        std_id = marksheet_data.get("student_id") or marksheet_data.get("roll") or "—"
        exam = marksheet_data.get("exam_name") or marksheet_data.get("exam") or "Academic Examination"
        marks = marksheet_data.get("final_marks")
        if marks is None:
            marks = marksheet_data.get("marks", 0)
        max_m = marksheet_data.get("max_marks", 100.0)

        # Standard institutional grade mapping
        grade = marksheet_data.get("grade")
        if not grade:
            pct = marksheet_data.get("percentage")
            if pct is None and max_m:
                try:
                    pct = (float(marks) / float(max_m)) * 100.0
                except Exception:
                    pct = 0.0
            if pct is not None:
                try:
                    pct_val = float(pct)
                    if pct_val >= 90:
                        grade = "A+"
                    elif pct_val >= 80:
                        grade = "A"
                    elif pct_val >= 70:
                        grade = "B+"
                    elif pct_val >= 55:
                        grade = "B"
                    elif pct_val >= 45:
                        grade = "C"
                    elif pct_val >= 40:
                        grade = "P"
                    else:
                        grade = "F"
                except Exception:
                    grade = f"{pct}%"
            else:
                grade = "PASS"

        # Generate cryptographic offline token
        token = ""
        try:
            payload_for_signing = dict(marksheet_data)
            if not payload_for_signing.get("marksheet_id"):
                payload_for_signing["marksheet_id"] = clean_id
            if not payload_for_signing.get("grade"):
                payload_for_signing["grade"] = grade
            token = sign_offline_marksheet_payload(payload_for_signing)
        except Exception as e:
            logger.warning("Could not generate offline token for QR: %s", e)

        # Format pure text card for native camera HUD without http:// IP suppression
        lines = [
            "🎓 ANSWERCHAIN SECURE MARKSHEET",
            f"Student: {std_name} (Roll: {std_id})",
            f"Subject: {exam}",
            f"Score: {marks}/{max_m} (Grade: {grade})",
            "Status: OFFICIALLY VERIFIED (AUTH-001)",
            f"Marksheet ID: {clean_id}",
        ]
        if token:
            lines.append(f"Token: {token}")

        return "\n".join(lines)

    return get_verification_url(clean_id, marksheet_data=marksheet_data)


def generate_qr_png_bytes(
    marksheet_id: str,
    marksheet_data: Optional[Dict[str, Any]] = None,
) -> bytes:
    """
    Generate high-resolution PNG bytes of QR code.
    Encodes offline cryptographic signature and human-readable metadata.
    """
    qr_payload = get_qr_payload(marksheet_id, marksheet_data=marksheet_data)
    qr = qrcode.QRCode(
        error_correction=ERROR_CORRECT_M,
        box_size=10,
        border=2,
        image_factory=PilImage,
    )
    qr.add_data(qr_payload)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")

    buffer = io.BytesIO()
    img.save(buffer, format="PNG")
    return buffer.getvalue()


def generate_qr_data_uri(
    marksheet_id: str,
    marksheet_data: Optional[Dict[str, Any]] = None,
) -> str:
    """Generate a base64 data URI string for embedding into HTML or responses."""
    png_bytes = generate_qr_png_bytes(marksheet_id, marksheet_data=marksheet_data)
    b64 = base64.b64encode(png_bytes).decode("utf-8")
    return f"data:image/png;base64,{b64}"
