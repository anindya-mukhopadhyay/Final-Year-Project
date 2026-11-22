"""
AnswerChain QR Generation Service.

Generates cryptographic verification QR codes encoding only the public
verification URL, ensuring zero exposure of sensitive academic data in the QR matrix.
"""

import base64
import io
import os
from typing import Optional
import qrcode
from qrcode.constants import ERROR_CORRECT_M
from qrcode.image.pil import PilImage

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


def get_verification_url(marksheet_id: str) -> str:
    """Build the clean public verification endpoint URL."""
    clean_id = marksheet_id.strip()

    # If inside an active Flask HTTP request, use the request host (e.g. 192.168.29.37:8000 or custom host)
    try:
        from flask import has_request_context, request
        if has_request_context():
            host = request.host
            scheme = request.scheme
            return f"{scheme}://{host}/verify/{clean_id}"
    except Exception:
        pass

    if PUBLIC_VERIFY_BASE_URL:
        base = PUBLIC_VERIFY_BASE_URL.rstrip("/")
        return f"{base}/{clean_id}"

    local_ip = get_local_ip()
    return f"http://{local_ip}:8000/verify/{clean_id}"


def generate_qr_png_bytes(marksheet_id: str) -> bytes:
    """Generate PNG bytes of QR code pointing to verification URL."""
    verify_url = get_verification_url(marksheet_id)
    qr = qrcode.QRCode(
        version=1,
        error_correction=ERROR_CORRECT_M,
        box_size=8,
        border=3,
        image_factory=PilImage,
    )
    qr.add_data(verify_url)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")

    buffer = io.BytesIO()
    img.save(buffer, format="PNG")
    return buffer.getvalue()


def generate_qr_data_uri(marksheet_id: str) -> str:
    """Generate a base64 data URI string for embedding into HTML or responses."""
    png_bytes = generate_qr_png_bytes(marksheet_id)
    b64 = base64.b64encode(png_bytes).decode("utf-8")
    return f"data:image/png;base64,{b64}"
