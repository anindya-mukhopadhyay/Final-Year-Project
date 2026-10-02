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

# Default public verification base URL
PUBLIC_VERIFY_BASE_URL = os.environ.get(
    "PUBLIC_VERIFY_BASE_URL",
    "http://127.0.0.1:8000/verify",
)


def get_verification_url(marksheet_id: str) -> str:
    """Build the clean public verification endpoint URL."""
    clean_id = marksheet_id.strip()
    return f"{PUBLIC_VERIFY_BASE_URL}/{clean_id}"


def generate_qr_png_bytes(marksheet_id: str) -> bytes:
    """Generate PNG bytes of QR code pointing to verification URL."""
    verify_url = get_verification_url(marksheet_id)
    qr = qrcode.QRCode(
        version=1,
        error_correction=ERROR_CORRECT_M,
        box_size=8,
        border=3,
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
