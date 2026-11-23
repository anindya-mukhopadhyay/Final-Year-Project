"""
AnswerChain Offline Cryptographic QR Verification Service.

Provides Aadhaar-style offline verifiable credentials:
- Uses ECDSA with NIST P-256 (secp256r1) and SHA-256.
- Signs canonical academic marksheet data with the Central Authority's private key.
- Produces compact, URL-safe base64 cryptographic tokens embedded in QR codes.
- Verifiable 100% offline on any smartphone or browser using the native WebCrypto API
  with zero internet connection and zero server round-trips.
"""

import base64
import json
import logging
import os
from typing import Any, Dict, Optional, Tuple

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import (
    decode_dss_signature,
    encode_dss_signature,
)

logger = logging.getLogger("crypto_offline")

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
KEY_STORAGE_DIR = os.path.join(PROJECT_ROOT, "data", "keys")

# Default Authority Actor ID for cryptographic certificate issuance
DEFAULT_AUTHORITY_ID = "AUTH-001"

_CACHED_PRIV_KEY: Optional[ec.EllipticCurvePrivateKey] = None
_CACHED_PUB_KEY: Optional[ec.EllipticCurvePublicKey] = None


def get_or_create_offline_authority_keypair(
    authority_id: str = DEFAULT_AUTHORITY_ID,
    key_dir: str = KEY_STORAGE_DIR,
) -> Tuple[ec.EllipticCurvePrivateKey, ec.EllipticCurvePublicKey]:
    """
    Retrieve or create persistent ECDSA NIST P-256 keypair for offline credentials.
    """
    global _CACHED_PRIV_KEY, _CACHED_PUB_KEY
    if _CACHED_PRIV_KEY is not None and _CACHED_PUB_KEY is not None:
        return _CACHED_PRIV_KEY, _CACHED_PUB_KEY

    os.makedirs(key_dir, exist_ok=True)
    clean_id = authority_id.strip().upper()
    priv_path = os.path.join(key_dir, f"{clean_id}_ecdsa_private.pem")
    pub_path = os.path.join(key_dir, f"{clean_id}_ecdsa_public.pem")

    if os.path.isfile(priv_path) and os.path.isfile(pub_path):
        try:
            with open(priv_path, "rb") as f:
                priv = serialization.load_pem_private_key(f.read(), password=None)
            with open(pub_path, "rb") as f:
                pub = serialization.load_pem_public_key(f.read())
            if isinstance(priv, ec.EllipticCurvePrivateKey) and isinstance(pub, ec.EllipticCurvePublicKey):
                _CACHED_PRIV_KEY = priv
                _CACHED_PUB_KEY = pub
                return priv, pub
        except Exception as e:
            logger.warning("Failed loading ECDSA offline keypair for %s: %s. Regenerating.", clean_id, e)

    # Generate new ECDSA P-256 keypair
    priv = ec.generate_private_key(ec.SECP256R1())
    pub = priv.public_key()

    priv_pem = priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub_pem = pub.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    with open(priv_path, "wb") as f:
        f.write(priv_pem)
    try:
        os.chmod(priv_path, 0o600)
    except Exception:
        pass

    with open(pub_path, "wb") as f:
        f.write(pub_pem)

    _CACHED_PRIV_KEY = priv
    _CACHED_PUB_KEY = pub
    logger.info("Generated persistent ECDSA P-256 offline keypair for %s at %s", clean_id, key_dir)
    return priv, pub


def get_offline_authority_public_key_raw_b64() -> str:
    """
    Export the Authority's uncompressed EC public key (65 bytes: 0x04 || X || Y)
    as a base64 string, which can be directly imported into browser WebCrypto API.
    """
    _, pub = get_or_create_offline_authority_keypair()
    raw_pub = pub.public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint,
    )
    return base64.b64encode(raw_pub).decode("utf-8")


def get_offline_authority_public_jwk() -> Dict[str, Any]:
    """
    Export the Authority's public key as standard JWK (JSON Web Key) for WebCrypto.
    """
    _, pub = get_or_create_offline_authority_keypair()
    numbers = pub.public_numbers()
    x_bytes = numbers.x.to_bytes(32, "big")
    y_bytes = numbers.y.to_bytes(32, "big")

    return {
        "kty": "EC",
        "crv": "P-256",
        "x": base64.urlsafe_b64encode(x_bytes).decode("utf-8").rstrip("="),
        "y": base64.urlsafe_b64encode(y_bytes).decode("utf-8").rstrip("="),
        "kid": DEFAULT_AUTHORITY_ID,
        "use": "sig",
        "alg": "ES256",
    }


def create_canonical_offline_document(marksheet_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Extract standard verifiable attributes into canonical format with short keys.
    """
    mid = marksheet_data.get("marksheet_id") or marksheet_data.get("id", "")
    std_name = marksheet_data.get("student_name") or marksheet_data.get("name", "Student")
    roll = marksheet_data.get("student_id") or marksheet_data.get("roll", "")
    univ = marksheet_data.get("university") or marksheet_data.get("univ", "AnswerChain Institution")
    exam = marksheet_data.get("exam_name") or marksheet_data.get("exam", "University Examination")

    # Score handling: check final_marks, marks, total_marks
    marks = marksheet_data.get("final_marks")
    if marks is None:
        marks = marksheet_data.get("marks")
    if marks is None:
        marks = marksheet_data.get("total_marks", 0)
    max_marks = marksheet_data.get("max_marks", 100)
    score_str = f"{marks}/{max_marks}"

    grade = marksheet_data.get("grade")
    if not grade:
        pct = marksheet_data.get("percentage")
        if pct is not None:
            try:
                p = float(pct)
                if p >= 90:
                    grade = "A+"
                elif p >= 80:
                    grade = "A"
                elif p >= 70:
                    grade = "B+"
                elif p >= 55:
                    grade = "B"
                elif p >= 45:
                    grade = "C"
                elif p >= 40:
                    grade = "P"
                else:
                    grade = "F"
            except Exception:
                grade = f"{pct:.1f}%"
        else:
            grade = "PASS"

    hsh = marksheet_data.get("marksheet_pdf_hash") or marksheet_data.get("hsh", "")
    if len(hsh) > 24:
        hsh = hsh[:24]  # Compact hash prefix for QR matrix size optimization

    auth = marksheet_data.get("authority_id") or DEFAULT_AUTHORITY_ID
    dt = marksheet_data.get("timestamp") or marksheet_data.get("dt", "")
    if isinstance(dt, (int, float)):
        import datetime
        dt = datetime.datetime.fromtimestamp(dt, datetime.timezone.utc).strftime("%Y-%m-%d")

    return {
        "v": 1,
        "id": mid.strip(),
        "std": std_name.strip(),
        "roll": roll.strip(),
        "univ": univ.strip(),
        "exam": exam.strip(),
        "scr": score_str.strip(),
        "grd": str(grade).strip(),
        "auth": auth.strip(),
        "dt": str(dt).strip(),
        "hsh": hsh.strip(),
    }


def sign_offline_marksheet_payload(marksheet_data: Dict[str, Any]) -> str:
    """
    Sign canonical marksheet document with ECDSA P-256 and return a URL-safe base64 token.
    WebCrypto compatible: IEEE P1363 (64 bytes raw r || s) signature format.
    """
    priv, _ = get_or_create_offline_authority_keypair()
    doc = create_canonical_offline_document(marksheet_data)

    # Canonical deterministic JSON string
    canonical_str = json.dumps(doc, separators=(",", ":"), sort_keys=True)
    canonical_bytes = canonical_str.encode("utf-8")

    # Sign using ECDSA with SHA-256
    sig_der = priv.sign(canonical_bytes, ec.ECDSA(hashes.SHA256()))

    # Convert DER signature to WebCrypto IEEE P1363 64-byte raw (r || s)
    r, s = decode_dss_signature(sig_der)
    raw_sig = r.to_bytes(32, "big") + s.to_bytes(32, "big")
    sig_b64 = base64.b64encode(raw_sig).decode("utf-8")

    package = {
        "d": doc,
        "s": sig_b64,
        "kid": DEFAULT_AUTHORITY_ID,
    }

    # URL-safe Base64 token without padding
    pkg_bytes = json.dumps(package, separators=(",", ":")).encode("utf-8")
    return base64.urlsafe_b64encode(pkg_bytes).decode("utf-8").rstrip("=")


def verify_offline_marksheet_token(
    token: str,
    custom_public_key: Optional[ec.EllipticCurvePublicKey] = None,
) -> Tuple[bool, Optional[Dict[str, Any]], Optional[str]]:
    """
    Verify an offline marksheet cryptographic token.
    Returns (is_valid, decoded_document, error_message).
    """
    try:
        # Re-add padding if needed
        rem = len(token) % 4
        padded = token + ("=" * (4 - rem) if rem else "")
        raw_pkg = base64.urlsafe_b64decode(padded)
        package = json.loads(raw_pkg.decode("utf-8"))

        doc = package.get("d")
        sig_b64 = package.get("s")
        if not doc or not sig_b64:
            return False, None, "Malformed offline token payload."

        canonical_str = json.dumps(doc, separators=(",", ":"), sort_keys=True)
        canonical_bytes = canonical_str.encode("utf-8")

        raw_sig = base64.b64decode(sig_b64)
        if len(raw_sig) != 64:
            return False, doc, "Invalid signature length (expected 64 bytes IEEE P1363)."

        r = int.from_bytes(raw_sig[:32], "big")
        s = int.from_bytes(raw_sig[32:], "big")
        sig_der = encode_dss_signature(r, s)

        pub_key = custom_public_key
        if pub_key is None:
            _, pub_key = get_or_create_offline_authority_keypair()

        pub_key.verify(sig_der, canonical_bytes, ec.ECDSA(hashes.SHA256()))
        return True, doc, None

    except InvalidSignature:
        return False, None, "Digital signature verification failed: signature does not match document data."
    except Exception as e:
        return False, None, f"Verification failed: {str(e)}"
