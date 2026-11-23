"""
Comprehensive test suite for Phase 12: Offline Cryptographic QR Verification (Aadhaar-style).
Tests ECDSA P-256 signing, tamper-detection, QR code generation, PDF inclusion,
API endpoints, and WebCrypto cross-platform verification parity.
"""

import base64
import json
import os
import shutil
import subprocess
import tempfile
import unittest

from backend.crypto_offline import (
    DEFAULT_AUTHORITY_ID,
    create_canonical_offline_document,
    get_offline_authority_public_jwk,
    get_offline_authority_public_key_raw_b64,
    get_or_create_offline_authority_keypair,
    sign_offline_marksheet_payload,
    verify_offline_marksheet_token,
)
from backend.marksheet_pdf import generate_marksheet_pdf
from backend.qr_service import (
    generate_qr_data_uri,
    generate_qr_png_bytes,
    get_verification_url,
)
from backend.server import app


class TestOfflineCryptographicQR(unittest.TestCase):

    def setUp(self):
        self.app = app
        self.client = self.app.test_client()

        self.sample_marksheet = {
            "marksheet_id": "MARKSHEET-OFFLINE-TEST01",
            "answer_script_id": "AS-2024-TEST01",
            "result_id": "RES-2024-TEST01",
            "evaluation_id": "EVAL-2024-TEST01",
            "student_id": "STU-2024-001",
            "student_name": "Aarav Sharma",
            "university": "Maulana Abul Kalam Azad University of Technology",
            "exam_name": "B.Tech Computer Science 8th Semester",
            "marks": 91,
            "final_marks": 91,
            "max_marks": 100,
            "percentage": 91.0,
            "grade": "91.0%",
            "marksheet_pdf_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "authority_id": "AUTH-001",
            "timestamp": "2026-11-24",
        }

    def test_01_keypair_generation_and_export(self):
        """Test persistent ECDSA P-256 keypair retrieval and public key export."""
        priv, pub = get_or_create_offline_authority_keypair()
        self.assertIsNotNone(priv)
        self.assertIsNotNone(pub)

        raw_b64 = get_offline_authority_public_key_raw_b64()
        raw_bytes = base64.b64decode(raw_b64)
        self.assertEqual(len(raw_bytes), 65, "Uncompressed EC public key must be exactly 65 bytes (0x04 || X || Y)")
        self.assertEqual(raw_bytes[0], 0x04, "First byte must be 0x04 indicating uncompressed curve point")

        jwk = get_offline_authority_public_jwk()
        self.assertEqual(jwk["kty"], "EC")
        self.assertEqual(jwk["crv"], "P-256")
        self.assertEqual(jwk["kid"], DEFAULT_AUTHORITY_ID)
        self.assertIn("x", jwk)
        self.assertIn("y", jwk)

    def test_02_canonical_document_creation(self):
        """Verify standard canonical document mapping with short keys."""
        doc = create_canonical_offline_document(self.sample_marksheet)
        self.assertEqual(doc["v"], 1)
        self.assertEqual(doc["id"], "MARKSHEET-OFFLINE-TEST01")
        self.assertEqual(doc["std"], "Aarav Sharma")
        self.assertEqual(doc["roll"], "STU-2024-001")
        self.assertEqual(doc["scr"], "91/100")
        self.assertEqual(doc["grd"], "91.0%")
        self.assertEqual(doc["auth"], "AUTH-001")

    def test_03_sign_and_verify_valid_token(self):
        """Sign a marksheet payload and verify it returns True with correct attributes."""
        token = sign_offline_marksheet_payload(self.sample_marksheet)
        self.assertIsInstance(token, str)
        self.assertGreater(len(token), 100)

        is_valid, decoded_doc, err = verify_offline_marksheet_token(token)
        self.assertTrue(is_valid)
        self.assertIsNone(err)
        self.assertEqual(decoded_doc["std"], "Aarav Sharma")
        self.assertEqual(decoded_doc["scr"], "91/100")
        self.assertEqual(decoded_doc["id"], "MARKSHEET-OFFLINE-TEST01")

    def test_04_tamper_detection_altered_score(self):
        """Tampering marks from 91 to 99 must fail signature verification."""
        token = sign_offline_marksheet_payload(self.sample_marksheet)

        # Decode package
        rem = len(token) % 4
        padded = token + ("=" * (4 - rem) if rem else "")
        pkg = json.loads(base64.urlsafe_b64decode(padded).decode("utf-8"))

        # Alter score in the document payload
        pkg["d"]["scr"] = "99/100"
        pkg["d"]["grd"] = "99.0%"

        tampered_bytes = json.dumps(pkg, separators=(",", ":")).encode("utf-8")
        tampered_token = base64.urlsafe_b64encode(tampered_bytes).decode("utf-8").rstrip("=")

        is_valid, doc, err = verify_offline_marksheet_token(tampered_token)
        self.assertFalse(is_valid, "Tampered score must fail cryptographic verification")
        self.assertIn("signature does not match", str(err).lower())

    def test_05_tamper_detection_altered_student_name(self):
        """Tampering student name must fail signature verification."""
        token = sign_offline_marksheet_payload(self.sample_marksheet)

        rem = len(token) % 4
        padded = token + ("=" * (4 - rem) if rem else "")
        pkg = json.loads(base64.urlsafe_b64decode(padded).decode("utf-8"))

        # Alter student name
        pkg["d"]["std"] = "Imposter Name"

        tampered_bytes = json.dumps(pkg, separators=(",", ":")).encode("utf-8")
        tampered_token = base64.urlsafe_b64encode(tampered_bytes).decode("utf-8").rstrip("=")

        is_valid, doc, err = verify_offline_marksheet_token(tampered_token)
        self.assertFalse(is_valid)
        self.assertIn("signature does not match", str(err).lower())

    def test_06_qr_url_generation_dual_mode(self):
        """Test dual-mode verification URL containing online ID and offline hash."""
        url = get_verification_url(
            self.sample_marksheet["marksheet_id"],
            marksheet_data=self.sample_marksheet,
        )
        self.assertIn("id=MARKSHEET-OFFLINE-TEST01", url)
        self.assertIn("#offline=", url)

        # Generate PNG bytes and data URI
        png_bytes = generate_qr_png_bytes(
            self.sample_marksheet["marksheet_id"],
            marksheet_data=self.sample_marksheet,
        )
        self.assertGreater(len(png_bytes), 500)
        self.assertEqual(png_bytes[:4], b"\x89PNG")

        data_uri = generate_qr_data_uri(
            self.sample_marksheet["marksheet_id"],
            marksheet_data=self.sample_marksheet,
        )
        self.assertTrue(data_uri.startswith("data:image/png;base64,"))

    def test_07_pdf_generation_with_offline_qr(self):
        """Test generating official PDF marksheet containing the offline cryptographic QR."""
        pdf_res = generate_marksheet_pdf(self.sample_marksheet, self.sample_marksheet["marksheet_id"])
        self.assertIn("pdf_path", pdf_res)
        self.assertTrue(os.path.isfile(pdf_res["pdf_path"]))
        self.assertGreater(os.path.getsize(pdf_res["pdf_path"]), 1000)

    def test_08_api_public_offline_key(self):
        """Test GET /api/authority/offline-public-key returns standard ECDSA P-256 metadata."""
        resp = self.client.get("/api/authority/offline-public-key")
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertEqual(data["authority_id"], DEFAULT_AUTHORITY_ID)
        self.assertEqual(data["algorithm"], "ECDSA")
        self.assertEqual(data["named_curve"], "P-256")
        self.assertEqual(data["hash"], "SHA-256")
        self.assertIn("raw_public_key_b64", data)
        self.assertIn("jwk", data)

    def test_09_api_verify_offline_endpoint(self):
        """Test POST /api/verify/offline verifies valid tokens and catches tampered ones."""
        valid_token = sign_offline_marksheet_payload(self.sample_marksheet)

        # Test valid
        resp_valid = self.client.post("/api/verify/offline", json={"token": valid_token})
        self.assertEqual(resp_valid.status_code, 200)
        data_valid = resp_valid.get_json()
        self.assertTrue(data_valid["verified"])
        self.assertEqual(data_valid["document"]["std"], "Aarav Sharma")

        # Test empty token
        resp_empty = self.client.post("/api/verify/offline", json={"token": ""})
        self.assertEqual(resp_empty.status_code, 400)

        # Test tampered token
        rem = len(valid_token) % 4
        padded = valid_token + ("=" * (4 - rem) if rem else "")
        pkg = json.loads(base64.urlsafe_b64decode(padded).decode("utf-8"))
        pkg["d"]["scr"] = "100/100"
        tampered_token = base64.urlsafe_b64encode(json.dumps(pkg).encode()).decode().rstrip("=")

        resp_tampered = self.client.post("/api/verify/offline", json={"token": tampered_token})
        self.assertEqual(resp_tampered.status_code, 400)
        data_tampered = resp_tampered.get_json()
        self.assertFalse(data_tampered["verified"])

    def test_10_node_webcrypto_parity(self):
        """Verify that Python-generated offline tokens verify in WebCrypto with zero error."""
        token = sign_offline_marksheet_payload(self.sample_marksheet)
        raw_pub_b64 = get_offline_authority_public_key_raw_b64()

        node_script = """
        const crypto = require('crypto');
        const token = process.argv[1];
        const pubB64 = process.argv[2];

        function canonicalStringify(obj) {
            if (typeof obj !== 'object' || obj === null) return JSON.stringify(obj);
            if (Array.isArray(obj)) return '[' + obj.map(canonicalStringify).join(',') + ']';
            const keys = Object.keys(obj).sort();
            return '{' + keys.map(k => JSON.stringify(k) + ':' + canonicalStringify(obj[k])).join(',') + '}';
        }

        async function verify() {
            let b64 = token.replace(/-/g, '+').replace(/_/g, '/');
            while (b64.length % 4) b64 += '=';
            const pkg = JSON.parse(Buffer.from(b64, 'base64').toString('utf-8'));

            const docBytes = Buffer.from(canonicalStringify(pkg.d), 'utf-8');
            const sigBytes = Buffer.from(pkg.s, 'base64');
            const pubBytes = Buffer.from(pubB64, 'base64');

            const key = await crypto.webcrypto.subtle.importKey(
                'raw',
                pubBytes,
                { name: 'ECDSA', namedCurve: 'P-256' },
                false,
                ['verify']
            );

            const ok = await crypto.webcrypto.subtle.verify(
                { name: 'ECDSA', hash: { name: 'SHA-256' } },
                key,
                sigBytes,
                docBytes
            );

            if (!ok) {
                console.error("WebCrypto signature verification failed!");
                process.exit(1);
            }
            console.log("WebCrypto Verified Successfully!");
            process.exit(0);
        }

        verify().catch(e => {
            console.error(e);
            process.exit(1);
        });
        """

        res = subprocess.run(["node", "-e", node_script, token, raw_pub_b64], capture_output=True, text=True)
        self.assertEqual(res.returncode, 0, f"Node WebCrypto failed: {res.stderr}")
        self.assertIn("WebCrypto Verified Successfully!", res.stdout)


if __name__ == "__main__":
    unittest.main()
