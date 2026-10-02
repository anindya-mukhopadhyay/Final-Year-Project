"""
AnswerChain Phase 7A Test Suite: Public Marksheet Upload Authenticity Checker.

Validates:
1. test_valid_original_pdf              -> VERIFIED (200, matching hashes, metadata)
2. test_modified_pdf                    -> TAMPERED_OR_UNKNOWN (404)
3. test_random_pdf                      -> TAMPERED_OR_UNKNOWN (404)
4. test_missing_file                    -> HTTP 400
5. test_empty_file                      -> HTTP 400
6. test_non_pdf_file                    -> HTTP 400
7. test_oversized_file                  -> HTTP 400
8. test_public_endpoint_without_auth    -> Allowed (No auth token needed, returns 200)
9. test_existing_marksheet_id_verification -> VERIFIED (via GET /api/verify/<id>)
10. test_existing_qr_verification       -> VERIFIED (via GET /api/qr/<id> returns image/png)
"""

import io
import json
import os
import sys
import unittest
import hashlib

PROJECT_ROOT = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..")
)
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from backend.server import app

TEST_MARKSHEET_ID = "MARKSHEET-461E92F6E79C"
EXPECTED_PDF_HASH = "22e250a8b1d821eb97892d1d83a3fc952ab13b0f3527e22210e3a115112e675c"
ORIGINAL_PDF_PATH = os.path.join(
    PROJECT_ROOT, "generated", "marksheets", f"{TEST_MARKSHEET_ID}.pdf"
)


class Phase7APublicUploadVerificationTests(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.client = app.test_client()
        if not os.path.isfile(ORIGINAL_PDF_PATH):
            raise FileNotFoundError(
                f"Required verified test marksheet PDF not found at {ORIGINAL_PDF_PATH}"
            )
        with open(ORIGINAL_PDF_PATH, "rb") as f:
            cls.original_pdf_bytes = f.read()

        cls.original_pdf_hash = hashlib.sha256(cls.original_pdf_bytes).hexdigest()
        assert cls.original_pdf_hash.lower() == EXPECTED_PDF_HASH.lower(), (
            f"Hash mismatch for original test file: got {cls.original_pdf_hash}, expected {EXPECTED_PDF_HASH}"
        )

    # 1. test_valid_original_pdf
    def test_valid_original_pdf(self):
        """Upload the authentic registered marksheet PDF -> expect VERIFIED status."""
        data = {
            "file": (io.BytesIO(self.original_pdf_bytes), f"{TEST_MARKSHEET_ID}.pdf", "application/pdf")
        }
        resp = self.client.post(
            "/api/public/verify-upload",
            data=data,
            content_type="multipart/form-data",
        )
        self.assertEqual(resp.status_code, 200)
        body = resp.get_json()
        self.assertTrue(body.get("verified"))
        self.assertEqual(body.get("status"), "VERIFIED")
        self.assertEqual(body.get("marksheet_id"), TEST_MARKSHEET_ID)
        self.assertEqual(body.get("pdf_hash"), EXPECTED_PDF_HASH)
        self.assertEqual(body.get("result_status"), "FINALIZED")
        self.assertEqual(body.get("student_name"), "Sourav Ganguly")
        self.assertEqual(body.get("final_marks"), 88.0)
        self.assertIn("transaction_id", body)
        self.assertIn("block_index", body)

    # 2. test_modified_pdf
    def test_modified_pdf(self):
        """Modify a copy of the official PDF -> expect TAMPERED_OR_UNKNOWN status."""
        modified_bytes = self.original_pdf_bytes + b"\n%tampered_payload_byte_addition%"
        modified_hash = hashlib.sha256(modified_bytes).hexdigest()

        data = {
            "file": (io.BytesIO(modified_bytes), f"{TEST_MARKSHEET_ID}_modified.pdf", "application/pdf")
        }
        resp = self.client.post(
            "/api/public/verify-upload",
            data=data,
            content_type="multipart/form-data",
        )
        self.assertEqual(resp.status_code, 404)
        body = resp.get_json()
        self.assertFalse(body.get("verified"))
        self.assertEqual(body.get("status"), "TAMPERED_OR_UNKNOWN")
        self.assertEqual(body.get("uploaded_pdf_hash"), modified_hash)
        self.assertIn("does not match any registered AnswerChain marksheet", body.get("message", ""))

    # 3. test_random_pdf
    def test_random_pdf(self):
        """Upload a completely unrelated but syntactically valid PDF -> expect TAMPERED_OR_UNKNOWN."""
        random_pdf_bytes = (
            b"%PDF-1.4\n"
            b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n"
            b"2 0 obj\n<< /Type /Pages /Kids [] /Count 0 >>\nendobj\n"
            b"xref\n0 3\n0000000000 65535 f \n"
            b"trailer\n<< /Root 1 0 R >>\nstartxref\n100\n%%EOF\n"
        )
        data = {
            "file": (io.BytesIO(random_pdf_bytes), "sample_resume.pdf", "application/pdf")
        }
        resp = self.client.post(
            "/api/public/verify-upload",
            data=data,
            content_type="multipart/form-data",
        )
        self.assertEqual(resp.status_code, 404)
        body = resp.get_json()
        self.assertFalse(body.get("verified"))
        self.assertEqual(body.get("status"), "TAMPERED_OR_UNKNOWN")
        self.assertEqual(
            body.get("uploaded_pdf_hash"),
            hashlib.sha256(random_pdf_bytes).hexdigest(),
        )

    # 4. test_missing_file
    def test_missing_file(self):
        """POST without multipart 'file' field -> HTTP 400 Bad Request."""
        resp = self.client.post(
            "/api/public/verify-upload",
            data={},
            content_type="multipart/form-data",
        )
        self.assertEqual(resp.status_code, 400)
        body = resp.get_json()
        self.assertEqual(body.get("error"), "Bad Request")

    # 5. test_empty_file
    def test_empty_file(self):
        """POST with empty 0-byte file -> HTTP 400 Bad Request."""
        data = {
            "file": (io.BytesIO(b""), "empty.pdf", "application/pdf")
        }
        resp = self.client.post(
            "/api/public/verify-upload",
            data=data,
            content_type="multipart/form-data",
        )
        self.assertEqual(resp.status_code, 400)
        body = resp.get_json()
        self.assertIn("empty or missing", body.get("message", ""))

    # 6. test_non_pdf_file
    def test_non_pdf_file(self):
        """POST with non-PDF extension and content -> HTTP 400 Bad Request."""
        # Text file
        data = {
            "file": (io.BytesIO(b"This is a plain text file."), "notes.txt", "text/plain")
        }
        resp = self.client.post(
            "/api/public/verify-upload",
            data=data,
            content_type="multipart/form-data",
        )
        self.assertEqual(resp.status_code, 400)

        # File named .pdf but containing arbitrary non-PDF bytes (missing %PDF- magic header)
        fake_pdf = {
            "file": (io.BytesIO(b"NOT A REAL PDF FILE HEADER"), "fake.pdf", "application/pdf")
        }
        resp_fake = self.client.post(
            "/api/public/verify-upload",
            data=fake_pdf,
            content_type="multipart/form-data",
        )
        self.assertEqual(resp_fake.status_code, 400)
        self.assertIn("PDF specification", resp_fake.get_json().get("message", ""))

    # 7. test_oversized_file
    def test_oversized_file(self):
        """POST with file exceeding 10 MB limit -> HTTP 400 Bad Request."""
        # 10 MB + 1024 bytes
        oversized_bytes = b"%PDF-" + b"A" * (10 * 1024 * 1024 + 1024)
        data = {
            "file": (io.BytesIO(oversized_bytes), "huge.pdf", "application/pdf")
        }
        resp = self.client.post(
            "/api/public/verify-upload",
            data=data,
            content_type="multipart/form-data",
        )
        self.assertEqual(resp.status_code, 400)
        body = resp.get_json()
        self.assertIn("10 MB", body.get("message", ""))

    # 8. test_public_endpoint_without_auth
    def test_public_endpoint_without_auth(self):
        """Public endpoint must not require JWT or Authorization header."""
        data = {
            "file": (io.BytesIO(self.original_pdf_bytes), f"{TEST_MARKSHEET_ID}.pdf", "application/pdf")
        }
        # Explicitly ensure no headers passed
        resp = self.client.post(
            "/api/public/verify-upload",
            data=data,
            content_type="multipart/form-data",
            headers={},
        )
        # Must succeed with 200, not 401 or 403
        self.assertNotEqual(resp.status_code, 401)
        self.assertNotEqual(resp.status_code, 403)
        self.assertEqual(resp.status_code, 200)

    # 9. test_existing_marksheet_id_verification
    def test_existing_marksheet_id_verification(self):
        """Existing GET /api/verify/<marksheet_id> must remain fully working and return VERIFIED."""
        resp = self.client.get(f"/api/verify/{TEST_MARKSHEET_ID}")
        self.assertEqual(resp.status_code, 200)
        body = resp.get_json()
        self.assertTrue(body.get("verified"))
        self.assertEqual(body.get("status"), "VERIFIED")
        self.assertEqual(body.get("marksheet_id"), TEST_MARKSHEET_ID)
        self.assertEqual(body.get("marksheet_pdf_hash"), EXPECTED_PDF_HASH)

    # 10. test_existing_qr_verification
    def test_existing_qr_verification(self):
        """Existing GET /api/qr/<marksheet_id> must return a valid PNG image."""
        resp = self.client.get(f"/api/qr/{TEST_MARKSHEET_ID}")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.content_type, "image/png")
        self.assertTrue(resp.data.startswith(b"\x89PNG\r\n\x1a\n"))


if __name__ == "__main__":
    unittest.main()
