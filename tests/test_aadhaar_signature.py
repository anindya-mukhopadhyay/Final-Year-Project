"""
Test Suite for Aadhaar-Style Digital Signature Authenticity Indicators.

Verifies:
1. Green Tick (✓): Original signed PDF with valid institutional signature matching blockchain record.
2. Yellow Question Mark (?): Unsigned copy.
3. Red Tampered (✕): PDF modified / altered after signing (Rule 5: classified as INVALID / TAMPERED).
4. Yellow Question Mark (?): PDF signed by an unknown / untrusted issuer (Rule 6: distinguished from invalid).
"""

import io
import os
import unittest
from reportlab.pdfgen import canvas
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pyhanko.sign import fields, signers

from backend.application_service import AcademicApplicationService
from backend.blockchain_service import blockchain_service
from backend.marksheet_pdf import (
    generate_marksheet_pdf,
    sign_marksheet_pdf,
    verify_pdf_digital_signature,
)


class TestAadhaarStyleSignature(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.app_service = AcademicApplicationService()
        cls.ca_cert = "keys/answerchain_ca_cert.pem"
        cls.auth_cert = "keys/authority_pdf_cert.pem"
        cls.auth_key = "keys/authority_pdf_key.pem"
        cls.untrusted_cert = "keys/untrusted_pdf_cert.pem"
        cls.untrusted_key = "keys/untrusted_pdf_key.pem"

        # Ensure certificates exist
        assert os.path.isfile(cls.ca_cert), "AnswerChain Root CA cert missing"
        assert os.path.isfile(cls.auth_cert), "Institutional signer cert missing"
        assert os.path.isfile(cls.untrusted_cert), "Untrusted test cert missing"

    def test_scenario_1_original_signed_pdf_green_tick(self):
        """
        Scenario 1: Original signed PDF with valid institutional signature.
        Display: Green Tick (✓), 'Verified Original Certificate',
                 'Digitally signed by AnswerChain Authorized Institution.'
        """
        student_id = "STU-AADHAAR-001"
        student_name = "Ananya Mukherjee"
        exam_name = "Computer Science Tripos 2026"
        marksheet_id = "MARKSHEET-AADHAAR01"

        marksheet_data = {
            "student_id": student_id,
            "student_name": student_name,
            "university": "Techno International New Town",
            "exam_name": exam_name,
            "answer_script_id": "AS-AADHAAR-01",
            "result_id": "RES-AADHAAR-01",
            "evaluation_id": "EVAL-AADHAAR-01",
            "marksheet_data_hash": "a1b2c3d4e5f6",
            "final_marks": 94.0,
            "max_marks": 100.0,
            "percentage": 94.0,
        }

        # 1. Generate signed marksheet PDF
        pdf_info = generate_marksheet_pdf(marksheet_data, marksheet_id)
        pdf_path = pdf_info["pdf_path"]
        pdf_hash = pdf_info["pdf_hash"]

        with open(pdf_path, "rb") as f:
            signed_bytes = f.read()

        # 2. Check cryptographic signature directly
        sig_info = verify_pdf_digital_signature(signed_bytes, self.ca_cert)
        self.assertTrue(sig_info["has_signature"])
        self.assertTrue(sig_info["intact"])
        self.assertTrue(sig_info["valid"])
        self.assertTrue(sig_info["trusted"])
        self.assertEqual(sig_info["status"], "VERIFIED_TRUSTED")
        self.assertIn("AnswerChain Examination Authority", sig_info["signer_name"])
        self.assertIn("AnswerChain Root Certificate Authority", sig_info["issuer_name"])

        # 3. Simulate on-chain registration via mocked get_all_blockchain_transactions
        mock_txs = [
            {
                "transaction_id": "TX-FINALIZED-01",
                "block_number": 1,
                "data": {
                    "type": "RESULT_FINALIZED",
                    "result_id": "RES-AADHAAR-01",
                    "status": "FINALIZED",
                },
            },
            {
                "transaction_id": "TX-MARKSHEET-01",
                "block_number": 2,
                "data": {
                    "type": "MARKSHEET_REGISTERED",
                    "marksheet_id": marksheet_id,
                    "student_id": student_id,
                    "student_name": student_name,
                    "university": "Techno International New Town",
                    "exam_name": exam_name,
                    "result_id": "RES-AADHAAR-01",
                    "evaluation_id": "EVAL-AADHAAR-01",
                    "marksheet_pdf_hash": pdf_hash,
                    "final_marks": 94.0,
                    "max_marks": 100.0,
                    "percentage": 94.0,
                },
            },
        ]

        from unittest.mock import patch
        with patch.object(self.app_service, "get_all_blockchain_transactions", return_value=mock_txs):
            # 4. Verify via upload verification endpoint logic
            verified, payload, status_code = self.app_service.verify_uploaded_marksheet_pdf(
                file_name="Marksheet_Original.pdf",
                file_bytes=signed_bytes,
            )

        self.assertEqual(status_code, 200)
        self.assertTrue(verified)
        self.assertTrue(payload["verified"])
        self.assertEqual(payload["status"], "VERIFIED")

        # Check visual badge for Green Tick
        badge = payload.get("visual_badge", {})
        self.assertEqual(badge.get("type"), "GREEN_TICK")
        self.assertEqual(badge.get("icon"), "✓")
        self.assertEqual(badge.get("title"), "Verified Original Certificate")
        self.assertEqual(badge.get("subtitle"), "Digitally signed by AnswerChain Authorized Institution.")

        # Clean up
        if os.path.isfile(pdf_path):
            os.remove(pdf_path)

    def test_scenario_2_unsigned_copy_yellow_question(self):
        """
        Scenario 2: Unsigned PDF copy downloaded or obtained from unverified source.
        Display: Yellow Question Mark (?), 'Signature Not Verified',
                 'This document could not be authenticated as an official AnswerChain certificate.'
        """
        # Generate an unsigned PDF
        buf = io.BytesIO()
        c = canvas.Canvas(buf)
        c.drawString(100, 700, "Official-looking Marksheet but Unsigned")
        c.drawString(100, 680, "Marksheet ID: MARKSHEET-UNSIGNED-01")
        c.save()
        unsigned_bytes = buf.getvalue()

        # 1. Cryptographic inspection
        sig_info = verify_pdf_digital_signature(unsigned_bytes, self.ca_cert)
        self.assertFalse(sig_info["has_signature"])
        self.assertFalse(sig_info["intact"])
        self.assertEqual(sig_info["status"], "UNSIGNED")

        # 2. Upload verification
        verified, payload, status_code = self.app_service.verify_uploaded_marksheet_pdf(
            file_name="Unsigned_Copy.pdf",
            file_bytes=unsigned_bytes,
        )

        self.assertEqual(status_code, 404)
        self.assertFalse(verified)
        self.assertFalse(payload["verified"])
        self.assertEqual(payload.get("signature_status"), "UNSIGNED_COPY")

        # Check visual badge for Yellow Question Mark
        badge = payload.get("visual_badge", {})
        self.assertEqual(badge.get("type"), "YELLOW_QUESTION")
        self.assertEqual(badge.get("icon"), "?")
        self.assertEqual(badge.get("title"), "Signature Not Verified")
        self.assertEqual(badge.get("subtitle"), "This document could not be authenticated as an official AnswerChain certificate.")

    def test_scenario_3_modified_after_signing_red_tampered(self):
        """
        Scenario 3: PDF modified / altered after signing (Rule 5).
        Must classify as INVALID / TAMPERED internally and explain modification.
        Do NOT mislabel it as merely unknown.
        """
        marksheet_id = "MARKSHEET-TAMP-01"
        marksheet_data = {
            "student_id": "STU-TAMP-01",
            "student_name": "Tamper Test Student",
            "university": "Techno International New Town",
            "exam_name": "Security Audit Exam",
            "answer_script_id": "AS-TAMP-01",
            "result_id": "RES-TAMP-01",
            "evaluation_id": "EVAL-TAMP-01",
            "marksheet_data_hash": "deadbeef1234",
            "final_marks": 75.0,
            "max_marks": 100.0,
            "percentage": 75.0,
        }

        # Generate genuine signed PDF
        pdf_info = generate_marksheet_pdf(marksheet_data, marksheet_id)
        pdf_path = pdf_info["pdf_path"]

        with open(pdf_path, "rb") as f:
            original_signed_bytes = f.read()

        # Modify byte content in the stream of the signed PDF to simulate post-signing tampering
        byte_arr = bytearray(original_signed_bytes)
        stream_idx = byte_arr.find(b"stream") + 10
        byte_arr[stream_idx] = (byte_arr[stream_idx] + 1) % 256
        tampered_bytes = bytes(byte_arr)
        self.assertNotEqual(original_signed_bytes, tampered_bytes)

        # 1. Cryptographic inspection confirms tampering
        sig_info = verify_pdf_digital_signature(tampered_bytes, self.ca_cert)
        self.assertTrue(sig_info["has_signature"])
        self.assertFalse(sig_info["intact"])  # Integrity check must fail
        self.assertEqual(sig_info["status"], "TAMPERED_INVALID")
        self.assertIn("Bytes were modified or altered after signing", sig_info["explanation"])

        # 2. Upload verification: classified as TAMPERED_INVALID (Rule 5)
        verified, payload, status_code = self.app_service.verify_uploaded_marksheet_pdf(
            file_name="Altered_Marksheet.pdf",
            file_bytes=tampered_bytes,
        )

        self.assertEqual(status_code, 422)
        self.assertFalse(verified)
        self.assertFalse(payload["verified"])
        self.assertEqual(payload["status"], "TAMPERED_INVALID")
        self.assertEqual(payload["document_status"], "DOCUMENT_TAMPERED")

        # Check visual badge for Red Tampered
        badge = payload.get("visual_badge", {})
        self.assertEqual(badge.get("type"), "RED_TAMPERED")
        self.assertEqual(badge.get("icon"), "✕")
        self.assertEqual(badge.get("title"), "Document Tampered / Invalid")
        self.assertIn("modified after digital signing", badge.get("subtitle"))

        # Clean up
        if os.path.isfile(pdf_path):
            os.remove(pdf_path)

    def test_scenario_4_untrusted_issuer_yellow_question(self):
        """
        Scenario 4: PDF signed by an untrusted issuer (Rule 6 & Rule 8).
        Valid cryptographic format, but certificate is not signed by AnswerChain Root CA.
        Display: Yellow Question Mark (?), 'Signature Not Verified',
                 'This document could not be authenticated as an official AnswerChain certificate.'
        """
        buf = io.BytesIO()
        c = canvas.Canvas(buf)
        c.drawString(100, 700, "Official Looking Document Signed by Rogue Issuer")
        c.save()
        raw_bytes = buf.getvalue()

        # Sign using untrusted key and cert
        untrusted_signer = signers.SimpleSigner.load(
            key_file=self.untrusted_key,
            cert_file=self.untrusted_cert,
        )
        w = IncrementalPdfFileWriter(io.BytesIO(raw_bytes))
        meta = signers.PdfSignatureMetadata(
            field_name="AnswerChainInstitutionalSignature",
            reason="Fake Institutional Certification",
        )
        out_buf = io.BytesIO()
        signers.sign_pdf(w, meta, signer=untrusted_signer, output=out_buf)
        untrusted_signed_bytes = out_buf.getvalue()

        # 1. Cryptographic inspection confirms untrusted
        sig_info = verify_pdf_digital_signature(untrusted_signed_bytes, self.ca_cert)
        self.assertTrue(sig_info["has_signature"])
        self.assertTrue(sig_info["intact"])  # Bytes are intact
        self.assertFalse(sig_info["trusted"])  # But not trusted
        self.assertEqual(sig_info["status"], "UNTRUSTED_ISSUER")

        # 2. Upload verification: classified as UNTRUSTED_ISSUER
        verified, payload, status_code = self.app_service.verify_uploaded_marksheet_pdf(
            file_name="Untrusted_Signed_Marksheet.pdf",
            file_bytes=untrusted_signed_bytes,
        )

        self.assertEqual(status_code, 404)
        self.assertFalse(verified)
        self.assertFalse(payload["verified"])
        self.assertEqual(payload.get("signature_status"), "UNTRUSTED_ISSUER")

        # Check visual badge for Yellow Question Mark
        badge = payload.get("visual_badge", {})
        self.assertEqual(badge.get("type"), "YELLOW_QUESTION")
        self.assertEqual(badge.get("icon"), "?")
        self.assertEqual(badge.get("title"), "Signature Not Verified")
        self.assertEqual(badge.get("subtitle"), "This document could not be authenticated as an official AnswerChain certificate.")


if __name__ == "__main__":
    unittest.main()
