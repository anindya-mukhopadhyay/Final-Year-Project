"""
AnswerChain DigiLocker / National Academic Depository (NAD) Test Suite.

Verifies:
1. DigiLocker PullURI protocol resolution (by Roll Number and Semester).
2. DigiLocker PullDoc protocol (Official digitally signed PDF generation).
3. Cryptographic hash anchoring and blockchain verification.
4. Public verification and certificate listing APIs.
"""

import json
import os
import unittest
from typing import Any, Dict

from backend import database as db
from backend import digilocker
from backend import marksheet_pdf
from backend.server import app


class TestDigiLockerGateway(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        db.init_db()
        cls.client = app.test_client()

    def test_01_build_digilocker_uri(self):
        uri = digilocker.build_digilocker_uri("TINT", "2023-24", "11100123001", 1)
        self.assertTrue(uri.startswith("in.gov.nad.answerchain/marksheet/TINT/"))
        self.assertIn("11100123001-SEM1", uri)

    def test_02_resolve_pull_uri_success(self):
        res = digilocker.resolve_pull_uri(roll_number="11100123001", semester=1)
        self.assertEqual(res["status"], "SUCCESS")
        self.assertGreaterEqual(res["total_documents"], 1)
        doc = res["documents"][0]
        self.assertEqual(doc["doctype"], "DGMST")
        self.assertEqual(doc["semester"], 1)
        self.assertIn("11100123001", doc["doc_uri"])
        self.assertEqual(doc["roll_number"], "11100123001")

    def test_03_resolve_pull_uri_missing_roll(self):
        res = digilocker.resolve_pull_uri(roll_number="")
        self.assertEqual(res["status"], "FAILED")
        self.assertEqual(res["code"], "MISSING_PARAM")

    def test_04_resolve_pull_uri_student_not_found(self):
        res = digilocker.resolve_pull_uri(roll_number="99999999999")
        self.assertEqual(res["status"], "NOT_FOUND")
        self.assertEqual(res["code"], "STUDENT_NOT_FOUND")

    def test_05_pull_document_generation(self):
        success, pdf_path, meta, err = digilocker.pull_document(
            roll_number="11100123001",
            semester=1
        )
        self.assertTrue(success, f"pull_document failed: {err}")
        self.assertIsNotNone(pdf_path)
        self.assertTrue(os.path.isfile(pdf_path))
        self.assertIsNotNone(meta)
        self.assertEqual(meta["doctype"], "DGMST")
        self.assertEqual(meta["semester"], 1)
        self.assertTrue(meta["file_hash"])

        # Verify PDF hash integrity
        calculated_hash = marksheet_pdf.calculate_pdf_hash(pdf_path)
        self.assertEqual(calculated_hash, meta["file_hash"])

    def test_06_verify_digilocker_credential(self):
        # First ensure document is pulled
        success, pdf_path, meta, err = digilocker.pull_document(
            roll_number="11100123001",
            semester=1
        )
        self.assertTrue(success)

        # Verify by doc_id
        ver = digilocker.verify_digilocker_credential(meta["doc_id"])
        self.assertEqual(ver["status"], "VERIFIED")
        self.assertTrue(ver["verified"])
        self.assertEqual(ver["document"]["roll_number"], "11100123001")
        self.assertEqual(ver["document"]["semester"], 1)

        # Verify by roll number
        ver_roll = digilocker.verify_digilocker_credential("11100123001")
        self.assertEqual(ver_roll["status"], "VERIFIED")
        self.assertTrue(ver_roll["verified"])

    def test_07_api_pull_uri_endpoint(self):
        res = self.client.post(
            "/api/digilocker/v1/pull-uri",
            data=json.dumps({"roll_number": "11100123001", "semester": 1}),
            content_type="application/json"
        )
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertEqual(data["status"], "SUCCESS")
        self.assertTrue(len(data["documents"]) >= 1)

    def test_08_api_pull_doc_stream_pdf(self):
        # Discover URI
        res_uri = self.client.post(
            "/api/digilocker/v1/pull-uri",
            data=json.dumps({"roll_number": "11100123001", "semester": 1}),
            content_type="application/json"
        )
        doc_uri = res_uri.get_json()["documents"][0]["doc_uri"]

        # Pull document via GET with uri parameter
        res_doc = self.client.get(f"/api/digilocker/v1/pull-doc?uri={doc_uri}")
        self.assertEqual(res_doc.status_code, 200)
        self.assertEqual(res_doc.mimetype, "application/pdf")
        self.assertTrue(len(res_doc.data) > 1000)

    def test_09_api_pull_doc_json_metadata(self):
        res = self.client.get("/api/digilocker/v1/pull-doc?roll=11100123001&semester=1&format=json")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertEqual(data["status"], "SUCCESS")
        self.assertEqual(data["metadata"]["roll_number"], "11100123001")

    def test_10_api_verify_endpoint(self):
        res = self.client.get("/api/digilocker/v1/verify/11100123001")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertTrue(data["verified"])
        self.assertEqual(data["status"], "VERIFIED")

    def test_11_api_certificates_list(self):
        res = self.client.get("/api/digilocker/v1/certificates/11100123001")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertEqual(data["status"], "SUCCESS")
        self.assertTrue(len(data["documents"]) >= 1)


if __name__ == "__main__":
    unittest.main()
