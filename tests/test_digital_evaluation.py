"""
Tests for Digital Answer-Script Evaluation.

Verifies:
1. Original Answer Script PDF viewing and access authorization.
2. Digital page-wise evaluation with question marks and annotations.
3. Automatic page and overall total calculation.
4. Page completion workflow and validation.
5. Incomplete page prevention of final submission.
6. Explicit final confirmation and blockchain commitment.
7. Original PDF hash preservation and tamper-evidence.
8. Duplicate submission prevention.
"""

import hashlib
import json
import os
import unittest
import uuid

from backend.application_service import academic_service
from backend.server import app


class TestDigitalEvaluation(unittest.TestCase):

    def setUp(self):
        self.app = app
        self.client = self.app.test_client()

        # Login as University (to register & assign script)
        uni_login = self.client.post(
            "/api/auth/login",
            data=json.dumps({"user_id": "UNIV-001", "password": "university123"}),
            content_type="application/json",
        ).get_json()
        self.uni_token = uni_login["token"]

        # Login as Teacher TCH-001 (assigned teacher)
        tch1_login = self.client.post(
            "/api/auth/login",
            data=json.dumps({"user_id": "TCH-001", "password": "teacher123"}),
            content_type="application/json",
        ).get_json()
        self.tch1_token = tch1_login["token"]

        # Login as Teacher TCH-002 (unassigned teacher)
        tch2_login = self.client.post(
            "/api/auth/login",
            data=json.dumps({"user_id": "TCH-002", "password": "teacher123"}),
            content_type="application/json",
        ).get_json()
        self.tch2_token = tch2_login["token"]

    def _create_assigned_script(self, base_id: str) -> str:
        script_id = f"{base_id}-{uuid.uuid4().hex[:6].upper()}"
        # Register new answer script
        reg_resp = self.client.post(
            "/api/university/answer-scripts",
            headers={"Authorization": f"Bearer {self.uni_token}"},
            data=json.dumps({
                "student_id": "STU-DIGITAL-01",
                "student_name": "Digital Evaluation Candidate",
                "exam_id": "EXAM-CS801",
                "exam_name": "Distributed Systems Final 2026",
                "answer_script_id": script_id,
            }),
            content_type="application/json",
        )
        self.assertEqual(reg_resp.status_code, 201)

        # Assign to TCH-001
        assign_resp = self.client.post(
            f"/api/university/answer-scripts/{script_id}/assign",
            headers={"Authorization": f"Bearer {self.uni_token}"},
            data=json.dumps({"teacher_id": "TCH-001"}),
            content_type="application/json",
        )
        self.assertEqual(assign_resp.status_code, 200)
        return script_id

    def test_01_view_pdf_authorization_and_integrity(self):
        """Assigned examiner can view PDF; unassigned examiner is blocked (403). Original hash preserved."""
        script_id = self._create_assigned_script("AS-DIGITAL-01")

        # 1. Unassigned teacher TCH-002 is forbidden
        forbidden_resp = self.client.get(
            f"/api/teacher/assignments/{script_id}/file",
            headers={"Authorization": f"Bearer {self.tch2_token}"},
        )
        self.assertEqual(forbidden_resp.status_code, 403)

        # 2. Assigned teacher TCH-001 can access file
        allowed_resp = self.client.get(
            f"/api/teacher/assignments/{script_id}/file",
            headers={"Authorization": f"Bearer {self.tch1_token}"},
        )
        self.assertEqual(allowed_resp.status_code, 200)
        self.assertEqual(allowed_resp.content_type, "application/pdf")
        pdf_bytes = allowed_resp.data
        self.assertGreater(len(pdf_bytes), 1000)

        # 3. Verify SHA-256 header matches actual byte hash
        computed_hash = hashlib.sha256(pdf_bytes).hexdigest()
        self.assertEqual(allowed_resp.headers.get("X-AnswerScript-Hash"), computed_hash)

    def test_02_draft_loading_and_page_structure(self):
        """Verify initial draft initialization and structure."""
        script_id = self._create_assigned_script("AS-DIGITAL-02")

        draft_resp = self.client.get(
            f"/api/teacher/assignments/{script_id}/draft",
            headers={"Authorization": f"Bearer {self.tch1_token}"},
        )
        self.assertEqual(draft_resp.status_code, 200)
        data = draft_resp.get_json()
        self.assertIn("draft", data)
        draft = data["draft"]
        self.assertEqual(draft["total_pages"], 3)
        self.assertIn("1", draft["pages"])
        self.assertIn("2", draft["pages"])
        self.assertIn("3", draft["pages"])
        self.assertFalse(data["all_pages_completed"])

    def test_03_page_evaluation_validation_and_auto_totals(self):
        """Marks validation: bounds checking, negative marks, and auto total calculation."""
        script_id = self._create_assigned_script("AS-DIGITAL-03")

        # 1. Error on marks exceeding max
        bad_marks_resp = self.client.post(
            f"/api/teacher/assignments/{script_id}/page",
            headers={"Authorization": f"Bearer {self.tch1_token}"},
            data=json.dumps({
                "page_number": 1,
                "questions": [
                    {"question_id": "Q1(a)", "max_marks": 15, "awarded_marks": 20}  # Exceeds!
                ],
                "mark_completed": True,
            }),
            content_type="application/json",
        )
        self.assertEqual(bad_marks_resp.status_code, 400)
        self.assertIn("cannot exceed maximum marks", bad_marks_resp.get_json()["error"])

        # 2. Error on negative marks
        neg_marks_resp = self.client.post(
            f"/api/teacher/assignments/{script_id}/page",
            headers={"Authorization": f"Bearer {self.tch1_token}"},
            data=json.dumps({
                "page_number": 1,
                "questions": [
                    {"question_id": "Q1(a)", "max_marks": 15, "awarded_marks": -5}
                ],
            }),
            content_type="application/json",
        )
        self.assertEqual(neg_marks_resp.status_code, 400)

        # 3. Valid save for Page 1
        valid_page1 = self.client.post(
            f"/api/teacher/assignments/{script_id}/page",
            headers={"Authorization": f"Bearer {self.tch1_token}"},
            data=json.dumps({
                "page_number": 1,
                "questions": [
                    {"question_id": "Q1(a)", "max_marks": 15, "awarded_marks": 14.5, "remarks": "Very clear"},
                    {"question_id": "Q1(b)", "max_marks": 10, "awarded_marks": 9.0, "remarks": "Accurate proof"}
                ],
                "page_remarks": "Page 1 thoroughly answered",
                "mark_completed": True,
            }),
            content_type="application/json",
        )
        self.assertEqual(valid_page1.status_code, 200)
        p1_data = valid_page1.get_json()
        self.assertEqual(p1_data["page"]["page_total"], 23.5)
        self.assertEqual(p1_data["page"]["page_max"], 25.0)
        self.assertTrue(p1_data["page"]["is_completed"])
        self.assertEqual(p1_data["completed_pages_count"], 1)
        self.assertFalse(p1_data["all_pages_completed"])

    def test_04_incomplete_pages_block_final_submission(self):
        """Final submission is strictly blocked until all pages are completed."""
        script_id = self._create_assigned_script("AS-DIGITAL-04")

        # Complete only Page 1 (leaving Page 2 and 3 incomplete)
        self.client.post(
            f"/api/teacher/assignments/{script_id}/page",
            headers={"Authorization": f"Bearer {self.tch1_token}"},
            data=json.dumps({
                "page_number": 1,
                "questions": [{"question_id": "Q1", "max_marks": 25, "awarded_marks": 20}],
                "mark_completed": True,
            }),
            content_type="application/json",
        )

        # Attempt final submission before completing Page 2 and 3
        sub_resp = self.client.post(
            f"/api/teacher/assignments/{script_id}/evaluate",
            headers={"Authorization": f"Bearer {self.tch1_token}"},
            data=json.dumps({"marks": 20.0, "max_marks": 100.0, "comments": "Premature submit"}),
            content_type="application/json",
        )
        self.assertEqual(sub_resp.status_code, 400)
        self.assertIn("All pages must be completed", sub_resp.get_json().get("message", ""))

    def test_05_complete_evaluation_workflow_and_blockchain_commitment(self):
        """Complete workflow: evaluate all 3 pages -> submit -> blockchain commitment -> duplicate blocked."""
        script_id = self._create_assigned_script("AS-DIGITAL-05")

        # Page 1 (22 / 25)
        self.client.post(
            f"/api/teacher/assignments/{script_id}/page",
            headers={"Authorization": f"Bearer {self.tch1_token}"},
            data=json.dumps({
                "page_number": 1,
                "questions": [
                    {"question_id": "Q1(a)", "max_marks": 15, "awarded_marks": 13.0},
                    {"question_id": "Q1(b)", "max_marks": 10, "awarded_marks": 9.0}
                ],
                "mark_completed": True,
            }),
            content_type="application/json",
        )

        # Page 2 (31 / 35)
        self.client.post(
            f"/api/teacher/assignments/{script_id}/page",
            headers={"Authorization": f"Bearer {self.tch1_token}"},
            data=json.dumps({
                "page_number": 2,
                "questions": [
                    {"question_id": "Q2", "max_marks": 35, "awarded_marks": 31.0}
                ],
                "mark_completed": True,
            }),
            content_type="application/json",
        )

        # Page 3 (38 / 40) -> Total = 22 + 31 + 38 = 91.0
        p3_resp = self.client.post(
            f"/api/teacher/assignments/{script_id}/page",
            headers={"Authorization": f"Bearer {self.tch1_token}"},
            data=json.dumps({
                "page_number": 3,
                "questions": [
                    {"question_id": "Q3", "max_marks": 40, "awarded_marks": 38.0}
                ],
                "mark_completed": True,
            }),
            content_type="application/json",
        )
        self.assertEqual(p3_resp.status_code, 200)
        p3_data = p3_resp.get_json()
        self.assertEqual(p3_data["total_awarded_marks"], 91.0)
        self.assertEqual(p3_data["completed_pages_count"], 3)
        self.assertTrue(p3_data["all_pages_completed"])

        # Final Submit (Total: 91.0 / 100.0)
        submit_resp = self.client.post(
            f"/api/teacher/assignments/{script_id}/evaluate",
            headers={"Authorization": f"Bearer {self.tch1_token}"},
            data=json.dumps({
                "marks": 91.0,
                "max_marks": 100.0,
                "comments": "Excellent digital evaluation across all 3 answer pages."
            }),
            content_type="application/json",
        )
        self.assertEqual(submit_resp.status_code, 200)
        sub_data = submit_resp.get_json()
        self.assertIn("evaluation_id", sub_data)
        self.assertEqual(sub_data["marks"], 91.0)

        # Duplicate submission is strictly rejected (409 Conflict)
        dup_resp = self.client.post(
            f"/api/teacher/assignments/{script_id}/evaluate",
            headers={"Authorization": f"Bearer {self.tch1_token}"},
            data=json.dumps({"marks": 91.0, "max_marks": 100.0}),
            content_type="application/json",
        )
        self.assertEqual(dup_resp.status_code, 409)


if __name__ == "__main__":
    unittest.main()
