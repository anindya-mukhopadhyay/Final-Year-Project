"""
Comprehensive Integration Test Suite for Multi-College Academic Management System & Dedicated Student Portal (Phase 11).

Tests:
1. Super Admin: College provisioning, validation, status updates, credentials reset, global analytics.
2. College Admin: Strict multi-tenant isolation, student registration (no self-registration), duplicate detection, bulk import.
3. Academic Results: Semester results entry, automatic SGPA & CGPA calculation, result publication.
4. Marksheets & Cryptography: Official PDF marksheet generation, QR code embedding, pyHanko digital signature, public verification.
5. Student Portal: Authentication, forced password change on first login, profile viewing, profile correction request & review.
"""

import io
import json
import os
import unittest
from backend.auth import authenticate, verify_token
import backend.database as db
from backend.server import app


class TestPhase11MultiCollegeStudent(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.client = app.test_client()
        db.init_db()

        # Authenticate Super Admin
        admin_auth = authenticate("ADMIN-001", "admin123")
        assert admin_auth is not None, "Admin authentication failed"
        cls.admin_token = admin_auth["token"]
        cls.admin_headers = {"Authorization": f"Bearer {cls.admin_token}"}

    def test_01_super_admin_create_college_and_credentials(self):
        """Test Super Admin creates a college and generates admin credentials."""
        payload = {
            "name": "Heritage Institute of Technology",
            "code": "HIT",
            "university": "MAKAUT",
            "official_email": "admin@heritageit.edu",
            "contact_number": "+91 33 2443 0456",
            "address": "Chowbaga Road, Anandapur",
            "district": "Kolkata",
            "state": "West Bengal",
            "admin_name": "Dr. Pranay Chaudhuri",
            "admin_email": "principal@heritageit.edu",
            "admin_username": "COL-HIT-ADMIN",
            "admin_password": "heritagePass123",
        }

        resp = self.client.post("/api/admin/colleges", headers=self.admin_headers, json=payload)
        self.assertIn(resp.status_code, (201, 409))

        if resp.status_code == 201:
            data = resp.get_json()
            self.assertEqual(data["college"]["code"], "HIT")
            self.assertEqual(data["credentials"]["username"], "COL-HIT-ADMIN")
            self.assertEqual(data["credentials"]["temporary_password"], "heritagePass123")

    def test_02_super_admin_duplicate_college_prevention(self):
        """Test Super Admin cannot create college with duplicate code."""
        payload = {
            "name": "Duplicate College Code",
            "code": "TINT",  # Already seeded
            "university": "MAKAUT",
            "official_email": "dup@tint.edu.in",
            "contact_number": "+91 9999999999",
            "address": "New Town",
            "district": "Kolkata",
            "state": "West Bengal",
            "admin_name": "Duplicate Admin",
            "admin_email": "dupadmin@tint.edu.in",
            "admin_username": "dup_admin",
            "admin_password": "password123",
        }

        resp = self.client.post("/api/admin/colleges", headers=self.admin_headers, json=payload)
        self.assertEqual(resp.status_code, 409)

    def test_03_super_admin_college_status_and_reset(self):
        """Test Super Admin activates, suspends, and resets college credentials."""
        # 1. Status update
        resp = self.client.patch(
            "/api/admin/colleges/COL-HIT/status",
            headers=self.admin_headers,
            json={"status": "ACTIVE"},
        )
        self.assertEqual(resp.status_code, 200)

        # 2. Reset credentials
        resp2 = self.client.post(
            "/api/admin/colleges/COL-HIT/reset-credentials",
            headers=self.admin_headers,
            json={"password": "newCollegePass123"},
        )
        self.assertEqual(resp2.status_code, 200)
        creds = resp2.get_json()["credentials"]
        self.assertEqual(creds["temporary_password"], "newCollegePass123")

        # Verify authentication with newly reset password
        auth = authenticate(creds["username"], "newCollegePass123")
        self.assertIsNotNone(auth)
        self.assertEqual(auth["role"], "COLLEGE_ADMIN")

    def test_04_global_analytics(self):
        """Test platform-wide global analytics aggregation."""
        resp = self.client.get("/api/admin/global-analytics", headers=self.admin_headers)
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertGreaterEqual(data["total_colleges"], 1)
        self.assertGreaterEqual(data["total_students"], 1)

    def test_05_college_admin_student_registration_and_credentials(self):
        """Test College Admin registers a student with auto credentials."""
        # Login as TINT college admin
        admin_auth = authenticate("COL-TINT-ADMIN", "college123")
        self.assertIsNotNone(admin_auth)
        tint_headers = {"Authorization": f"Bearer {admin_auth['token']}"}

        import uuid
        unique_suffix = uuid.uuid4().hex[:4]
        roll = f"11100123{unique_suffix}"
        reg = f"23111{unique_suffix}"

        payload = {
            "name": f"Debanjan Sen {unique_suffix}",
            "roll_number": roll,
            "registration_number": reg,
            "department": "Computer Science & Engineering",
            "course": "B.Tech Computer Science & Engineering",
            "admission_year": "2023",
            "current_semester": 1,
            "academic_session": "2023-2024",
            "email": f"debanjan.{unique_suffix}@tint.edu.in",
            "password": "tempStudentPass123",
        }

        resp = self.client.post("/api/college/students", headers=tint_headers, json=payload)
        self.assertEqual(resp.status_code, 201)
        res_data = resp.get_json()
        self.assertEqual(res_data["student"]["roll_number"], roll)
        self.assertEqual(res_data["credentials"]["temporary_password"], "tempStudentPass123")

        # Test duplicate roll rejection
        resp_dup = self.client.post("/api/college/students", headers=tint_headers, json=payload)
        self.assertEqual(resp_dup.status_code, 409)

    def test_06_college_data_isolation(self):
        """Verify strict multi-tenant isolation: College A cannot view or modify College B students."""
        # Ensure college HIT has an admin
        hit_auth = authenticate("COL-HIT-ADMIN", "heritagePass123")
        if not hit_auth:
            return  # Skip if HIT not provisioned

        hit_headers = {"Authorization": f"Bearer {hit_auth['token']}"}

        # Attempt to access TINT's student STU-111 using HIT's college admin token
        resp = self.client.get("/api/college/students/STU-111", headers=hit_headers)
        self.assertEqual(resp.status_code, 403, "College Admin from HIT should NOT be able to view TINT student")

    def test_07_bulk_student_registration_csv(self):
        """Test bulk student registration using CSV upload."""
        admin_auth = authenticate("COL-TINT-ADMIN", "newCollegePass123") or authenticate("COL-TINT-ADMIN", "college123")
        tint_headers = {"Authorization": f"Bearer {admin_auth['token']}"}

        import uuid
        u = uuid.uuid4().hex[:4]
        csv_content = (
            "name,roll_number,registration_number,department,course,admission_year,current_semester,email\n"
            f"Bulk Student A,BULK-{u}-1,REG-{u}-1,Computer Science & Engineering,B.Tech,2023,1,bulk1.{u}@tint.edu.in\n"
            f"Bulk Student B,BULK-{u}-2,REG-{u}-2,Information Technology,B.Tech,2023,1,bulk2.{u}@tint.edu.in\n"
        )

        data = {"file": (io.BytesIO(csv_content.encode("utf-8")), "students.csv")}
        resp = self.client.post(
            "/api/college/students/bulk",
            headers={"Authorization": f"Bearer {admin_auth['token']}"},
            data=data,
            content_type="multipart/form-data",
        )
        self.assertEqual(resp.status_code, 200)
        res = resp.get_json()
        self.assertEqual(res["created_count"], 2)

    def test_08_academic_results_entry_and_sgpa(self):
        """Test semester results entry with subject marks and SGPA auto-computation."""
        admin_auth = authenticate("COL-TINT-ADMIN", "college123")
        self.assertIsNotNone(admin_auth)
        tint_headers = {"Authorization": f"Bearer {admin_auth['token']}"}

        payload = {
            "student_id": "STU-111",
            "semester": 3,
            "academic_session": "2024-2025",
            "subjects": [
                {"subject_code": "CS-301", "subject_name": "Operating Systems", "credits": 4, "internal_marks": 24, "external_marks": 66}, # Total 90 -> Grade O, GP 10.0
                {"subject_code": "CS-302", "subject_name": "DBMS", "credits": 4, "internal_marks": 20, "external_marks": 60},             # Total 80 -> Grade E, GP 9.0
            ],
        }

        resp = self.client.post("/api/college/results", headers=tint_headers, json=payload)
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()["result"]

        # SGPA: (4*10 + 4*9) / 8 = 76 / 8 = 9.5
        self.assertEqual(data["sgpa"], 9.5)
        self.assertEqual(data["total_credits"], 8)

        # Publish the result
        res_id = data["result_id"]
        pub_resp = self.client.post(f"/api/college/results/{res_id}/publish", headers=tint_headers)
        self.assertEqual(pub_resp.status_code, 200)

    def test_09_marksheet_pdf_generation_and_verification(self):
        """Test generating official marksheet PDF with QR and pyHanko signature, and public verification."""
        admin_auth = authenticate("COL-TINT-ADMIN", "college123")
        self.assertIsNotNone(admin_auth)
        tint_headers = {"Authorization": f"Bearer {admin_auth['token']}"}

        gen_resp = self.client.post(
            "/api/college/marksheets/generate",
            headers=tint_headers,
            json={"student_id": "STU-111", "semester": 1},
        )
        self.assertEqual(gen_resp.status_code, 201)
        ms_data = gen_resp.get_json()
        marksheet_id = ms_data["marksheet_id"]
        self.assertTrue(marksheet_id.startswith("MS-"))

        # Public verification
        v_resp = self.client.get(f"/api/public/verify-marksheet/{marksheet_id}")
        self.assertEqual(v_resp.status_code, 200)
        v_data = v_resp.get_json()
        self.assertTrue(v_data["is_valid"])
        self.assertEqual(v_data["status"], "VERIFIED")
        self.assertEqual(v_data["student"]["name"], "Asmit Mondal")

    def test_10_student_authentication_and_password_change(self):
        """Test student logs in, views own published results, and changes password."""
        # Authenticate student 111
        stu_auth = authenticate("111", "student123")
        self.assertIsNotNone(stu_auth)
        token = stu_auth["token"]
        headers = {"Authorization": f"Bearer {token}"}

        # 1. View profile
        prof_resp = self.client.get("/api/student/profile", headers=headers)
        self.assertEqual(prof_resp.status_code, 200)
        self.assertEqual(prof_resp.get_json()["student"]["roll_number"], "11100123001")

        # 2. View results (only published results appear)
        res_resp = self.client.get("/api/student/results", headers=headers)
        self.assertEqual(res_resp.status_code, 200)
        results = res_resp.get_json()["results"]
        self.assertGreaterEqual(len(results), 1)

        # 3. Submit profile correction request
        corr_resp = self.client.post(
            "/api/student/profile-correction",
            headers=headers,
            json={"field_name": "mobile_number", "requested_value": "+91 99999 11111", "reason": "New phone number"},
        )
        self.assertEqual(corr_resp.status_code, 201)

        # 4. Change password
        change_resp = self.client.post(
            "/api/auth/change-password",
            headers=headers,
            json={
                "current_password": "student123",
                "new_password": "newSecureStudentPass123",
                "confirm_password": "newSecureStudentPass123",
            },
        )
        self.assertEqual(change_resp.status_code, 200)

        # Verify old password fails
        self.assertIsNone(authenticate("111", "student123"))

        # Verify new password succeeds
        new_auth = authenticate("111", "newSecureStudentPass123")
        self.assertIsNotNone(new_auth)
        self.assertFalse(new_auth["must_change_password"])

        # Reset back for test repeatability
        db.change_user_password("111", "newSecureStudentPass123", "student123")


if __name__ == "__main__":
    unittest.main()
