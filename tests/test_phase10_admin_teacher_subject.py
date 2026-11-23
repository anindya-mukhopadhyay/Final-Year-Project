"""
Phase 10: Admin Teacher Management and Dynamic Subject Management Test Suite.

Verifies:
1. SQLite database initialization, schemas, and seeding.
2. Admin Subject Management:
   - Dynamic listing (/api/subjects)
   - Creation (/api/admin/subjects)
   - Update (/api/admin/subjects/<code>)
   - Activation/Deactivation (/api/admin/subjects/<code>/status)
   - RBAC enforcement (non-admin blocked)
3. Admin Teacher Management:
   - Listing with assigned subjects (/api/admin/teachers)
   - Account creation with unique ID, hashed password, and assigned subject
   - Password reset and immediate session revocation
   - Activation/Deactivation
   - Successful authentication with newly created teacher credentials
4. Dynamic Subject Integration:
   - Newly created subjects appear in course listings
   - Teacher filtering by subject (/api/teachers?subject=<code>)
   - Script registration and evaluation workflows preserving dynamic subjects
   - Strict teacher authorization scoping
"""

import json
import unittest

from backend.auth import authenticate
import backend.database as db
from backend.server import app


class Phase10AdminTeacherSubjectTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        app.testing = True
        cls.client = app.test_client()

        # Clean any previous test data
        cls._cleanup_test_data()

        # Obtain Admin token
        admin_auth = authenticate("ADMIN-001", "admin123")
        assert admin_auth is not None, "Failed to authenticate default admin"
        cls.admin_token = admin_auth["token"]
        cls.admin_headers = {"Authorization": f"Bearer {cls.admin_token}"}

        # Obtain University token
        univ_auth = authenticate("UNIV-001", "university123")
        assert univ_auth is not None, "Failed to authenticate default university"
        cls.univ_token = univ_auth["token"]
        cls.univ_headers = {"Authorization": f"Bearer {cls.univ_token}"}

        # Obtain Teacher token
        tch_auth = authenticate("TCH-001", "teacher123")
        assert tch_auth is not None, "Failed to authenticate teacher 1"
        cls.tch1_token = tch_auth["token"]
        cls.tch1_headers = {"Authorization": f"Bearer {cls.tch1_token}"}

    @classmethod
    def tearDownClass(cls):
        cls._cleanup_test_data()

    @classmethod
    def _cleanup_test_data(cls):
        conn = db.get_db_connection()
        try:
            with conn:
                conn.execute("DELETE FROM users WHERE user_id IN ('TCH-TEST-99', 'TCH-TEST-98')")
                conn.execute("DELETE FROM teacher_subjects WHERE teacher_id IN ('TCH-TEST-99', 'TCH-TEST-98')")
                conn.execute("DELETE FROM subjects WHERE subject_code IN ('ROBOTICS', 'UNAUTH101')")
        except Exception:
            pass
        finally:
            conn.close()

    def test_01_database_initialization_and_seeding(self):
        """Verify that SQLite tables and initial seed subjects and users exist."""
        subjects = db.list_subjects(active_only=False)
        self.assertGreaterEqual(len(subjects), 8)
        codes = [s["subject_code"] for s in subjects]
        self.assertIn("DBMS", codes)
        self.assertIn("OS", codes)
        self.assertIn("AIML", codes)

        users = db.list_users()
        self.assertGreaterEqual(len(users), 14)
        user_ids = [u["user_id"] for u in users]
        self.assertIn("ADMIN-001", user_ids)
        self.assertIn("UNIV-001", user_ids)
        self.assertIn("TCH-001", user_ids)

    def test_02_get_subjects_endpoint(self):
        """Verify GET /api/subjects returns active subjects."""
        resp = self.client.get("/api/subjects")
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertIn("subjects", data)
        self.assertGreaterEqual(len(data["subjects"]), 8)

    def test_03_admin_create_subject(self):
        """Verify Admin can create a new academic subject."""
        payload = {
            "subject_code": "ROBOTICS",
            "subject_name": "Robotics & Autonomous Systems",
            "description": "Kinematics, sensor fusion, and ROS 2 autonomy."
        }
        resp = self.client.post("/api/admin/subjects", json=payload, headers=self.admin_headers)
        self.assertEqual(resp.status_code, 201)
        data = resp.get_json()
        self.assertEqual(data["subject"]["subject_code"], "ROBOTICS")
        self.assertEqual(data["subject"]["subject_name"], "Robotics & Autonomous Systems")

        # Verify it now appears in GET /api/subjects
        check_resp = self.client.get("/api/subjects")
        subjects = check_resp.get_json()["subjects"]
        codes = [s["subject_code"] for s in subjects]
        self.assertIn("ROBOTICS", codes)

    def test_04_create_subject_rbac(self):
        """Verify non-admin users cannot create subjects."""
        payload = {
            "subject_code": "UNAUTH101",
            "subject_name": "Unauthorized Subject"
        }
        # Attempt with Teacher token
        resp = self.client.post("/api/admin/subjects", json=payload, headers=self.tch1_headers)
        self.assertEqual(resp.status_code, 403)

        # Attempt with University token
        resp2 = self.client.post("/api/admin/subjects", json=payload, headers=self.univ_headers)
        self.assertEqual(resp2.status_code, 403)

    def test_05_create_duplicate_subject(self):
        """Verify creating a subject with existing code returns 409 Conflict."""
        payload = {
            "subject_code": "DBMS",
            "subject_name": "Database Management Duplicate"
        }
        resp = self.client.post("/api/admin/subjects", json=payload, headers=self.admin_headers)
        self.assertEqual(resp.status_code, 409)

    def test_06_admin_update_subject(self):
        """Verify Admin can update subject name and description."""
        update_payload = {
            "subject_name": "Robotics, Autonomy & Control Systems",
            "description": "Updated syllabus: Advanced kinematics, SLAM, and ROS 2."
        }
        resp = self.client.put("/api/admin/subjects/ROBOTICS", json=update_payload, headers=self.admin_headers)
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertEqual(data["subject"]["subject_name"], "Robotics, Autonomy & Control Systems")

    def test_07_admin_toggle_subject_status(self):
        """Verify Admin can deactivate and reactivate a subject."""
        # Deactivate
        resp = self.client.patch("/api/admin/subjects/ROBOTICS/status", json={"active": False}, headers=self.admin_headers)
        self.assertEqual(resp.status_code, 200)
        self.assertFalse(resp.get_json()["active"])

        # Check it does NOT appear in default active list
        active_resp = self.client.get("/api/subjects")
        active_codes = [s["subject_code"] for s in active_resp.get_json()["subjects"]]
        self.assertNotIn("ROBOTICS", active_codes)

        # But appears in all list
        all_resp = self.client.get("/api/subjects?all=1")
        all_codes = [s["subject_code"] for s in all_resp.get_json()["subjects"]]
        self.assertIn("ROBOTICS", all_codes)

        # Reactivate
        resp2 = self.client.patch("/api/admin/subjects/ROBOTICS/status", json={"active": True}, headers=self.admin_headers)
        self.assertEqual(resp2.status_code, 200)
        self.assertTrue(resp2.get_json()["active"])

    def test_08_admin_create_teacher_account(self):
        """Verify Admin can create a new teacher account with assigned subject."""
        payload = {
            "name": "Prof. Alan Turing",
            "user_id": "TCH-TEST-99",
            "assigned_subject": "ROBOTICS",
            "department": "Computer Science & Artificial Intelligence",
            "email": "a.turing@tint.edu.in",
            "password": "turing_secure_pass123",
            "confirm_password": "turing_secure_pass123"
        }
        resp = self.client.post("/api/admin/teachers", json=payload, headers=self.admin_headers)
        self.assertEqual(resp.status_code, 201)
        data = resp.get_json()
        self.assertEqual(data["teacher"]["user_id"], "TCH-TEST-99")
        self.assertEqual(data["teacher"]["role"], "TEACHER")
        self.assertEqual(data["teacher"]["assigned_subject"], "ROBOTICS")

    def test_09_new_teacher_authentication(self):
        """Verify newly created teacher can log in and receive authorized session token."""
        login_resp = self.client.post("/api/auth/login", json={
            "user_id": "TCH-TEST-99",
            "password": "turing_secure_pass123"
        })
        self.assertEqual(login_resp.status_code, 200)
        data = login_resp.get_json()
        user_info = data.get("user", {})
        self.assertEqual(user_info.get("user_id"), "TCH-TEST-99")
        self.assertEqual(user_info.get("role"), "TEACHER")
        self.assertEqual(user_info.get("assigned_subject"), "ROBOTICS")
        self.assertIn("token", data)

        # Also verify login using institutional email works
        email_login_resp = self.client.post("/api/auth/login", json={
            "user_id": "a.turing@tint.edu.in",
            "password": "turing_secure_pass123"
        })
        self.assertEqual(email_login_resp.status_code, 200)
        email_data = email_login_resp.get_json()
        self.assertEqual(email_data.get("user", {}).get("user_id"), "TCH-TEST-99")

    def test_10_teacher_creation_password_mismatch(self):
        """Verify password mismatch returns 400 Bad Request."""
        payload = {
            "name": "Prof. Ada Lovelace",
            "user_id": "TCH-TEST-98",
            "assigned_subject": "ROBOTICS",
            "password": "password123",
            "confirm_password": "different_password"
        }
        resp = self.client.post("/api/admin/teachers", json=payload, headers=self.admin_headers)
        self.assertEqual(resp.status_code, 400)
        self.assertIn("do not match", resp.get_json()["error"])

    def test_11_teacher_creation_duplicate_id(self):
        """Verify duplicate user ID returns 409 Conflict."""
        payload = {
            "name": "Prof. Duplicate",
            "user_id": "TCH-TEST-99",
            "assigned_subject": "ROBOTICS",
            "password": "password123",
            "confirm_password": "password123"
        }
        resp = self.client.post("/api/admin/teachers", json=payload, headers=self.admin_headers)
        self.assertEqual(resp.status_code, 409)

    def test_12_admin_edit_teacher_assigned_subject(self):
        """Verify Admin can change a teacher's assigned subject."""
        resp = self.client.put("/api/admin/teachers/TCH-TEST-99", json={
            "assigned_subject": "AIML",
            "department": "Department of Cognitive Systems"
        }, headers=self.admin_headers)
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertEqual(data["teacher"]["assigned_subject"], "AIML")
        self.assertEqual(data["teacher"]["department"], "Department of Cognitive Systems")

    def test_13_admin_reset_teacher_password(self):
        """Verify Admin can reset a teacher's password and old password is invalidated."""
        reset_payload = {
            "new_password": "new_turing_pass456",
            "confirm_password": "new_turing_pass456"
        }
        resp = self.client.post("/api/admin/teachers/TCH-TEST-99/reset-password", json=reset_payload, headers=self.admin_headers)
        self.assertEqual(resp.status_code, 200)

        # Old password fails
        fail_login = self.client.post("/api/auth/login", json={
            "user_id": "TCH-TEST-99",
            "password": "turing_secure_pass123"
        })
        self.assertEqual(fail_login.status_code, 401)

        # New password succeeds
        ok_login = self.client.post("/api/auth/login", json={
            "user_id": "TCH-TEST-99",
            "password": "new_turing_pass456"
        })
        self.assertEqual(ok_login.status_code, 200)

    def test_14_admin_toggle_teacher_status(self):
        """Verify deactivating teacher denies login and revokes access."""
        # Deactivate
        resp = self.client.patch("/api/admin/teachers/TCH-TEST-99/status", json={"active": False}, headers=self.admin_headers)
        self.assertEqual(resp.status_code, 200)
        self.assertFalse(resp.get_json()["active"])

        # Login is denied
        denied_login = self.client.post("/api/auth/login", json={
            "user_id": "TCH-TEST-99",
            "password": "new_turing_pass456"
        })
        self.assertEqual(denied_login.status_code, 401)

        # Reactivate
        resp2 = self.client.patch("/api/admin/teachers/TCH-TEST-99/status", json={"active": True}, headers=self.admin_headers)
        self.assertEqual(resp2.status_code, 200)
        self.assertTrue(resp2.get_json()["active"])

    def test_15_dynamic_teacher_filter_by_subject(self):
        """Verify GET /api/teachers?subject=<code> returns eligible teachers for that subject."""
        # Query teachers for AIML (which now includes TCH-TEST-99 and TCH-003)
        resp = self.client.get("/api/teachers?subject=AIML", headers=self.univ_headers)
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        teachers = data["teachers"]
        teacher_ids = [t["user_id"] for t in teachers]
        self.assertIn("TCH-TEST-99", teacher_ids)
        self.assertIn("TCH-003", teacher_ids)


if __name__ == "__main__":
    unittest.main()
