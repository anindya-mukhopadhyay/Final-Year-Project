"""
AnswerChain Phase 8 Test Suite: Production Security & Cryptographic Trust.

Comprehensive automated verification covering:
1. Valid transaction signature (Ed25519)
2. Invalid transaction signature rejection
3. Unauthorized actor rejection
4. Altered signed payload detection
5. Duplicate transaction replay protection
6. Invalid block rejection (structural)
7. Invalid previous hash rejection
8. Invalid block hash rejection
9. Teacher cannot finalize result (RBAC)
10. Teacher cannot modify finalized result (Academic Invariant)
11. Invalid / expired token rejection
12. Revoked token rejection (Logout)
13. Secrets and private keys not exposed through APIs
14. Public verification regression test
15. PDF hash verification regression test
16. Public upload checker regression test
17. Node recovery / synchronization
18. Peer authentication & validation
19. Chain synchronization with validation
20. Multi-vector tamper detection
21. Secure document storage abstraction
"""

import copy
import hashlib
import io
import json
import os
import sys
import time
import unittest

PROJECT_ROOT = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..")
)
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from backend.application_service import academic_service
from backend.audit import get_audit_events
from backend.auth import (
    authenticate,
    create_token,
    revoke_token,
    verify_token,
    _USERS,
)
from backend.crypto import (
    canonicalize_transaction_payload,
    generate_keypair,
    get_actor_public_key,
    load_keypair,
    sign_academic_transaction,
    sign_payload,
    verify_academic_transaction,
    verify_signature,
)
from backend.document_storage import document_storage
from backend.server import app
from nodes.node import NodeBlockchain, app as node_app, NODE_AUTH_TOKEN

TEST_MARKSHEET_ID = "MARKSHEET-461E92F6E79C"
EXPECTED_PDF_HASH = "22e250a8b1d821eb97892d1d83a3fc952ab13b0f3527e22210e3a115112e675c"
ORIGINAL_PDF_PATH = os.path.join(
    PROJECT_ROOT, "generated", "marksheets", f"{TEST_MARKSHEET_ID}.pdf"
)


class Phase8SecurityTests(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.client = app.test_client()
        cls.node_client = node_app.test_client()

        # Ensure original PDF exists for regression tests
        if os.path.isfile(ORIGINAL_PDF_PATH):
            with open(ORIGINAL_PDF_PATH, "rb") as f:
                cls.original_pdf_bytes = f.read()
        else:
            cls.original_pdf_bytes = b""

    # ========================================================
    # 1. VALID TRANSACTION SIGNATURE
    # ========================================================
    def test_01_valid_transaction_signature(self):
        """Verify that a deterministically signed academic payload validates cleanly."""
        payload = {
            "type": "ANSWER_SCRIPT_REGISTERED",
            "university": "TINT",
            "exam_id": "EXAM-2026-CS101",
            "answer_script_id": "AS-SEC-001",
            "file_name": "as_sec_001.pdf",
            "answer_script_hash": "a" * 64,
        }
        signed_tx = sign_academic_transaction(
            payload=payload,
            actor_id="UNIV-001",
            actor_role="UNIVERSITY",
        )
        self.assertIn("signature", signed_tx)
        self.assertIn("payload_hash", signed_tx)
        self.assertEqual(signed_tx["actor_id"], "UNIV-001")
        self.assertEqual(signed_tx["actor_role"], "UNIVERSITY")

        is_valid, err = verify_academic_transaction(signed_tx)
        self.assertTrue(is_valid, f"Verification failed with: {err}")
        self.assertIsNone(err)

    # ========================================================
    # 2. INVALID TRANSACTION SIGNATURE
    # ========================================================
    def test_02_invalid_transaction_signature(self):
        """Verify that a corrupted or forged signature is strictly rejected."""
        payload = {
            "type": "EVALUATION_SUBMITTED",
            "evaluation_id": "EVAL-SEC-001",
            "answer_script_id": "AS-SEC-001",
            "teacher_id": "TCH-001",
            "marks": 92.0,
            "max_marks": 100.0,
        }
        signed_tx = sign_academic_transaction(
            payload=payload,
            actor_id="TCH-001",
            actor_role="TEACHER",
        )
        # Corrupt the signature hex
        sig_chars = list(signed_tx["signature"])
        sig_chars[0] = "0" if sig_chars[0] != "0" else "1"
        signed_tx["signature"] = "".join(sig_chars)

        is_valid, err = verify_academic_transaction(signed_tx)
        self.assertFalse(is_valid)
        self.assertEqual(err, "SIGNATURE_INVALID")

    # ========================================================
    # 3. UNAUTHORIZED ACTOR
    # ========================================================
    def test_03_unauthorized_actor(self):
        """Verify that an actor cannot sign transactions outside their authorized role."""
        payload = {
            "type": "ANSWER_SCRIPT_REGISTERED",
            "university": "TINT",
            "exam_id": "EXAM-2026-CS101",
            "answer_script_id": "AS-SEC-UNAUTH",
            "file_name": "as.pdf",
            "answer_script_hash": "b" * 64,
        }
        # TCH-001 attempts to sign an action reserved for UNIVERSITY
        signed_tx = sign_academic_transaction(
            payload=payload,
            actor_id="TCH-001",
            actor_role="UNIVERSITY",  # Falsely claimed role
        )
        is_valid, err = verify_academic_transaction(signed_tx)
        self.assertFalse(is_valid)
        self.assertEqual(err, "ACTOR_NOT_AUTHORIZED")

        # Unknown actor ID
        unknown_tx = copy.deepcopy(signed_tx)
        unknown_tx["actor_id"] = "ROGUE-999"
        is_valid_unknown, err_unknown = verify_academic_transaction(unknown_tx)
        self.assertFalse(is_valid_unknown)
        self.assertEqual(err_unknown, "UNKNOWN_ACTOR")

    # ========================================================
    # 4. ALTERED SIGNED PAYLOAD
    # ========================================================
    def test_04_altered_signed_payload(self):
        """Verify that altering even a single field in a signed transaction invalidates it."""
        payload = {
            "type": "EVALUATION_SUBMITTED",
            "evaluation_id": "EVAL-SEC-002",
            "answer_script_id": "AS-SEC-002",
            "teacher_id": "TCH-001",
            "marks": 75.0,
            "max_marks": 100.0,
        }
        signed_tx = sign_academic_transaction(
            payload=payload,
            actor_id="TCH-001",
            actor_role="TEACHER",
        )
        # Malicious actor changes marks to 98.0 without resigning
        tampered_tx = copy.deepcopy(signed_tx)
        tampered_tx["marks"] = 98.0

        is_valid, err = verify_academic_transaction(tampered_tx)
        self.assertFalse(is_valid)
        self.assertIn(err, ("PAYLOAD_HASH_MISMATCH", "SIGNATURE_INVALID"))

    # ========================================================
    # 5. DUPLICATE TRANSACTION REPLAY
    # ========================================================
    def test_05_duplicate_transaction_replay(self):
        """Verify that submitting the same answer script registration twice is rejected with 409."""
        as_id = f"AS-REPLAY-{int(time.time() * 1000)}"
        payload = {
            "university": "TINT",
            "exam_id": "EXAM-REPLAY",
            "answer_script_id": as_id,
            "file_name": "replay.pdf",
            "file_hash": "c" * 64,
        }
        # First submission succeeds
        resp1 = self.node_client.post("/answer-scripts/register", json=payload)
        self.assertEqual(resp1.status_code, 200)

        # Duplicate submission is rejected
        resp2 = self.node_client.post("/answer-scripts/register", json=payload)
        self.assertEqual(resp2.status_code, 409)
        self.assertIn("already registered", resp2.get_json().get("error", ""))

    # ========================================================
    # 6. INVALID BLOCK (STRUCTURAL)
    # ========================================================
    def test_06_invalid_block(self):
        """Verify that an incomplete or structurally invalid block is rejected."""
        malformed_block = {
            "index": 999,
            "timestamp": time.time(),
            # Missing "data", "previous_hash", "hash"
        }
        resp = self.node_client.post(
            "/receive-block",
            json={"block": malformed_block},
        )
        self.assertEqual(resp.status_code, 400)
        self.assertEqual(resp.get_json().get("error"), "INVALID_BLOCK_STRUCTURE")

    # ========================================================
    # 7. INVALID PREVIOUS HASH
    # ========================================================
    def test_07_invalid_previous_hash(self):
        """Verify that a block referencing an invalid previous_hash fails chain validation."""
        nb = NodeBlockchain()
        self.assertTrue(nb.is_valid_chain(nb.chain))

        corrupted_chain = copy.deepcopy(nb.chain)
        if len(corrupted_chain) > 1:
            corrupted_chain[-1]["previous_hash"] = "0" * 64
            self.assertFalse(nb.is_valid_chain(corrupted_chain))

    # ========================================================
    # 8. INVALID BLOCK HASH
    # ========================================================
    def test_08_invalid_block_hash(self):
        """Verify that a block with an altered or forged hash is rejected."""
        nb = NodeBlockchain()
        corrupted_chain = copy.deepcopy(nb.chain)
        if len(corrupted_chain) > 1:
            corrupted_chain[-1]["hash"] = "deadbeef" * 8
            self.assertFalse(nb.is_valid_chain(corrupted_chain))

        # Test receive-block endpoint with forged hash
        latest = nb.chain[-1]
        forged_block = {
            "index": latest["index"] + 1,
            "timestamp": time.time(),
            "data": [],
            "previous_hash": latest["hash"],
            "hash": "badhash" * 9,
        }
        resp = self.node_client.post(
            "/receive-block",
            json={"block": forged_block},
        )
        self.assertEqual(resp.status_code, 409)
        self.assertEqual(resp.get_json().get("error"), "INVALID_BLOCK_HASH")

    # ========================================================
    # 9. TEACHER CANNOT FINALIZE
    # ========================================================
    def test_09_teacher_cannot_finalize(self):
        """Verify that a Teacher role attempting to call Authority endpoints is blocked (403)."""
        auth_tch = authenticate("TCH-001", "teacher123")
        self.assertIsNotNone(auth_tch)
        token = auth_tch["token"]

        headers = {"Authorization": f"Bearer {token}"}
        resp = self.client.post(
            "/api/results/finalize",
            json={"answer_script_id": "AS-004"},
            headers=headers,
        )
        self.assertEqual(resp.status_code, 403)
        self.assertEqual(resp.get_json().get("error"), "Forbidden")

        # Verify audit event recorded AUTHORIZATION_DENIED
        audits = get_audit_events(limit=5, action="AUTHORIZATION_DENIED")
        self.assertTrue(len(audits) > 0)
        self.assertEqual(audits[0]["actor"], "TCH-001")
        self.assertEqual(audits[0]["status"], "DENIED")

    # ========================================================
    # 10. TEACHER CANNOT MODIFY FINALIZED RESULT
    # ========================================================
    def test_10_teacher_cannot_modify_finalized_result(self):
        """Verify that once a result is FINALIZED, an evaluation cannot be submitted or changed."""
        resp = self.node_client.post(
            "/evaluations/submit",
            json={
                "answer_script_id": "AS-004",  # Already finalized on ledger
                "teacher_id": "TCH-004",
                "marks": 99.0,
                "max_marks": 100.0,
            },
        )
        self.assertEqual(resp.status_code, 409)
        self.assertIn("already finalized and cannot be modified", resp.get_json().get("error", ""))

    # ========================================================
    # 11. INVALID / EXPIRED TOKEN
    # ========================================================
    def test_11_invalid_expired_token(self):
        """Verify that invalid and expired session tokens return consistent 401 responses."""
        # 1. No token
        resp1 = self.client.get("/api/auth/me")
        self.assertEqual(resp1.status_code, 401)

        # 2. Garbage token
        resp2 = self.client.get(
            "/api/auth/me",
            headers={"Authorization": "Bearer invalid.token.payload.xyz"},
        )
        self.assertEqual(resp2.status_code, 401)

        # 3. Expired token simulation
        user = _USERS["UNIV-001"]
        token = create_token(user)
        # Verify valid token works
        self.assertIsNotNone(verify_token(token))

        # Manually expire in active sessions
        from backend.auth import _ACTIVE_SESSIONS
        _ACTIVE_SESSIONS[token]["expires_at"] = time.time() - 3600

        # Now verify_token must return None
        self.assertIsNone(verify_token(token))

        resp3 = self.client.get(
            "/api/auth/me",
            headers={"Authorization": f"Bearer {token}"},
        )
        self.assertEqual(resp3.status_code, 401)

    # ========================================================
    # 12. REVOKED TOKEN (LOGOUT)
    # ========================================================
    def test_12_revoked_token(self):
        """Verify that session tokens are revoked upon logout and cannot be reused."""
        auth = authenticate("UNIV-001", "university123")
        self.assertIsNotNone(auth)
        token = auth["token"]
        headers = {"Authorization": f"Bearer {token}"}

        # Check me works
        me_resp = self.client.get("/api/auth/me", headers=headers)
        self.assertEqual(me_resp.status_code, 200)

        # Log out
        logout_resp = self.client.post("/api/auth/logout", headers=headers)
        self.assertEqual(logout_resp.status_code, 200)

        # Token is now revoked -> should be 401
        me_after_logout = self.client.get("/api/auth/me", headers=headers)
        self.assertEqual(me_after_logout.status_code, 401)

    # ========================================================
    # 13. SECRET NOT EXPOSED THROUGH API
    # ========================================================
    def test_13_secret_not_exposed_through_api(self):
        """Verify that neither passwords, password hashes, nor private keys leak in API responses."""
        # Login response
        auth = authenticate("ADMIN-001", "admin123")
        self.assertNotIn("password", auth)
        self.assertNotIn("password_hash", auth)
        self.assertNotIn("private_key", auth)

        # Teachers list
        token = auth["token"]
        headers = {"Authorization": f"Bearer {token}"}
        teachers_resp = self.client.get("/api/teachers", headers=headers)
        self.assertEqual(teachers_resp.status_code, 200)
        teachers_data = teachers_resp.get_json().get("teachers", [])
        for t in teachers_data:
            self.assertNotIn("password", t)
            self.assertNotIn("password_hash", t)
            self.assertNotIn("private_key", t)

        # Audit logs endpoint
        audit_resp = self.client.get("/api/audit-logs", headers=headers)
        self.assertEqual(audit_resp.status_code, 200)
        audit_raw = audit_resp.get_data(as_text=True).lower()
        self.assertNotIn("answerchain-dev-secret-key", audit_raw)
        self.assertNotIn("university123", audit_raw)
        self.assertNotIn("teacher123", audit_raw)
        self.assertNotIn("admin123", audit_raw)
        self.assertNotIn("private_key", audit_raw)

    # ========================================================
    # 14. PUBLIC VERIFICATION REGRESSION
    # ========================================================
    def test_14_public_verification_still_works(self):
        """Verify GET /api/verify/<marksheet_id> still functions accurately."""
        resp = self.client.get(f"/api/verify/{TEST_MARKSHEET_ID}")
        self.assertEqual(resp.status_code, 200)
        body = resp.get_json()
        self.assertTrue(body.get("verified"))
        self.assertEqual(body.get("status"), "VERIFIED")
        self.assertEqual(body.get("marksheet_id"), TEST_MARKSHEET_ID)

    # ========================================================
    # 15. PDF HASH VERIFICATION REGRESSION
    # ========================================================
    def test_15_pdf_hash_verification_still_works(self):
        """Verify that registered marksheet PDF hash matches on-disk SHA-256."""
        if not self.original_pdf_bytes:
            self.skipTest("Original test marksheet PDF not present")
        computed_hash = hashlib.sha256(self.original_pdf_bytes).hexdigest()
        self.assertEqual(computed_hash.lower(), EXPECTED_PDF_HASH.lower())

    # ========================================================
    # 16. UPLOAD CHECKER REGRESSION
    # ========================================================
    def test_16_upload_checker_still_works(self):
        """Verify that public marksheet upload checking works for valid PDF."""
        if not self.original_pdf_bytes:
            self.skipTest("Original test marksheet PDF not present")
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
        self.assertEqual(body.get("document_status"), "DOCUMENT_MATCH")

    # ========================================================
    # 17. NODE RECOVERY / SYNCHRONIZATION
    # ========================================================
    def test_17_node_recovery(self):
        """Simulate an out-of-sync node recovering via consensus."""
        primary = NodeBlockchain()
        self.assertTrue(len(primary.chain) >= 1)

        # Simulate lagging secondary node with only genesis block
        secondary = NodeBlockchain()
        secondary.chain = [primary.chain[0]]  # only genesis

        self.assertEqual(len(secondary.chain), 1)

        # Secondary adopts longest valid chain
        replaced = secondary.replace_chain(primary.chain)
        self.assertTrue(replaced)
        self.assertEqual(len(secondary.chain), len(primary.chain))
        self.assertEqual(secondary.chain[-1]["hash"], primary.chain[-1]["hash"])
        self.assertTrue(secondary.is_valid_chain(secondary.chain))

    # ========================================================
    # 18. PEER VALIDATION
    # ========================================================
    def test_18_peer_validation(self):
        """Verify that requests with invalid peer credentials are rejected (403)."""
        bad_headers = {"X-Node-Auth-Token": "unauthorized-token-xyz"}
        resp = self.node_client.post(
            "/receive-block",
            json={"block": {}},
            headers=bad_headers,
        )
        self.assertEqual(resp.status_code, 403)
        self.assertEqual(resp.get_json().get("error"), "INVALID_PEER_CREDENTIAL")

    # ========================================================
    # 19. CHAIN SYNCHRONIZATION
    # ========================================================
    def test_19_chain_synchronization(self):
        """Verify that replace_chain rejects shorter or tampered candidate chains."""
        nb = NodeBlockchain()
        current_chain = copy.deepcopy(nb.chain)

        # 1. Reject shorter chain
        shorter_chain = current_chain[:-1]
        self.assertFalse(nb.replace_chain(shorter_chain))

        # 2. Reject chain with tampered block
        if len(current_chain) > 2:
            tampered_candidate = copy.deepcopy(current_chain)
            # Add dummy block with wrong hash
            latest = tampered_candidate[-1]
            tampered_candidate.append({
                "index": latest["index"] + 1,
                "timestamp": time.time(),
                "data": [],
                "previous_hash": latest["hash"],
                "hash": "invalidhash123",
            })
            self.assertFalse(nb.replace_chain(tampered_candidate))

    # ========================================================
    # 20. TAMPER DETECTION (MULTI-VECTOR)
    # ========================================================
    def test_20_tamper_detection(self):
        """Verify detection across all primary attack surfaces."""
        # Vector 1: Tampered PDF payload -> 404 TAMPERED_OR_UNKNOWN
        if self.original_pdf_bytes:
            tampered_bytes = self.original_pdf_bytes + b"\n%injected_forgery%"
            resp = self.client.post(
                "/api/public/verify-upload",
                data={"file": (io.BytesIO(tampered_bytes), "tampered.pdf", "application/pdf")},
                content_type="multipart/form-data",
            )
            self.assertEqual(resp.status_code, 404)
            body = resp.get_json()
            self.assertFalse(body.get("verified"))
            self.assertEqual(body.get("status"), "TAMPERED_OR_UNKNOWN")
            self.assertEqual(body.get("document_status"), "DOCUMENT_MISMATCH")

        # Vector 2: Tampered transaction inside block -> is_valid_chain returns False
        nb = NodeBlockchain()
        tampered_chain = copy.deepcopy(nb.chain)
        if len(tampered_chain) > 2:
            # Modify data in block 1
            tampered_chain[1]["data"] = [{"tampered": True}]
            self.assertFalse(nb.is_valid_chain(tampered_chain))

        # Vector 3: Tampered block hash -> is_valid_chain returns False
        tampered_chain2 = copy.deepcopy(nb.chain)
        if len(tampered_chain2) > 1:
            tampered_chain2[1]["hash"] = "0" * 64
            self.assertFalse(nb.is_valid_chain(tampered_chain2))

        # Vector 4: Tampered previous_hash -> is_valid_chain returns False
        tampered_chain3 = copy.deepcopy(nb.chain)
        if len(tampered_chain3) > 1:
            tampered_chain3[1]["previous_hash"] = "f" * 64
            self.assertFalse(nb.is_valid_chain(tampered_chain3))

        # Vector 5: Tampered academic payload signature -> verify_academic_transaction returns False
        signed_tx = sign_academic_transaction(
            payload={"type": "ANSWER_SCRIPT_REGISTERED", "exam_id": "EX-1", "answer_script_id": "AS-T"},
            actor_id="UNIV-001",
            actor_role="UNIVERSITY",
        )
        signed_tx["exam_id"] = "EX-FORGED"
        is_valid, err = verify_academic_transaction(signed_tx)
        self.assertFalse(is_valid)

    # ========================================================
    # 21. SECURE DOCUMENT STORAGE ABSTRACTION
    # ========================================================
    def test_21_secure_document_storage_abstraction(self):
        """Verify document storage abstraction with path traversal protection."""
        test_filename = f"test_doc_{int(time.time())}.pdf"
        test_content = b"%PDF-1.4 test document content"

        # Save document
        path = document_storage.save_document(test_filename, test_content)
        self.assertTrue(document_storage.exists(test_filename))

        # Retrieve document
        retrieved = document_storage.get_document(test_filename)
        self.assertEqual(retrieved, test_content)

        # Path traversal rejection
        with self.assertRaises((ValueError, PermissionError)):
            document_storage.save_document("../../evil_file.pdf", b"evil")

        with self.assertRaises((ValueError, PermissionError)):
            document_storage.get_document("../../etc/passwd")

        # Delete document
        deleted = document_storage.delete_document(test_filename)
        self.assertTrue(deleted)
        self.assertFalse(document_storage.exists(test_filename))


if __name__ == "__main__":
    unittest.main()
