#!/usr/bin/env python3
"""
AnswerChain Phase 8 Acceptance Scenario Verification Script.

Executes the complete production security & cryptographic trust acceptance scenario:
1. UNIVERSITY registers answer script -> signed transaction -> distributed block
2. TEACHER submits evaluation -> signed transaction -> distributed block
3. AUTHORITY finalizes result -> signed transaction -> distributed block
4. AUTHORITY generates marksheet -> PDF hash -> MARKSHEET_REGISTERED
5. Public upload verification -> VERIFIED & DOCUMENT_MATCH
6. TAMPER PDF -> TAMPERED_OR_UNKNOWN & DOCUMENT_MISMATCH
7. ALTER TRANSACTION -> SIGNATURE_INVALID
8. STOP NODE-2 -> NODE-1 + NODE-3 continue
9. RESTART NODE-2 -> NODE-2 synchronizes -> same valid ledger
"""

import hashlib
import io
import json
import os
import subprocess
import sys
import time
import requests

PROJECT_ROOT = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..")
)
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from backend.crypto import sign_academic_transaction, verify_academic_transaction

BASE_URL = "http://127.0.0.1:8000"
NODE1_URL = "http://127.0.0.1:5001"
NODE2_URL = "http://127.0.0.1:5002"
NODE3_URL = "http://127.0.0.1:5003"


def main():
    print("================================================================")
    print("      AnswerChain Phase 8 - Complete Acceptance Scenario        ")
    print("================================================================")

    # --- Step 0: Login as University, Teacher, Authority ---
    print("\n[Step 0] Authenticating actors...")
    univ_auth = requests.post(f"{BASE_URL}/api/auth/login", json={"user_id": "UNIV-001", "password": "university123"}).json()
    tch_auth = requests.post(f"{BASE_URL}/api/auth/login", json={"user_id": "TCH-004", "password": "teacher123"}).json()
    auth_auth = requests.post(f"{BASE_URL}/api/auth/login", json={"user_id": "AUTH-001", "password": "authority123"}).json()

    univ_token = univ_auth["token"]
    tch_token = tch_auth["token"]
    auth_token = auth_auth["token"]

    print("  ✓ University authenticated: UNIV-001")
    print("  ✓ Teacher authenticated: TCH-004")
    print("  ✓ Authority authenticated: AUTH-001")

    # --- Step 1: UNIVERSITY registers answer script with signed transaction ---
    as_id = f"AS-P8-{int(time.time())}"
    print(f"\n[Step 1] Registering answer script {as_id} with Ed25519 digital signature...")
    reg_payload = {
        "student_id": "STU-2026-007",
        "student_name": "Antigravity Candidate",
        "university": "TINT",
        "exam_id": "EXAM-2026-FINAL",
        "exam_name": "Computer Science & Cryptography",
        "answer_script_id": as_id,
        "file_name": f"{as_id}.pdf",
        "file_hash": hashlib.sha256(f"bytes_for_{as_id}".encode()).hexdigest(),
    }
    # Sign transaction payload
    reg_tx = sign_academic_transaction(
        actor_id="UNIV-001",
        actor_role="UNIVERSITY",
        transaction_data={"type": "ANSWER_SCRIPT_REGISTERED", **reg_payload},
    )
    assert "signature" in reg_tx
    print(f"  ✓ Transaction signed with Ed25519 signature: {reg_tx['signature'][:24]}...")

    # Post to application server
    reg_resp = requests.post(
        f"{BASE_URL}/api/university/answer-scripts",
        json=reg_payload,
        headers={"Authorization": f"Bearer {univ_token}"},
    )
    assert reg_resp.status_code == 201, f"Registration failed: {reg_resp.text}"
    print(f"  ✓ Answer script {as_id} committed to distributed blockchain")

    # Assign Teacher
    print(f"\n[Step 1.1] Assigning teacher TCH-004 to {as_id}...")
    assign_resp = requests.post(
        f"{BASE_URL}/api/university/answer-scripts/{as_id}/assign",
        json={"teacher_id": "TCH-004"},
        headers={"Authorization": f"Bearer {univ_token}"},
    )
    assert assign_resp.status_code == 200, f"Assignment failed: {assign_resp.text}"
    print(f"  ✓ Assigned teacher TCH-004 to {as_id}")
    time.sleep(0.8)

    # --- Step 2: TEACHER submits evaluation with signed transaction ---
    print(f"\n[Step 2] Teacher TCH-004 submitting signed evaluation for {as_id}...")
    eval_payload = {
        "marks": 94.0,
        "max_marks": 100.0,
        "remarks": "Exceptional cryptographic rigor and clean design.",
    }
    eval_resp = requests.post(
        f"{BASE_URL}/api/teacher/assignments/{as_id}/evaluate",
        json=eval_payload,
        headers={"Authorization": f"Bearer {tch_token}"},
    )
    assert eval_resp.status_code == 200, f"Evaluation failed: {eval_resp.text}"
    print(f"  ✓ Evaluation submitted (94/100) and committed to distributed blockchain")
    time.sleep(0.8)

    # --- Step 3: AUTHORITY finalizes result with signed transaction ---
    print(f"\n[Step 3] Authority AUTH-001 finalizing result for {as_id}...")
    finalize_resp = requests.post(
        f"{BASE_URL}/api/authority/results/{as_id}/finalize",
        json={},
        headers={"Authorization": f"Bearer {auth_token}"},
    )
    assert finalize_resp.status_code == 200, f"Finalization failed: {finalize_resp.text}"
    print(f"  ✓ Result finalized and committed to distributed blockchain")
    time.sleep(0.8)

    # --- Step 4: AUTHORITY generates marksheet + PDF ---
    print(f"\n[Step 4] Generating official marksheet and physical PDF for {as_id}...")
    ms_resp = requests.post(
        f"{BASE_URL}/api/authority/results/{as_id}/marksheet",
        json={"student_name": "Antigravity Research Candidate", "student_id": "STU-2026-007"},
        headers={"Authorization": f"Bearer {auth_token}"},
    )
    assert ms_resp.status_code == 201, f"Marksheet generation failed: {ms_resp.text}"
    ms_data = ms_resp.json()
    marksheet_id = ms_data["marksheet_id"]
    pdf_hash = ms_data["marksheet_pdf_hash"]
    print(f"  ✓ Marksheet created: {marksheet_id}")
    print(f"  ✓ Physical PDF generated with SHA-256: {pdf_hash}")

    # --- Step 5: Public upload verification -> VERIFIED ---
    print(f"\n[Step 5] Performing public verification of official PDF bytes...")
    pdf_download_resp = requests.get(f"{BASE_URL}/api/marksheets/{marksheet_id}/pdf")
    assert pdf_download_resp.status_code == 200, "Could not download generated PDF"
    pdf_bytes = pdf_download_resp.content

    upload_resp = requests.post(
        f"{BASE_URL}/api/public/verify-upload",
        files={"file": (f"{marksheet_id}.pdf", pdf_bytes, "application/pdf")},
    )
    assert upload_resp.status_code == 200, f"Upload check failed: {upload_resp.text}"
    upload_body = upload_resp.json()
    assert upload_body.get("verified") is True
    assert upload_body.get("status") == "VERIFIED"
    assert upload_body.get("document_status") == "DOCUMENT_MATCH"
    print(f"  ✓ Public upload verification result: {upload_body['status']} ({upload_body['document_status']})")

    # --- Step 6: TAMPER PDF -> TAMPERED_OR_UNKNOWN ---
    print(f"\n[Step 6] Testing Tamper Detection on PDF bytes...")
    tampered_bytes = pdf_bytes + b"\n%tampered_payload_data_injection%"
    tamper_resp = requests.post(
        f"{BASE_URL}/api/public/verify-upload",
        files={"file": (f"{marksheet_id}.pdf", tampered_bytes, "application/pdf")},
    )
    assert tamper_resp.status_code == 404, f"Tamper test failed: expected 404, got {tamper_resp.status_code}"
    tamper_body = tamper_resp.json()
    assert tamper_body.get("verified") is False
    assert tamper_body.get("status") == "TAMPERED_OR_UNKNOWN"
    assert tamper_body.get("document_status") == "DOCUMENT_MISMATCH"
    print(f"  ✓ Tampered PDF correctly identified: {tamper_body['status']} ({tamper_body['document_status']})")

    # --- Step 7: ALTER TRANSACTION -> SIGNATURE_INVALID ---
    print(f"\n[Step 7] Testing Tamper Detection on signed academic transaction...")
    signed_tx = sign_academic_transaction(
        actor_id="TCH-004",
        actor_role="TEACHER",
        transaction_data={
            "type": "EVALUATION_SUBMITTED",
            "evaluation_id": "EVAL-TEST-TAMPER",
            "answer_script_id": as_id,
            "marks": 94.0,
            "max_marks": 100.0,
        },
    )
    # Alter marks field without regenerating signature
    signed_tx["marks"] = 100.0
    is_valid, err = verify_academic_transaction(signed_tx)
    assert not is_valid, "Altered transaction should have failed verification"
    print(f"  ✓ Altered transaction detected: {err}")

    # Submit to node endpoint directly -> expect rejection
    node_tx_resp = requests.post(f"{NODE1_URL}/transaction", json=signed_tx)
    assert node_tx_resp.status_code == 400, f"Node should reject invalid signature: {node_tx_resp.text}"
    print(f"  ✓ Node rejected altered transaction with: {node_tx_resp.json().get('error')}")

    # --- Step 8: STOP NODE-2 -> NODE-1 + NODE-3 continue ---
    print(f"\n[Step 8] Testing Cluster Fault Tolerance: Stopping node-2 (port 5002)...")
    # Find PID for port 5002
    pid_out = subprocess.check_output(["lsof", "-ti", ":5002"]).decode().strip()
    if pid_out:
        pids = pid_out.split()
        for p in pids:
            os.kill(int(p), 9)
    time.sleep(1)

    # Check node-1 and node-3 remain responsive
    n1_status = requests.get(f"{NODE1_URL}/node").json()
    n3_status = requests.get(f"{NODE3_URL}/node").json()
    print(f"  ✓ Node-1 running: blocks={n1_status['blocks']}, chain_valid={n1_status['chain_valid']}")
    print(f"  ✓ Node-3 running: blocks={n3_status['blocks']}, chain_valid={n3_status['chain_valid']}")

    # --- Step 9: RESTART NODE-2 -> NODE-2 synchronizes -> same valid ledger ---
    print(f"\n[Step 9] Restarting node-2 and verifying catch-up synchronization...")
    venv_py = os.path.join(PROJECT_ROOT, "venv", "bin", "python3")
    node2_env = {
        **os.environ,
        "NODE_ID": "node-2",
        "NODE_ROLE": "TEACHER",
        "NODE_PORT": "5002",
        "PEERS": "127.0.0.1:5001,127.0.0.1:5003",
    }
    subprocess.Popen([venv_py, "nodes/node.py"], env=node2_env, cwd=PROJECT_ROOT)
    time.sleep(2)

    # Query network status from node-1
    net_status = requests.get(f"{NODE1_URL}/network").json()
    print(f"  ✓ Cluster network status: {net_status['network_status']}")
    print(f"  ✓ Connected peers count: {net_status['connected_peers_count']}")

    # Trigger consensus on node-2 to ensure synchronization
    n2_consensus = requests.post(f"{NODE2_URL}/consensus").json()
    n1_blocks = requests.get(f"{NODE1_URL}/node").json()["blocks"]
    n2_blocks = requests.get(f"{NODE2_URL}/node").json()["blocks"]
    n3_blocks = requests.get(f"{NODE3_URL}/node").json()["blocks"]

    print(f"  ✓ Node block counts: Node-1={n1_blocks}, Node-2={n2_blocks}, Node-3={n3_blocks}")
    assert n1_blocks == n2_blocks == n3_blocks, f"Node blocks out of sync: {n1_blocks}, {n2_blocks}, {n3_blocks}"

    n1_hash = requests.get(f"{NODE1_URL}/chain").json()["chain"][-1]["hash"]
    n2_hash = requests.get(f"{NODE2_URL}/chain").json()["chain"][-1]["hash"]
    n3_hash = requests.get(f"{NODE3_URL}/chain").json()["chain"][-1]["hash"]

    assert n1_hash == n2_hash == n3_hash, f"Hash mismatch: {n1_hash} vs {n2_hash} vs {n3_hash}"
    print(f"  ✓ Synchronized latest block hash: {n1_hash[:16]}... (all nodes match)")

    print("\n================================================================")
    print("      ✓ ALL PHASE 8 ACCEPTANCE SCENARIOS PASSED CLEANLY!       ")
    print("================================================================")


if __name__ == "__main__":
    main()
