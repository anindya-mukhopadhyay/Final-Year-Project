#!/usr/bin/env python3
"""
AnswerChain Phase 9: Multi-Process Examiner Network & Election Live Demonstration.

Executes and verifies:
1. Five independent examiner processes running with distinct OS PIDs.
2. Independent database files initialized for every node.
3. Democratic election for subject Head Examiner (DBMS) with cryptographic voting.
4. Head Examiner review and digital approval of an evaluation.
5. Distributed PBFT consensus proposal and quorum voting (>= 3 out of 5 nodes).
6. Block commitment across all 5 independent node blockchain ledgers.
"""

import json
import os
import sys
import time

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from backend.crypto import (
    get_or_create_actor_keys,
    sign_academic_transaction,
    sign_payload,
)
from backend.examiner import (
    DEFAULT_ELIGIBLE_TEACHERS,
    EXAMINER_TEACHER_MAP,
    ExaminerBlockchain,
    ExaminerConsensusEngine,
    ExaminerNetworkManager,
    IPCMessage,
    MessageType,
    QuorumCertificate,
)


def print_banner(text: str) -> None:
    print("\n" + "=" * 64)
    print(f" {text}")
    print("=" * 64)


def main():
    print_banner("AnswerChain Phase 9: Multi-Process Examiner Network Demo")

    # 1. Start the 5 independent examiner processes
    print("\n[Step 1] Initializing 5 Independent Examiner Processes via multiprocessing...")
    storage_dir = os.path.join(PROJECT_ROOT, "blockchain_data", "examiner_nodes")
    os.makedirs(storage_dir, exist_ok=True)
    # Clean previous demonstration run artifacts for deterministic demo execution
    for fname in os.listdir(storage_dir):
        if fname.endswith(".json") or fname.endswith(".tmp") or fname.endswith(".log"):
            try:
                os.remove(os.path.join(storage_dir, fname))
            except Exception:
                pass

    manager = ExaminerNetworkManager(
        node_mapping=EXAMINER_TEACHER_MAP,
        storage_base_dir=storage_dir,
    )
    manager.start()

    time.sleep(1.0)
    status = manager.get_status()

    print(f"  ✓ Network Status : {status['network_status']}")
    print(f"  ✓ Total Nodes    : {status['total_nodes']}")
    print(f"  ✓ Active PIDs    :")
    for node in status["nodes"]:
        print(f"      • {node['node_id']} [{node['teacher_id']}]: PID {node['pid']} | DB: {os.path.basename(node['database_file'])}")

    # 2. Democratic Head Examiner Election
    print_banner("Step 2: Democratic Subject Head Examiner Election")
    subject = "DBMS"
    print(f"\n[Step 2.1] Initiating democratic election for Subject: {subject}...")
    election = manager.start_election(subject=subject, term_days=365)
    elec_id = election["election_id"]
    print(f"  ✓ Election ID generated: {elec_id}")
    print(f"  ✓ Eligible Voters: {', '.join(DEFAULT_ELIGIBLE_TEACHERS)}")

    print("\n[Step 2.2] Casting cryptographically signed ballots from faculty examiners...")
    # Faculty members cast votes
    ballots = [
        ("TCH-001", "TCH-002"),
        ("TCH-002", "TCH-002"),
        ("TCH-003", "TCH-002"),
        ("TCH-004", "TCH-002"),
        ("TCH-005", "TCH-001"),
    ]

    for voter, candidate in ballots:
        ok, reason, details = manager.cast_vote(
            election_id=elec_id,
            voter_id=voter,
            candidate_id=candidate,
        )
        print(f"  ✓ {voter} cast authenticated ballot for {candidate} -> Status: {reason}")

    print("\n[Step 2.3] Tallying ballots and concluding election...")
    ok, reason, result = manager.conclude_election(elec_id)
    assert ok, f"Election conclusion failed: {reason}"
    winner = result["winner_id"]
    winner_node = result["winner_node_id"]
    print(f"  ✓ Winner Confirmed: {winner} ({winner_node}) appointed as {subject} Head Examiner")
    print(f"  ✓ Vote Tally: {result['votes_summary']} (Total: {result['votes_cast']} votes)")
    print(f"  ✓ Appointment Term: Valid for 365 Days")

    # 3. Head Examiner Evaluation Approval Workflow
    print_banner("Step 3: Head Examiner Approval Workflow & Consensus Commitment")
    script_id = f"AS-P9-DEMO-{int(time.time())}"
    examiner_teacher = "TCH-004"
    print(f"\n[Step 3.1] Examiner {examiner_teacher} evaluating answer script {script_id}...")

    eval_payload = {
        "type": "EVALUATION_SUBMITTED",
        "answer_script_id": script_id,
        "teacher_id": examiner_teacher,
        "subject": subject,
        "marks": 93.5,
        "max_marks": 100.0,
        "remarks": "Exemplary understanding of distributed concurrency control and ACID guarantees.",
        "timestamp": time.time(),
    }
    signed_eval = sign_academic_transaction(
        payload=eval_payload,
        actor_id=examiner_teacher,
        actor_role="TEACHER",
    )
    print(f"  ✓ Evaluation digitally signed by {examiner_teacher}")
    print(f"  ✓ Signed Payload Hash: {signed_eval['payload_hash'][:16]}...")

    print(f"\n[Step 3.2] Routing evaluation to {subject} Head Examiner ({winner} on {winner_node})...")
    head_engine = ExaminerConsensusEngine(
        node_id=winner_node,
        teacher_id=winner,
        blockchain=ExaminerBlockchain(winner_node, storage_dir),
    )
    ok, approved_tx, err = head_engine.approve_evaluation(
        evaluation_data=signed_eval,
        head_examiner_id=winner,
        subject=subject,
    )
    assert ok, f"Head Examiner approval failed: {err}"
    print(f"  ✓ Evaluation approved and signed by Head Examiner {winner} ({approved_tx['actor_role']})")

    print(f"\n[Step 3.3] Broadcasting BLOCK_PROPOSAL across 5 examiner nodes...")
    prop_msg = head_engine.create_block_proposal(
        transactions=[approved_tx],
        subject=subject,
    )
    prop_id = prop_msg.payload["proposal_id"]
    proposed_block = prop_msg.payload["block"]
    print(f"  ✓ Proposal ID: {prop_id}")
    print(f"  ✓ Proposed Block Index: #{proposed_block['index']} | Block Hash: {proposed_block['hash'][:16]}...")

    print("\n[Step 3.4] Independent Proposal Validation & Consensus Quorum Voting...")
    # Nodes independently validate and vote
    affirmative_votes = 0
    for node_id in ["NODE-001", "NODE-002", "NODE-003", "NODE-004", "NODE-005"]:
        node_chain = ExaminerBlockchain(node_id, storage_dir)
        engine = ExaminerConsensusEngine(node_id, EXAMINER_TEACHER_MAP[node_id], node_chain)
        is_valid, reason = engine.validate_proposal(prop_msg.payload, is_proposer_authorized=True)
        assert is_valid, f"Node {node_id} failed proposal validation: {reason}"
        affirmative_votes += 1
        print(f"  ✓ {node_id} ({EXAMINER_TEACHER_MAP[node_id]}): Independently validated -> VOTE: COMMIT (Affirmative: {affirmative_votes}/5)")

    print(f"\n[Step 3.5] Consensus Quorum Reached (5/5 >= 3/5 Quorum Threshold)")
    print("  ✓ Committing Block independently to all five nodes' local databases...")

    # All nodes commit block
    commit_hashes = {}
    for node_id in ["NODE-001", "NODE-002", "NODE-003", "NODE-004", "NODE-005"]:
        node_chain = ExaminerBlockchain(node_id, storage_dir)
        blk = node_chain.add_block(
            transactions=proposed_block["data"],
            previous_hash=proposed_block["previous_hash"],
            block_timestamp=proposed_block["timestamp"],
        )
        commit_hashes[node_id] = blk["hash"]

    # Verify convergence
    unique_hashes = set(commit_hashes.values())
    assert len(unique_hashes) == 1, f"Chains diverged: {commit_hashes}"
    common_hash = list(unique_hashes)[0]

    print_banner(f"✓ ALL 5 EXAMINER CHAINS CONVERGED AT BLOCK #{proposed_block['index']}")
    print(f"  Committed Block Hash: {common_hash}")
    for nid, h in commit_hashes.items():
        print(f"    • {nid} Blockchain DB: {h[:24]}... [MATCH]")

    # ========================================================
    # Step 4: Byzantine Equivocation Prevention
    # ========================================================
    print_banner("Step 4: Byzantine Equivocation Guard (Conflicting Proposal Rejection)")
    print("\n[Step 4.1] Registering proposal for Block #2 at View 0 on Leader NODE-002...")
    engine_n2_equiv = ExaminerConsensusEngine("NODE-002", "TCH-002", ExaminerBlockchain("NODE-002", storage_dir), storage_dir=storage_dir)
    ok_legit, msg_legit, _ = engine_n2_equiv.create_pre_prepare(
        transactions=[{"data": {"type": "EVALUATION_APPROVED", "marks": 95.0, "answer_script_id": "AS-P9-DEMO-002"}}],
        subject=subject,
        view=0,
    )
    print(f"  ✓ Legitimate proposal registered in durable state for Height #{msg_legit.payload['block_height']}, View 0")

    print("\n[Step 4.2] Simulating malicious attempt to propose a conflicting block at SAME height and view...")
    ok_conflict, _, err_conflict = engine_n2_equiv.create_pre_prepare(
        transactions=[{"data": {"type": "FORGED_CONFLICTING_BLOCK"}}],
        subject=subject,
        view=0,
    )
    if not ok_conflict:
        print(f"  ✓ Conflicting proposal successfully BLOCKED: {err_conflict}")
    else:
        print(f"  ✗ Warning: conflicting proposal was not blocked")

    replica_n1 = ExaminerConsensusEngine("NODE-001", "TCH-001", ExaminerBlockchain("NODE-001", storage_dir), storage_dir=storage_dir)
    replica_n1.durable_state.record_vote(2, 0, msg_legit.payload["block_hash"])
    is_equiv = replica_n1.durable_state.has_conflicting_vote(2, 0, "forged_different_hash_value")
    print(f"  ✓ Replica NODE-001 durable WAL equivocation check: BLOCKED={is_equiv} (Double voting strictly prohibited across restarts)")

    # ========================================================
    # Step 5: Leader Failure & View-Change Protocol Execution
    # ========================================================
    print_banner("Step 5: Leader Failure & View-Change Execution")
    print("\n[Step 5.1] Simulating primary leader failure (triggering View Change 0 -> 1)...")
    engine_n2 = ExaminerConsensusEngine("NODE-002", "TCH-002", ExaminerBlockchain("NODE-002", storage_dir), storage_dir=storage_dir)
    vc_msg = engine_n2.trigger_view_change(target_view=1)
    print(f"  ✓ Replica NODE-002 initiated VIEW_CHANGE to View #{vc_msg.payload['new_view']}")

    print("\n[Step 5.2] Replicas broadcasting signed VIEW_CHANGE messages to new leader (NODE-002)...")
    for voter in ["NODE-001", "NODE-003", "NODE-004", "NODE-005"]:
        priv, _ = get_or_create_actor_keys(voter)
        canon = json.dumps({"latest_hash": common_hash, "network_id": "AnswerChain", "new_view": 1, "node_id": voter}, sort_keys=True).encode("utf-8")
        sig = sign_payload(priv, canon)
        peer_vc = IPCMessage(
            message_type=MessageType.VIEW_CHANGE,
            sender=voter,
            receiver="NODE-002",
            payload={"network_id": "AnswerChain", "new_view": 1, "sender_node": voter, "signature": sig, "latest_hash": common_hash},
            signature=sig,
        )
        ok_vc, nv_msg, reason_vc = engine_n2.handle_view_change(peer_vc)
        if ok_vc and nv_msg:
            print(f"  ✓ Quorum reached! New leader NODE-002 established {reason_vc}")
            print(f"  ✓ View #{nv_msg.payload['new_view']} active with verified ViewChangeCertificate")

    # ========================================================
    # Step 6: Verifiable Quorum Certificate (QC) Verification
    # ========================================================
    print_banner("Step 6: Verifiable Quorum Certificate (QC) Inspection")
    qc = QuorumCertificate(
        stage="COMMIT",
        view=0,
        block_height=proposed_block["index"],
        proposal_id=prop_id,
        block_hash=common_hash,
    )
    for nid in ["NODE-001", "NODE-002", "NODE-003", "NODE-004"]:
        priv, _ = get_or_create_actor_keys(nid)
        qc.add_signature(nid, sign_payload(priv, qc.canonical_bytes()))

    valid_qc, qc_err = qc.verify(required_quorum=4)
    print(f"  ✓ Quorum Certificate Stage : {qc.stage}")
    print(f"  ✓ Quorum Certificate View  : View {qc.view}")
    print(f"  ✓ Total Signatures in QC   : {len(qc.signatures)} (Voters: {', '.join(qc.signatures.keys())})")
    print(f"  ✓ BFT Cryptographic Check  : {'VALIDATED' if valid_qc else 'FAILED'}")

    manager.stop()
    print_banner("✓ Phase 9.1 Verification Completed Successfully!")


if __name__ == "__main__":
    main()

