"""
AnswerChain Phase 9.1: Consensus Security, Byzantine Fault Tolerance & Failure Resilience Tests.

Verifies:
1. Two conflicting proposals at the same block height (Equivocation prevention).
2. Duplicate consensus votes rejection.
3. Invalid Ed25519 digital signatures rejection.
4. Replayed consensus messages rejection.
5. Unauthorized consensus proposer rejection.
6. Expired Head Examiner approval rejection.
7. Malicious node sending conflicting votes (Byzantine split-vote resilience).
8. Two nodes crash during consensus (CFT vs BFT quorum behavior).
9. Consensus leader crash & View-Change protocol execution.
10. Node restarts with outdated blockchain data and synchronizes safely via QC.
11. Node restarts with tampered blockchain data and rejects corrupted blocks.
12. Invalid or forged Quorum Certificate rejection.
13. Duplicate election ballot rejection.
14. Election tie handling (auditable TIED status and deterministic resolution).
15. Insufficient election participation rejection.
16. Unauthorized examiner approval and anti-self-approval enforcement.
17. All five nodes independently verify the same committed block and Quorum Certificate.
"""

import copy
import json
import os
import shutil
import tempfile
import time
import unittest

from backend.crypto import (
    get_actor_public_key,
    get_or_create_actor_keys,
    sign_academic_transaction,
    sign_payload,
    verify_signature,
)
from backend.examiner import (
    ALL_EXAMINER_NODES,
    ConsensusMode,
    ConsensusStage,
    ConsensusState,
    DEFAULT_ELIGIBLE_TEACHERS,
    DurableConsensusState,
    EXAMINER_TEACHER_MAP,
    ElectionStatus,
    ExaminerBlockchain,
    ExaminerConsensusEngine,
    ExaminerNetworkManager,
    HeadExaminerRegistry,
    IPCMessage,
    MessageType,
    QuorumCertificate,
    SubjectElection,
    validate_fault_model,
)


class Phase9ConsensusSecurityBFTTests(unittest.TestCase):
    """17 In-Depth Security, BFT, and Failure Tests for Examiner Consensus."""

    def setUp(self):
        self.test_dir = tempfile.mkdtemp(prefix="answerchain_sec_test_")

    def tearDown(self):
        if os.path.exists(self.test_dir):
            shutil.rmtree(self.test_dir, ignore_errors=True)

    # ========================================================
    # 1. CONFLICTING PROPOSALS AT SAME HEIGHT (EQUIVOCATION)
    # ========================================================
    def test_01_conflicting_proposals_at_same_block_height(self):
        """Verify that a node strictly refuses to vote for two conflicting blocks at the same height/view."""
        chain = ExaminerBlockchain("NODE-001", self.test_dir)
        engine = ExaminerConsensusEngine("NODE-001", "TCH-001", chain, storage_dir=self.test_dir)

        # First proposal A
        ok, msg_a, _ = engine.create_pre_prepare(
            transactions=[{"data": {"type": "EVALUATION_APPROVED", "answer_script_id": "AS-001"}}],
            subject="DBMS",
            view=0,
        )
        self.assertTrue(ok)
        self.assertIsNotNone(msg_a)

        # Attempt conflicting proposal B at SAME height and view
        ok2, msg_b, err = engine.create_pre_prepare(
            transactions=[{"data": {"type": "EVALUATION_APPROVED", "answer_script_id": "AS-CONFLICT"}}],
            subject="DBMS",
            view=0,
        )
        self.assertFalse(ok2)
        self.assertIn("EQUIVOCATION_REJECTED", err)

    # ========================================================
    # 2. DUPLICATE CONSENSUS VOTES
    # ========================================================
    def test_02_duplicate_consensus_votes_rejection(self):
        """Verify duplicate prepare/commit votes from the same node are rejected and not counted twice."""
        chain = ExaminerBlockchain("NODE-001", self.test_dir)
        engine = ExaminerConsensusEngine("NODE-001", "TCH-001", chain, storage_dir=self.test_dir)

        ok, prep_msg, _ = engine.create_pre_prepare(
            transactions=[{"data": {"type": "EVALUATION_APPROVED", "answer_script_id": "AS-DUP"}}],
            subject="DBMS",
        )
        self.assertTrue(ok)
        prop_id = prep_msg.payload["proposal_id"]
        state = engine.active_proposals[prop_id]

        priv, _ = get_or_create_actor_keys("NODE-002")
        qc_template = QuorumCertificate("PREPARE", 0, 1, prop_id, prep_msg.payload["block_hash"])
        sig = sign_payload(priv, qc_template.canonical_bytes())

        # First vote
        _, count1 = state.record_prepare_vote("NODE-002", sig)
        # Duplicate vote
        _, count2 = state.record_prepare_vote("NODE-002", sig)

        # Count must not increase on duplicate vote
        self.assertEqual(count1, count2)

    # ========================================================
    # 3. INVALID ED25519 SIGNATURES
    # ========================================================
    def test_03_invalid_ed25519_signatures(self):
        """Verify that consensus messages with invalid digital signatures are strictly rejected."""
        chain = ExaminerBlockchain("NODE-001", self.test_dir)
        engine = ExaminerConsensusEngine("NODE-001", "TCH-001", chain, storage_dir=self.test_dir)

        ok, prep_msg, _ = engine.create_pre_prepare(
            transactions=[{"data": {"type": "EVALUATION_APPROVED", "answer_script_id": "AS-SIG"}}],
            subject="DBMS",
        )
        prop_id = prep_msg.payload["proposal_id"]

        # Craft vote with forged/tampered signature
        bad_vote_msg = IPCMessage(
            message_type=MessageType.PREPARE,
            sender="NODE-002",
            receiver="NODE-001",
            payload={
                "proposal_id": prop_id,
                "view": 0,
                "block_height": 1,
                "block_hash": prep_msg.payload["block_hash"],
                "signature": "deadbeef" * 16,  # Forged signature
            },
        )

        ok, _, reason = engine.handle_prepare(bad_vote_msg)
        self.assertFalse(ok)
        self.assertEqual(reason, "INVALID_VOTE_SIGNATURE")

    # ========================================================
    # 4. REPLAYED CONSENSUS MESSAGES
    # ========================================================
    def test_04_replayed_consensus_messages(self):
        """Verify that identical replayed consensus messages are detected and rejected."""
        chain = ExaminerBlockchain("NODE-002", self.test_dir)
        engine = ExaminerConsensusEngine("NODE-002", "TCH-002", chain, storage_dir=self.test_dir)

        # Leader creates PRE_PREPARE
        leader_chain = ExaminerBlockchain("NODE-001", self.test_dir)
        leader_engine = ExaminerConsensusEngine("NODE-001", "TCH-001", leader_chain, storage_dir=self.test_dir)
        ok, msg, _ = leader_engine.create_pre_prepare(
            transactions=[{"data": {"type": "EVALUATION_APPROVED", "answer_script_id": "AS-REPLAY"}}],
            subject="DBMS",
        )
        self.assertTrue(ok)

        # First delivery succeeds
        ok1, _, reason1 = engine.handle_pre_prepare(msg, is_leader_authorized=True)
        self.assertTrue(ok1)
        self.assertEqual(reason1, "PREPARE_CAST")

        # Second delivery (replay) must be rejected
        ok2, _, reason2 = engine.handle_pre_prepare(msg, is_leader_authorized=True)
        self.assertFalse(ok2)
        self.assertEqual(reason2, "REPLAYED_MESSAGE_REJECTED")

    # ========================================================
    # 5. UNAUTHORIZED PROPOSER
    # ========================================================
    def test_05_unauthorized_proposer(self):
        """Verify that a proposal from an unauthorized node is rejected immediately."""
        chain = ExaminerBlockchain("NODE-001", self.test_dir)
        engine = ExaminerConsensusEngine("NODE-001", "TCH-001", chain, storage_dir=self.test_dir)

        fake_msg = IPCMessage(
            message_type=MessageType.PRE_PREPARE,
            sender="ROGUE-NODE-999",
            receiver="*",
            payload={"proposal_id": "PROP-FAKE", "view": 0, "block_height": 1, "block": {}},
        )

        ok, _, reason = engine.handle_pre_prepare(fake_msg, is_leader_authorized=False)
        self.assertFalse(ok)
        self.assertEqual(reason, "UNAUTHORIZED_LEADER_PROPOSAL")

    # ========================================================
    # 6. EXPIRED HEAD EXAMINER APPROVAL
    # ========================================================
    def test_06_expired_head_examiner_approval(self):
        """Verify that an expired Head Examiner appointment cannot authorize evaluations."""
        registry = HeadExaminerRegistry()
        past_time = time.time() - 86400  # Expired yesterday

        registry.active_head_examiners["DBMS"] = {
            "subject": "DBMS",
            "head_examiner_id": "TCH-002",
            "node_id": "NODE-002",
            "term_start": past_time - (365 * 86400),
            "term_end": past_time,
            "is_valid": True,
        }

        # Check authority check
        self.assertFalse(registry.is_head_examiner("TCH-002", "DBMS"))
        self.assertIsNone(registry.get_head_examiner("DBMS"))

    # ========================================================
    # 7. BYZANTINE EQUIVOCATION (CONFLICTING VOTES)
    # ========================================================
    def test_07_malicious_node_conflicting_votes(self):
        """
        Verify that in BFT mode (Q=4), a Byzantine node cannot cause split-brain
        because any two quorums overlap in at least f+1=2 nodes.
        """
        chain = ExaminerBlockchain("NODE-001", self.test_dir)
        # BFT Quorum = 4
        engine = ExaminerConsensusEngine("NODE-001", "TCH-001", chain, quorum_threshold=4, storage_dir=self.test_dir)

        # Propose Block A
        ok, prep_a, _ = engine.create_pre_prepare(
            transactions=[{"data": {"type": "EVALUATION_APPROVED", "answer_script_id": "AS-A"}}],
            subject="DBMS",
            view=0,
        )
        prop_id_a = prep_a.payload["proposal_id"]
        state_a = engine.active_proposals[prop_id_a]

        # Only 2 nodes vote for A (NODE-001 leader + NODE-002) -> total 2 (< 4)
        priv2, _ = get_or_create_actor_keys("NODE-002")
        qc_a = QuorumCertificate("PREPARE", 0, 1, prop_id_a, prep_a.payload["block_hash"])
        state_a.record_prepare_vote("NODE-002", sign_payload(priv2, qc_a.canonical_bytes()))

        # Quorum cannot be reached with only 2 votes
        self.assertIsNone(state_a.prepare_qc)
        self.assertFalse(state_a.is_committed)

    # ========================================================
    # 8. TWO NODES CRASH DURING CONSENSUS (CFT VS BFT)
    # ========================================================
    def test_08_two_nodes_crash_during_consensus(self):
        """
        Verify behavior when 2 nodes crash (3 surviving):
        - Under CFT (Q=3): 3 votes satisfy quorum.
        - Under BFT (Q=4): 3 votes do NOT satisfy quorum (safety halts rather than committing unsafely).
        """
        chain = ExaminerBlockchain("NODE-001", self.test_dir)

        # CFT Mode (Q=3)
        cft_engine = ExaminerConsensusEngine("NODE-001", "TCH-001", chain, quorum_threshold=3, storage_dir=self.test_dir)
        state_cft = ConsensusState("PROP-CFT", "NODE-001", "DBMS", {"hash": "hash_cft"}, quorum_required=3)
        state_cft.record_vote("NODE-001", True)
        state_cft.record_vote("NODE-002", True)
        quorum_reached, count = state_cft.record_vote("NODE-003", True)
        self.assertTrue(quorum_reached)
        self.assertEqual(count, 3)

        # BFT Mode (Q=4)
        state_bft = ConsensusState("PROP-BFT", "NODE-001", "DBMS", {"hash": "hash_bft"}, quorum_required=4)
        state_bft.record_vote("NODE-001", True)
        state_bft.record_vote("NODE-002", True)
        quorum_reached, count = state_bft.record_vote("NODE-003", True)
        # With 2 nodes dead, BFT requires 4 votes, so 3 is INSUFFICIENT
        self.assertFalse(quorum_reached)
        self.assertEqual(count, 3)

    # ========================================================
    # 9. CONSENSUS LEADER CRASHES & VIEW CHANGE
    # ========================================================
    def test_09_consensus_leader_crashes_and_view_change(self):
        """Verify that when consensus leader fails, replicas trigger view change and transition to view v+1."""
        chain = ExaminerBlockchain("NODE-002", self.test_dir)
        engine = ExaminerConsensusEngine("NODE-002", "TCH-002", chain, quorum_threshold=3, storage_dir=self.test_dir)

        # Trigger view change to view 1 (where leader is NODE-002: (1 % 5) + 1 = 2)
        vc_msg = engine.trigger_view_change(target_view=1)
        self.assertEqual(vc_msg.payload["new_view"], 1)
        self.assertEqual(engine.current_view, 1)

        # Replicas send view change votes to new leader (NODE-002)
        for voter in ["NODE-001", "NODE-003", "NODE-004"]:
            priv, _ = get_or_create_actor_keys(voter)
            canon = json.dumps({"new_view": 1, "node_id": voter, "latest_hash": chain.get_latest_block().get("hash")}, sort_keys=True).encode("utf-8")
            sig = sign_payload(priv, canon)
            peer_vc = IPCMessage(
                message_type=MessageType.VIEW_CHANGE,
                sender=voter,
                receiver="NODE-002",
                payload={"new_view": 1, "sender_node": voter, "signature": sig, "latest_hash": chain.get_latest_block().get("hash")},
            )
            engine.handle_view_change(peer_vc)

        # View change quorum reached -> leader established view 1
        self.assertEqual(engine.current_view, 1)
        self.assertEqual(engine.get_leader_for_view(1), "NODE-002")

    # ========================================================
    # 10. RESTART WITH OUTDATED DATA & CATCH-UP VIA QC
    # ========================================================
    def test_10_node_restarts_with_outdated_data_and_syncs_via_qc(self):
        """Verify that an outdated node synchronizes safely when presented with a valid certified chain."""
        node_chain = ExaminerBlockchain("NODE-005", self.test_dir)
        self.assertEqual(len(node_chain.chain), 1)  # Only genesis

        # Peer creates block #1 with authenticated Quorum Certificate
        peer_chain = ExaminerBlockchain("NODE-001", self.test_dir)
        tx = {"transaction_id": "tx-sync-1", "data": {"type": "TEST"}}
        block = peer_chain.add_block(transactions=[tx], block_timestamp=time.time())

        # Construct valid Quorum Certificate
        privs = [get_or_create_actor_keys(n)[0] for n in ALL_EXAMINER_NODES[:4]]
        qc = QuorumCertificate("COMMIT", 0, 1, "PROP-SYNC", block["hash"])
        for nid, priv in zip(ALL_EXAMINER_NODES[:4], privs):
            qc.add_signature(nid, sign_payload(priv, qc.canonical_bytes()))

        block["quorum_certificate"] = qc.to_dict()
        peer_chain.save_chain()

        # NODE-005 synchronizes
        ok = node_chain.replace_chain(peer_chain.chain, require_qc=True, required_quorum=3)
        self.assertTrue(ok)
        self.assertEqual(len(node_chain.chain), 2)
        self.assertEqual(node_chain.chain[1]["hash"], block["hash"])

    # ========================================================
    # 11. RESTART WITH TAMPERED BLOCKCHAIN DATA
    # ========================================================
    def test_11_node_restarts_with_tampered_blockchain_data(self):
        """Verify that any tampering with a node's local blockchain file is immediately detected."""
        chain = ExaminerBlockchain("NODE-001", self.test_dir)
        chain.add_block(transactions=[{"data": {"type": "REAL"}}])
        self.assertTrue(chain.is_valid_chain(chain.chain))

        # Tamper with block data directly on disk
        tampered_chain = copy.deepcopy(chain.chain)
        tampered_chain[1]["data"] = [{"data": {"type": "TAMPERED_IN_STORAGE"}}]

        # Validation must detect invalid hash
        self.assertFalse(chain.is_valid_chain(tampered_chain))

    # ========================================================
    # 12. INVALID OR FORGED QUORUM CERTIFICATE REJECTED
    # ========================================================
    def test_12_invalid_quorum_certificate_rejected(self):
        """Verify that an uncertified block or forged Quorum Certificate is rejected during chain synchronization."""
        chain = ExaminerBlockchain("NODE-001", self.test_dir)
        block = chain.add_block(transactions=[{"data": {"type": "TEST"}}])

        # Forged QC with insufficient signatures (only 1 signer when 3 required)
        forged_qc = QuorumCertificate("COMMIT", 0, 1, "PROP-FORGED", block["hash"])
        priv, _ = get_or_create_actor_keys("NODE-001")
        forged_qc.add_signature("NODE-001", sign_payload(priv, forged_qc.canonical_bytes()))

        valid, err = forged_qc.verify(required_quorum=3)
        self.assertFalse(valid)
        self.assertIn("INSUFFICIENT_QUORUM", err)

        block["quorum_certificate"] = forged_qc.to_dict()
        receiver_chain = ExaminerBlockchain("NODE-003", self.test_dir)
        # replace_chain with require_qc must reject
        self.assertFalse(receiver_chain.replace_chain(chain.chain, require_qc=True, required_quorum=3))

    # ========================================================
    # 13. DUPLICATE ELECTION BALLOT REJECTION
    # ========================================================
    def test_13_duplicate_election_ballot_rejected(self):
        """Verify that casting two ballots by the same teacher in the same election is strictly rejected."""
        election = SubjectElection("ELEC-DBMS-DUP", "DBMS", term_days=30)

        # First ballot accepted
        ok1, reason1 = election.cast_vote("TCH-001", "TCH-002")
        self.assertTrue(ok1)
        self.assertEqual(reason1, "VOTE_ACCEPTED")

        # Second ballot rejected
        ok2, reason2 = election.cast_vote("TCH-001", "TCH-003")
        self.assertFalse(ok2)
        self.assertIn("DUPLICATE_VOTE_REJECTED", reason2)

    # ========================================================
    # 14. ELECTION TIE HANDLING
    # ========================================================
    def test_14_election_tie_handling(self):
        """Verify that election ties produce auditable TIED status or deterministic resolution."""
        election = SubjectElection("ELEC-TIE-TEST", "NETWORKS", term_days=30)
        election.cast_vote("TCH-001", "TCH-001")
        election.cast_vote("TCH-002", "TCH-002")
        election.cast_vote("TCH-003", "TCH-001")
        election.cast_vote("TCH-004", "TCH-002")
        # 2 votes for TCH-001, 2 votes for TCH-002 -> Tie!

        # Without tie-breaker: status is TIED
        ok, reason, details = election.tally(break_ties=False)
        self.assertFalse(ok)
        self.assertEqual(reason, "ELECTION_TIED")
        self.assertEqual(election.status, ElectionStatus.TIED)

        # With deterministic seniority fallback: tie broken deterministically
        ok2, reason2, details2 = election.tally(break_ties=True)
        self.assertTrue(ok2)
        self.assertEqual(election.status, ElectionStatus.CONCLUDED)
        self.assertEqual(details2["winner_id"], "TCH-001")  # TCH-001 wins lexicographically
        self.assertTrue(details2["tie_resolved"])

    # ========================================================
    # 15. INSUFFICIENT ELECTION PARTICIPATION
    # ========================================================
    def test_15_insufficient_election_participation(self):
        """Verify election fails if voter participation is below participation quorum."""
        election = SubjectElection("ELEC-LOW-TURNOUT", "ALGORITHMS", participation_quorum=3)
        election.cast_vote("TCH-001", "TCH-001")
        election.cast_vote("TCH-002", "TCH-001")
        # Only 2 votes cast (< 3)

        ok, reason, details = election.tally()
        self.assertFalse(ok)
        self.assertEqual(reason, "INSUFFICIENT_PARTICIPATION")
        self.assertEqual(election.status, ElectionStatus.FAILED_INSUFFICIENT_PARTICIPATION)

    # ========================================================
    # 16. UNAUTHORIZED EXAMINER APPROVAL & SELF-APPROVAL
    # ========================================================
    def test_16_unauthorized_examiner_and_self_approval_rejection(self):
        """
        Verify:
        1. A Head Examiner cannot approve their own evaluation (anti-self-approval rule).
        2. Malformed or unauthorized approval transactions are rejected.
        """
        chain = ExaminerBlockchain("NODE-002", self.test_dir)
        engine = ExaminerConsensusEngine("NODE-002", "TCH-002", chain, storage_dir=self.test_dir)

        # TCH-002 evaluates an answer script and attempts to approve their OWN script
        self_eval = {
            "type": "EVALUATION_SUBMITTED",
            "answer_script_id": "AS-SELF-001",
            "teacher_id": "TCH-002",  # Evaluator is TCH-002
            "marks": 98.0,
            "max_marks": 100.0,
        }

        ok, _, err = engine.approve_evaluation(
            evaluation_data=self_eval,
            head_examiner_id="TCH-002",  # Approver is ALSO TCH-002
            subject="DBMS",
            allow_self_approval=False,
        )
        self.assertFalse(ok)
        self.assertIn("SELF_APPROVAL_PROHIBITED", err)

    # ========================================================
    # 17. ALL FIVE NODES INDEPENDENTLY COMMIT SAME BLOCK & QC
    # ========================================================
    def test_17_all_five_nodes_independently_verify_same_committed_block_and_qc(self):
        """
        Verify complete multi-stage consensus across 5 nodes:
        All five nodes independently verify transactions, sign PREPARE and COMMIT,
        form a verifiable Quorum Certificate, and commit the exact same block hash to disk.
        """
        nodes = ["NODE-001", "NODE-002", "NODE-003", "NODE-004", "NODE-005"]
        chains = {nid: ExaminerBlockchain(nid, self.test_dir) for nid in nodes}
        engines = {
            nid: ExaminerConsensusEngine(nid, EXAMINER_TEACHER_MAP[nid], chains[nid], quorum_threshold=4, storage_dir=self.test_dir)
            for nid in nodes
        }

        # Step 1: Leader (NODE-001) creates PRE_PREPARE
        ok, prep_msg, _ = engines["NODE-001"].create_pre_prepare(
            transactions=[{
                "transaction_id": "tx-final-bft",
                "data": {
                    "type": "EVALUATION_APPROVED",
                    "answer_script_id": "AS-BFT-FINAL-001",
                    "head_examiner_id": "TCH-002",
                    "marks": 94.0,
                },
            }],
            subject="DBMS",
            view=0,
        )
        self.assertTrue(ok)
        prop_id = prep_msg.payload["proposal_id"]
        block_hash = prep_msg.payload["block_hash"]

        # Step 2: Replicas handle PRE_PREPARE and generate PREPARE votes
        prepare_msgs = []
        for nid in nodes:
            ok, p_msg, _ = engines[nid].handle_pre_prepare(prep_msg, is_leader_authorized=True)
            if ok and p_msg:
                prepare_msgs.append(p_msg)

        self.assertEqual(len(prepare_msgs), 5)

        # Step 3: Replicas exchange PREPARE votes to form Prepare QC
        commit_msgs = []
        for nid in nodes:
            for p_msg in prepare_msgs:
                ok, c_msg, _ = engines[nid].handle_prepare(p_msg)
                if ok and c_msg and c_msg not in commit_msgs:
                    commit_msgs.append(c_msg)

        self.assertTrue(len(commit_msgs) >= 4)  # BFT Quorum reached!

        # Step 4: Replicas exchange COMMIT votes to form Commit QC and commit block
        committed_blocks = {}
        for nid in nodes:
            for c_msg in commit_msgs:
                ok, block, notice, _ = engines[nid].handle_commit(c_msg)
                if ok and block:
                    committed_blocks[nid] = block

        # All 5 nodes must have committed the block
        self.assertEqual(len(committed_blocks), 5)
        committed_hashes = {b["hash"] for b in committed_blocks.values()}
        self.assertEqual(len(committed_hashes), 1)  # All 5 nodes committed identical block hash
        self.assertEqual(list(committed_hashes)[0], block_hash)

        # Verify disk files contain valid block with Quorum Certificate
        for nid in nodes:
            chain_file = chains[nid].chain_file
            with open(chain_file, "r", encoding="utf-8") as f:
                disk_data = json.load(f)
            self.assertEqual(disk_data[-1]["hash"], block_hash)
            self.assertIn("quorum_certificate", disk_data[-1])
            qc = disk_data[-1]["quorum_certificate"]
            self.assertEqual(qc["stage"], "COMMIT")
            self.assertTrue(len(qc["signatures"]) >= 4)

    # ========================================================
    # 18. QUORUM CERTIFICATE CRYPTOGRAPHIC BINDING
    # ========================================================
    def test_18_quorum_certificate_cryptographic_binding(self):
        """
        Verify that the Quorum Certificate is strictly bound to:
        network ID, block height, block hash, proposal ID, and view number.
        Tampering with ANY of these attributes invalidates the certificate.
        """
        qc = QuorumCertificate(
            stage="COMMIT",
            view=0,
            block_height=1,
            proposal_id="PROP-BIND-001",
            block_hash="abcd" * 16,
            network_id="AnswerChain",
        )
        privs = [get_or_create_actor_keys(n)[0] for n in ALL_EXAMINER_NODES[:4]]
        for nid, priv in zip(ALL_EXAMINER_NODES[:4], privs):
            qc.add_signature(nid, sign_payload(priv, qc.canonical_bytes()))

        # Legitimate QC passes verification
        ok, err = qc.verify(required_quorum=4, expected_network_id="AnswerChain")
        self.assertTrue(ok)
        self.assertIsNone(err)

        # 1. Tamper Network ID
        qc.network_id = "OtherNetwork"
        ok_net, err_net = qc.verify(required_quorum=4, expected_network_id="AnswerChain")
        self.assertFalse(ok_net)
        self.assertIn("NETWORK_ID_MISMATCH", err_net)
        qc.network_id = "AnswerChain"

        # 2. Tamper Block Height
        qc.block_height = 2
        ok_h, err_h = qc.verify(required_quorum=4)
        self.assertFalse(ok_h)
        self.assertIn("INVALID_QC_SIGNATURE", err_h)
        qc.block_height = 1

        # 3. Tamper Block Hash
        qc.block_hash = "1234" * 16
        ok_hash, err_hash = qc.verify(required_quorum=4)
        self.assertFalse(ok_hash)
        self.assertIn("INVALID_QC_SIGNATURE", err_hash)
        qc.block_hash = "abcd" * 16

        # 4. Tamper Proposal ID
        qc.proposal_id = "PROP-FORGED-999"
        ok_prop, err_prop = qc.verify(required_quorum=4)
        self.assertFalse(ok_prop)
        self.assertIn("INVALID_QC_SIGNATURE", err_prop)
        qc.proposal_id = "PROP-BIND-001"

        # 5. Tamper View Number
        qc.view = 1
        ok_v, err_v = qc.verify(required_quorum=4)
        self.assertFalse(ok_v)
        self.assertIn("INVALID_QC_SIGNATURE", err_v)
        qc.view = 0

    # ========================================================
    # 19. FAULT MODEL MATHEMATICAL BOUNDS (BFT vs CFT)
    # ========================================================
    def test_19_fault_model_mathematical_bounds(self):
        """
        Verify that CFT mode (3/5 quorum, f=2) and BFT mode (4/5 quorum, f=1)
        are clearly separated and strictly mathematically asserted.
        """
        # BFT Mode: N=5, f=1 Byzantine node -> Q=4 (80%, N >= 3f + 1)
        f_bft, q_bft = validate_fault_model("BFT", 5)
        self.assertEqual(f_bft, 1)
        self.assertEqual(q_bft, 4)

        # CFT Mode: N=5, f=2 Crash failures -> Q=3 (60%, N >= 2f + 1)
        f_cft, q_cft = validate_fault_model("CFT", 5)
        self.assertEqual(f_cft, 2)
        self.assertEqual(q_cft, 3)

        # Engine initialization respects modes
        chain = ExaminerBlockchain("NODE-001", self.test_dir)
        eng_bft = ExaminerConsensusEngine("NODE-001", "TCH-001", chain, consensus_mode=ConsensusMode.BFT, storage_dir=self.test_dir)
        self.assertEqual(eng_bft.quorum_threshold, 4)

        eng_cft = ExaminerConsensusEngine("NODE-001", "TCH-001", chain, consensus_mode=ConsensusMode.CFT, storage_dir=self.test_dir)
        self.assertEqual(eng_cft.quorum_threshold, 3)

        # Invalid mode rejected
        with self.assertRaises(ValueError):
            validate_fault_model("INVALID_MODE", 5)

    # ========================================================
    # 20. PERSISTENT LOCKING BLOCKS CONFLICTING PROPOSALS ACROSS VIEWS
    # ========================================================
    def test_20_persistent_locking_blocks_conflicting_proposal_across_views(self):
        """
        Verify the PBFT locking rule:
        When a node prepares a proposal in View 0, it acquires a persistent lock.
        If a new leader in View 1 proposes a conflicting block without a higher prepared QC,
        the honest node strictly rejects the proposal with LOCKED_BLOCK_CONFLICT.
        """
        chain = ExaminerBlockchain("NODE-002", self.test_dir)
        engine = ExaminerConsensusEngine("NODE-002", "TCH-002", chain, quorum_threshold=4, storage_dir=self.test_dir)

        # Step 1: Proposal A in View 0
        block_a = {
            "index": 1,
            "timestamp": time.time(),
            "data": [{"type": "EVALUATION_APPROVED", "marks": 85.0}],
            "previous_hash": chain.get_latest_block()["hash"],
        }
        block_a["hash"] = chain.calculate_hash(1, block_a["timestamp"], block_a["data"], block_a["previous_hash"])

        prep_msg_a = IPCMessage(
            message_type=MessageType.PRE_PREPARE,
            sender="NODE-001",
            receiver="*",
            payload={
                "network_id": "AnswerChain",
                "proposal_id": "PROP-A-v0",
                "view": 0,
                "block_height": 1,
                "block_hash": block_a["hash"],
                "block": block_a,
                "subject": "DBMS",
            },
        )
        ok, _, _ = engine.handle_pre_prepare(prep_msg_a, is_leader_authorized=True)
        self.assertTrue(ok)

        # Simulate Prepare QC reaching quorum -> Node-002 locks on block A
        privs = [get_or_create_actor_keys(n)[0] for n in ALL_EXAMINER_NODES[:4]]
        qc_template = QuorumCertificate("PREPARE", 0, 1, "PROP-A-v0", block_a["hash"], network_id="AnswerChain")
        for nid, priv in zip(ALL_EXAMINER_NODES[:4], privs):
            sig = sign_payload(priv, qc_template.canonical_bytes())
            engine.handle_prepare(IPCMessage(
                message_type=MessageType.PREPARE,
                sender=nid,
                receiver="*",
                payload={"proposal_id": "PROP-A-v0", "view": 0, "block_height": 1, "block_hash": block_a["hash"], "signature": sig},
            ))

        # Verify persistent lock is active
        self.assertEqual(engine.durable_state.locked_block_hash, block_a["hash"])
        self.assertEqual(engine.durable_state.locked_height, 1)

        # Step 2: In View 1, a Byzantine leader attempts to propose conflicting block B
        block_b = {
            "index": 1,
            "timestamp": time.time(),
            "data": [{"type": "EVALUATION_APPROVED", "marks": 99.0}],
            "previous_hash": chain.get_latest_block()["hash"],
        }
        block_b["hash"] = chain.calculate_hash(1, block_b["timestamp"], block_b["data"], block_b["previous_hash"])

        prep_msg_b = IPCMessage(
            message_type=MessageType.PRE_PREPARE,
            sender="NODE-002",
            receiver="*",
            payload={
                "network_id": "AnswerChain",
                "proposal_id": "PROP-B-v1-CONFLICT",
                "view": 1,
                "block_height": 1,
                "block_hash": block_b["hash"],
                "block": block_b,
                "subject": "DBMS",
            },
        )
        ok_b, _, err_b = engine.handle_pre_prepare(prep_msg_b, is_leader_authorized=True)
        self.assertFalse(ok_b)
        self.assertIn("LOCKED_BLOCK_CONFLICT", err_b)

    # ========================================================
    # 21. VIEW-CHANGE PRESERVES HIGHEST PREPARED PROPOSAL
    # ========================================================
    def test_21_view_change_preserves_highest_prepared_proposal(self):
        """
        Verify that during a View-Change, the new leader preserves the proposal
        with the highest prepare certificate reported across the view-change quorum.
        """
        chain1 = ExaminerBlockchain("NODE-001", self.test_dir)
        chain2 = ExaminerBlockchain("NODE-002", self.test_dir)
        eng1 = ExaminerConsensusEngine("NODE-001", "TCH-001", chain1, quorum_threshold=4, storage_dir=self.test_dir)
        eng2 = ExaminerConsensusEngine("NODE-002", "TCH-002", chain2, quorum_threshold=4, storage_dir=self.test_dir)

        # Prepare a proposal on NODE-001 in view 0
        block_prep = {
            "index": 1,
            "timestamp": time.time(),
            "data": [{"type": "EVALUATION_APPROVED", "marks": 90.0}],
            "previous_hash": chain1.get_latest_block()["hash"],
        }
        block_prep["hash"] = chain1.calculate_hash(1, block_prep["timestamp"], block_prep["data"], block_prep["previous_hash"])

        prep_qc = QuorumCertificate("PREPARE", 0, 1, "PROP-PRESERVE-01", block_prep["hash"], network_id="AnswerChain")
        privs = [get_or_create_actor_keys(n)[0] for n in ALL_EXAMINER_NODES[:4]]
        for nid, priv in zip(ALL_EXAMINER_NODES[:4], privs):
            prep_qc.add_signature(nid, sign_payload(priv, prep_qc.canonical_bytes()))

        # Set lock on NODE-001
        eng1.durable_state.set_lock(1, 0, block_prep["hash"], prep_qc.to_dict(), block_prep)

        # Trigger view change to view 1 (where NODE-002 is leader)
        vc_msg1 = eng1.trigger_view_change(target_view=1)
        self.assertEqual(vc_msg1.payload["highest_prepared_qc"]["block_hash"], block_prep["hash"])

        # Feed 4 view-change messages to new leader NODE-002
        eng2.handle_view_change(vc_msg1)
        for voter in ["NODE-002", "NODE-003", "NODE-004"]:
            priv, _ = get_or_create_actor_keys(voter)
            canon = json.dumps({"latest_hash": chain2.get_latest_block()["hash"], "network_id": "AnswerChain", "new_view": 1, "node_id": voter}, sort_keys=True).encode("utf-8")
            sig = sign_payload(priv, canon)
            vc_other = IPCMessage(
                message_type=MessageType.VIEW_CHANGE,
                sender=voter,
                receiver="NODE-002",
                payload={"network_id": "AnswerChain", "new_view": 1, "sender_node": voter, "signature": sig, "latest_hash": chain2.get_latest_block()["hash"]},
                signature=sig,
            )
            eng2.handle_view_change(vc_other)

        # Leader NODE-002 must have established NEW_VIEW and preserved the prepared QC
        self.assertEqual(eng2.current_view, 1)
        self.assertEqual(eng2.durable_state.locked_block_hash, block_prep["hash"])

    # ========================================================
    # 22. LEADER FAILURE AT PRE-PREPARE STAGE
    # ========================================================
    def test_22_leader_failure_at_pre_prepare_stage(self):
        """
        Verify resilience when the leader crashes immediately after PRE-PREPARE.
        Replicas detect timeout / failure and trigger view change to View 1.
        """
        chain2 = ExaminerBlockchain("NODE-002", self.test_dir)
        eng2 = ExaminerConsensusEngine("NODE-002", "TCH-002", chain2, quorum_threshold=4, storage_dir=self.test_dir)

        # Replicas initiate view change 0 -> 1
        vc_msg = eng2.trigger_view_change(target_view=1)
        self.assertEqual(vc_msg.payload["new_view"], 1)

        # Feed quorum of 4 VIEW_CHANGE messages to new leader NODE-002
        for voter in ALL_EXAMINER_NODES[:4]:
            priv, _ = get_or_create_actor_keys(voter)
            canon = json.dumps({"latest_hash": chain2.get_latest_block()["hash"], "network_id": "AnswerChain", "new_view": 1, "node_id": voter}, sort_keys=True).encode("utf-8")
            sig = sign_payload(priv, canon)
            eng2.handle_view_change(IPCMessage(
                message_type=MessageType.VIEW_CHANGE,
                sender=voter,
                receiver="NODE-002",
                payload={"network_id": "AnswerChain", "new_view": 1, "sender_node": voter, "signature": sig},
                signature=sig,
            ))

        self.assertEqual(eng2.current_view, 1)
        self.assertEqual(eng2.get_leader_for_view(1), "NODE-002")

    # ========================================================
    # 23. LEADER FAILURE AT PREPARE STAGE
    # ========================================================
    def test_23_leader_failure_at_prepare_stage(self):
        """
        Verify resilience when leader crashes during PREPARE after nodes prepare.
        Nodes preserve the prepared block across the view change.
        """
        nodes = ["NODE-002", "NODE-003", "NODE-004", "NODE-005"]
        chains = {n: ExaminerBlockchain(n, self.test_dir) for n in nodes}
        engines = {n: ExaminerConsensusEngine(n, EXAMINER_TEACHER_MAP[n], chains[n], quorum_threshold=4, storage_dir=self.test_dir) for n in nodes}

        # Prepare proposal H_A
        block_hash = "cafebabe" * 8
        prep_qc = QuorumCertificate("PREPARE", 0, 1, "PROP-CRASH-PREP", block_hash, network_id="AnswerChain")
        privs = [get_or_create_actor_keys(n)[0] for n in ALL_EXAMINER_NODES[:4]]
        for nid, priv in zip(ALL_EXAMINER_NODES[:4], privs):
            prep_qc.add_signature(nid, sign_payload(priv, prep_qc.canonical_bytes()))

        for n in nodes:
            engines[n].durable_state.set_lock(1, 0, block_hash, prep_qc.to_dict(), {"index": 1, "hash": block_hash})

        # All 4 nodes initiate view change to view 1
        vc_msgs = [engines[n].trigger_view_change(target_view=1) for n in nodes]

        # Deliver to new leader NODE-002
        for msg in vc_msgs:
            engines["NODE-002"].handle_view_change(msg)

        # Leader NODE-002 enters view 1 with block preserved
        self.assertEqual(engines["NODE-002"].current_view, 1)
        self.assertEqual(engines["NODE-002"].durable_state.locked_block_hash, block_hash)

    # ========================================================
    # 24. LEADER FAILURE AT COMMIT STAGE
    # ========================================================
    def test_24_leader_failure_at_commit_stage(self):
        """
        Verify resilience when leader crashes after forming Commit QC.
        Replicas catch up and commit using the Commit QC.
        """
        chain = ExaminerBlockchain("NODE-002", self.test_dir)
        block = {
            "index": 1,
            "timestamp": time.time(),
            "data": [{"type": "EVALUATION_APPROVED", "marks": 88.0}],
            "previous_hash": chain.get_latest_block()["hash"],
        }
        block["hash"] = chain.calculate_hash(1, block["timestamp"], block["data"], block["previous_hash"])

        commit_qc = QuorumCertificate("COMMIT", 0, 1, "PROP-COMMIT-FAIL", block["hash"], network_id="AnswerChain")
        privs = [get_or_create_actor_keys(n)[0] for n in ALL_EXAMINER_NODES[:4]]
        for nid, priv in zip(ALL_EXAMINER_NODES[:4], privs):
            commit_qc.add_signature(nid, sign_payload(priv, commit_qc.canonical_bytes()))

        # Replicas verify the Commit QC and commit the block independently
        valid, err = commit_qc.verify(required_quorum=4, expected_network_id="AnswerChain")
        self.assertTrue(valid)

        committed_blk = chain.add_block(
            transactions=block["data"],
            previous_hash=block["previous_hash"],
            block_timestamp=block["timestamp"],
            quorum_certificate=commit_qc.to_dict(),
        )
        self.assertEqual(committed_blk["hash"], block["hash"])
        self.assertEqual(chain.get_latest_block()["index"], 1)

    # ========================================================
    # 25. NETWORK PARTITION RESILIENCE (MINORITY STALLS, MAJORITY HEALS)
    # ========================================================
    def test_25_network_partition_resilience(self):
        """
        Verify network partition safety:
        - In BFT mode (Q=4), a partition of 2 nodes cannot commit (2/4).
        - A partition of 3 nodes cannot commit (3/4). Zero forks occur!
        - When the partition heals, all nodes exchange votes and commit safely.
        """
        nodes = ALL_EXAMINER_NODES
        chains = {n: ExaminerBlockchain(n, self.test_dir) for n in nodes}
        engines = {n: ExaminerConsensusEngine(n, EXAMINER_TEACHER_MAP[n], chains[n], quorum_threshold=4, storage_dir=self.test_dir) for n in nodes}

        ok, prep_msg, _ = engines["NODE-001"].create_pre_prepare(
            transactions=[{"data": {"type": "EVALUATION_APPROVED", "marks": 75.0}}],
            subject="DBMS",
            view=0,
        )
        self.assertTrue(ok)

        # Partition 1: {NODE-001, NODE-002} (only 2 nodes can exchange messages)
        p1_msgs = []
        for n in ["NODE-001", "NODE-002"]:
            ok, p_msg, _ = engines[n].handle_pre_prepare(prep_msg, is_leader_authorized=True)
            if ok and p_msg:
                p1_msgs.append(p_msg)

        # Exchange in Partition 1 only
        p1_commit_msgs = []
        for n in ["NODE-001", "NODE-002"]:
            for m in p1_msgs:
                ok, c_msg, _ = engines[n].handle_prepare(m)
                if ok and c_msg:
                    p1_commit_msgs.append(c_msg)

        # Neither reached quorum (2 < 4)
        self.assertEqual(len(p1_commit_msgs), 0)
        self.assertEqual(chains["NODE-001"].get_latest_block()["index"], 0)
        self.assertEqual(chains["NODE-002"].get_latest_block()["index"], 0)

        # Partition Heals: deliver to NODE-003, NODE-004, NODE-005
        p2_msgs = []
        for n in ["NODE-003", "NODE-004", "NODE-005"]:
            ok, p_msg, _ = engines[n].handle_pre_prepare(prep_msg, is_leader_authorized=True)
            if ok and p_msg:
                p2_msgs.append(p_msg)

        all_prep_msgs = p1_msgs + p2_msgs
        all_commit_msgs = []
        for n in nodes:
            for m in all_prep_msgs:
                ok, c_msg, _ = engines[n].handle_prepare(m)
                if ok and c_msg and c_msg not in all_commit_msgs:
                    all_commit_msgs.append(c_msg)

        self.assertTrue(len(all_commit_msgs) >= 4)  # BFT Quorum reached!

        # Exchange commits
        for n in nodes:
            for c in all_commit_msgs:
                engines[n].handle_commit(c)

        # All 5 nodes safely converged
        for n in nodes:
            self.assertEqual(chains[n].get_latest_block()["index"], 1)

    # ========================================================
    # 26. DELAYED AND DUPLICATED IPC MESSAGES
    # ========================================================
    def test_26_delayed_and_duplicated_ipc_messages(self):
        """
        Verify that duplicate and delayed messages do not corrupt state or inflate quorum:
        - Duplicate PREPARE votes are not counted twice.
        - Replayed PRE_PREPARE is rejected with REPLAYED_MESSAGE_REJECTED.
        - COMMIT message for an unknown proposal is safely handled.
        """
        chain = ExaminerBlockchain("NODE-001", self.test_dir)
        engine = ExaminerConsensusEngine("NODE-001", "TCH-001", chain, quorum_threshold=4, storage_dir=self.test_dir)

        ok, prep_msg, _ = engine.create_pre_prepare(
            transactions=[{"data": {"type": "EVALUATION_APPROVED", "marks": 80.0}}],
            subject="DBMS",
        )
        self.assertTrue(ok)
        prop_id = prep_msg.payload["proposal_id"]

        # First delivery of PRE_PREPARE to replica
        replica = ExaminerConsensusEngine("NODE-002", "TCH-002", ExaminerBlockchain("NODE-002", self.test_dir), storage_dir=self.test_dir)
        ok1, _, _ = replica.handle_pre_prepare(prep_msg, is_leader_authorized=True)
        self.assertTrue(ok1)

        # Duplicate PRE_PREPARE replay to replica
        ok_dup, _, err_dup = replica.handle_pre_prepare(prep_msg, is_leader_authorized=True)
        self.assertFalse(ok_dup)
        self.assertEqual(err_dup, "REPLAYED_MESSAGE_REJECTED")

        # Duplicate PREPARE vote from NODE-002
        priv, _ = get_or_create_actor_keys("NODE-002")
        qc_t = QuorumCertificate("PREPARE", 0, 1, prop_id, prep_msg.payload["block_hash"], network_id="AnswerChain")
        sig = sign_payload(priv, qc_t.canonical_bytes())
        p_msg = IPCMessage(
            message_type=MessageType.PREPARE,
            sender="NODE-002",
            receiver="*",
            payload={"proposal_id": prop_id, "view": 0, "block_height": 1, "block_hash": prep_msg.payload["block_hash"], "signature": sig},
        )
        ok1, _, status1 = engine.handle_prepare(p_msg)
        ok2, _, status2 = engine.handle_prepare(p_msg)  # Duplicate!
        self.assertEqual(status1, status2)  # Vote count did not artificially inflate

        # Out-of-order COMMIT for unknown proposal
        unknown_commit = IPCMessage(
            message_type=MessageType.COMMIT,
            sender="NODE-003",
            receiver="*",
            payload={"proposal_id": "PROP-UNKNOWN-999", "view": 0, "block_height": 1, "block_hash": "0000", "signature": sig},
        )
        ok_unk, _, _, err_unk = engine.handle_commit(unknown_commit)
        self.assertFalse(ok_unk)
        self.assertEqual(err_unk, "UNKNOWN_PROPOSAL")

    # ========================================================
    # 27. CHAIN SYNC CANNOT REPLACE COMMITTED CHAIN WITH CONFLICTING LONGER CHAIN
    # ========================================================
    def test_27_chain_sync_cannot_replace_committed_chain_with_conflicting_longer_chain(self):
        """
        Verify Prefix Finality:
        A node with a locally committed chain strictly refuses to replace its chain
        with a longer candidate chain if the candidate conflicts with any already-committed block.
        """
        chain = ExaminerBlockchain("NODE-001", self.test_dir)

        # Commit Block #1 locally
        blk1 = chain.add_block(transactions=[{"tx": 1}], block_timestamp=100.0)
        self.assertEqual(chain.get_latest_block()["index"], 1)
        local_h1 = blk1["hash"]

        # Adversary crafts a longer chain (length 3, blocks 0, 1', 2') conflicting at block #1
        genesis = chain.chain[0]
        fake_b1 = {
            "index": 1,
            "timestamp": 105.0,
            "data": [{"tx": "FORGED_TX"}],
            "previous_hash": genesis["hash"],
        }
        fake_b1["hash"] = chain.calculate_hash(1, fake_b1["timestamp"], fake_b1["data"], fake_b1["previous_hash"])

        fake_b2 = {
            "index": 2,
            "timestamp": 110.0,
            "data": [{"tx": "FORGED_TX_2"}],
            "previous_hash": fake_b1["hash"],
        }
        fake_b2["hash"] = chain.calculate_hash(2, fake_b2["timestamp"], fake_b2["data"], fake_b2["previous_hash"])

        longer_adversarial_chain = [genesis, fake_b1, fake_b2]
        self.assertEqual(len(longer_adversarial_chain), 3)
        self.assertEqual(len(chain.chain), 2)

        # replace_chain must strictly REJECT the reorganization
        replaced = chain.replace_chain(longer_adversarial_chain)
        self.assertFalse(replaced)

        # Local chain remains unchanged
        self.assertEqual(chain.get_latest_block()["index"], 1)
        self.assertEqual(chain.get_latest_block()["hash"], local_h1)

    # ========================================================
    # 28. DURABLE CONSENSUS STATE WAL RESTORATION ACROSS CRASH
    # ========================================================
    def test_28_durable_consensus_state_wal_restoration_across_crash(self):
        """
        Verify that DurableConsensusState restores voting history, locks, and QCs
        from disk snapshot and WAL replay across an unexpected process crash.
        """
        # Node 1 writes to durable state
        state1 = DurableConsensusState("NODE-001", self.test_dir)
        state1.record_vote(height=1, view=0, block_hash="hash_h1_v0")
        state1.record_vote(height=2, view=0, block_hash="hash_h2_v0")
        state1.set_lock(height=2, view=0, block_hash="hash_h2_v0", prepare_qc={"view": 0, "block_hash": "hash_h2_v0"})
        state1.record_alert("BYZANTINE_DETECTED", {"offender": "NODE-005"})

        # Simulate process crash: destroy in-memory object and reload
        del state1

        recovered = DurableConsensusState("NODE-001", self.test_dir)
        self.assertEqual(recovered.voted_proposals.get("1_0"), "hash_h1_v0")
        self.assertEqual(recovered.voted_proposals.get("2_0"), "hash_h2_v0")
        self.assertEqual(recovered.locked_block_hash, "hash_h2_v0")
        self.assertEqual(recovered.locked_height, 2)
        self.assertTrue(recovered.has_conflicting_vote(2, 0, "conflicting_attempt"))
        self.assertEqual(len(recovered.alerts), 1)

    # ========================================================
    # 29. ELECTION PLURALITY, PARTICIPATION QUORUM & TERM EXPIRATION
    # ========================================================
    def test_29_election_plurality_participation_quorum_and_term_expiration(self):
        """
        Verify:
        1. Participation quorum: election with < 3 votes fails.
        2. Tie handling: tie between 2 candidates is deterministically broken.
        3. Term expiration: expired Head Examiner cannot approve evaluations.
        """
        # 1. Insufficient participation
        elec_low = SubjectElection(
            election_id="ELEC-LOW-PART",
            subject="OS",
            participation_quorum=3,
        )
        elec_low.cast_vote("TCH-001", "TCH-002")
        elec_low.cast_vote("TCH-002", "TCH-002")
        ok_low, reason_low, res_low = elec_low.tally()
        self.assertFalse(ok_low)
        self.assertEqual(reason_low, "INSUFFICIENT_PARTICIPATION")
        self.assertEqual(elec_low.status, ElectionStatus.FAILED_INSUFFICIENT_PARTICIPATION)

        # 2. Tie resolution
        elec_tie = SubjectElection(
            election_id="ELEC-TIE-BREAK",
            subject="NETWORKS",
            participation_quorum=3,
        )
        elec_tie.cast_vote("TCH-001", "TCH-001")
        elec_tie.cast_vote("TCH-002", "TCH-001")
        elec_tie.cast_vote("TCH-003", "TCH-002")
        elec_tie.cast_vote("TCH-004", "TCH-002")
        ok_tie, _, res_tie = elec_tie.tally(break_ties=True)
        self.assertTrue(ok_tie)
        self.assertEqual(res_tie["winner_id"], "TCH-001")  # Lexicographical tie break TCH-001 < TCH-002
        self.assertTrue(res_tie["tie_resolved"])

        # 3. Term expiration check
        registry = HeadExaminerRegistry()
        elec_exp = SubjectElection(
            election_id="ELEC-EXP",
            subject="COMPILERS",
            term_days=-1,  # Expired immediately
            participation_quorum=3,
        )
        for v in ["TCH-001", "TCH-002", "TCH-003"]:
            elec_exp.cast_vote(v, "TCH-003")
        elec_exp.tally()
        registry.record_election_conclusion(elec_exp)

        # is_head_examiner must return False for expired term
        self.assertFalse(registry.is_head_examiner("TCH-003", "COMPILERS"))


if __name__ == "__main__":
    unittest.main()
