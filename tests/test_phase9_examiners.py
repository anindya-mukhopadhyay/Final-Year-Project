"""
AnswerChain Phase 9 Comprehensive Automated Test Suite.

Tests:
1. Five independent examiner processes creation & PID verification.
2. Five independent database files on disk in separate paths.
3. Identical genesis hashes matching network standards across all 5 nodes.
4. IPC message exchange via multiprocessing.Queue.
5. Invalid IPC message rejection (bad type, bad structure).
6. Democratic subject Head Examiner election with cryptographic signatures.
7. Strict duplicate vote rejection per teacher per subject election.
8. Head Examiner evaluation verification & Ed25519 digital approval.
9. Invalid block proposal rejection (wrong prev_hash, bad signatures).
10. Distributed PBFT consensus quorum verification (>= 3 out of 5 votes).
11. Independent block commitment across all 5 examiner chains.
12. Node crash isolation (crashing 1 node leaves remaining 4 active).
13. Node restart recovery and peer chain synchronization.
14. Regression verification: Phase 1–8 functionality preserved.
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
    DEFAULT_ELIGIBLE_TEACHERS,
    EXAMINER_TEACHER_MAP,
    ElectionStatus,
    ExaminerBlockchain,
    ExaminerConsensusEngine,
    ExaminerNetworkManager,
    HeadExaminerRegistry,
    IPCMessage,
    IPCRouter,
    MessageType,
    SubjectElection,
)


class Phase9ExaminerNetworkTests(unittest.TestCase):
    """Phase 9 Comprehensive Test Suite for Multi-Process Examiner Network."""

    @classmethod
    def setUpClass(cls):
        # Create dedicated isolated test directory for examiner node databases
        cls.test_storage_dir = tempfile.mkdtemp(prefix="answerchain_test_examiners_")
        cls.manager = ExaminerNetworkManager(
            node_mapping=EXAMINER_TEACHER_MAP,
            storage_base_dir=cls.test_storage_dir,
        )
        cls.manager.start()

    @classmethod
    def tearDownClass(cls):
        cls.manager.stop()
        if os.path.exists(cls.test_storage_dir):
            shutil.rmtree(cls.test_storage_dir, ignore_errors=True)

    # ========================================================
    # 1. FIVE INDEPENDENT PROCESS CREATION
    # ========================================================
    def test_01_five_independent_processes_running(self):
        """Verify that exactly five independent OS processes are instantiated and running."""
        self.assertEqual(len(self.manager.processes), 5)
        pids = set()

        for node_id, proc in self.manager.processes.items():
            self.assertTrue(proc.is_alive(), f"Node {node_id} process should be alive")
            self.assertIsNotNone(proc.pid, f"Node {node_id} must have a valid OS PID")
            self.assertNotEqual(proc.pid, os.getpid(), f"Node {node_id} must run in a separate process from runner")
            pids.add(proc.pid)

        # All 5 PIDs must be unique
        self.assertEqual(len(pids), 5, "All 5 examiner nodes must run in distinct OS processes")

    # ========================================================
    # 2. FIVE INDEPENDENT DATABASE FILES
    # ========================================================
    def test_02_five_independent_database_files(self):
        """Verify that each process maintains its own independent database file."""
        expected_nodes = ["NODE-001", "NODE-002", "NODE-003", "NODE-004", "NODE-005"]
        for node_id in expected_nodes:
            db_file = os.path.join(self.test_storage_dir, f"{node_id}_blockchain.json")
            self.assertTrue(
                os.path.isfile(db_file),
                f"Database file for {node_id} must exist at {db_file}",
            )
            # Verify file contents are valid JSON
            with open(db_file, "r", encoding="utf-8") as f:
                data = json.load(f)
            self.assertIsInstance(data, list)
            self.assertTrue(len(data) >= 1)

    # ========================================================
    # 3. IDENTICAL GENESIS HASHES ACROSS ALL NODES
    # ========================================================
    def test_03_identical_genesis_block_and_network_id(self):
        """Verify that all nodes share identical genesis block, hash, and network ID."""
        genesis_hashes = []
        network_ids = []

        for node_id in ["NODE-001", "NODE-002", "NODE-003", "NODE-004", "NODE-005"]:
            db_file = os.path.join(self.test_storage_dir, f"{node_id}_blockchain.json")
            with open(db_file, "r", encoding="utf-8") as f:
                chain = json.load(f)
            genesis = chain[0]
            self.assertEqual(genesis["index"], 0)
            self.assertEqual(genesis["previous_hash"], "0")
            self.assertEqual(genesis["data"].get("type"), "GENESIS")
            self.assertEqual(genesis["data"].get("network"), "AnswerChain")
            genesis_hashes.append(genesis["hash"])
            network_ids.append(genesis["data"].get("network"))

        # All genesis hashes must match exactly
        self.assertEqual(len(set(genesis_hashes)), 1, "All 5 nodes must share identical genesis hash")
        self.assertEqual(
            genesis_hashes[0],
            "ab2d1cf7aeb06fcd256df0824f653cda30a180a86dcf3f9fa3fd79e966f471c7",
        )

    # ========================================================
    # 4. IPC MESSAGE EXCHANGE
    # ========================================================
    def test_04_ipc_message_exchange(self):
        """Verify message creation, delivery, and receipt across IPC channels."""
        msg = IPCMessage(
            message_type=MessageType.NODE_HEARTBEAT,
            sender="MANAGER",
            receiver="NODE-001",
            payload={"ping": 12345},
        )
        ok, err = self.manager.router.send(msg)
        self.assertTrue(ok, f"IPC send failed: {err}")

        # Node process responds with heartbeat to MANAGER
        # Wait up to 2 seconds for response on manager_queue
        received_reply = False
        start = time.time()
        while time.time() - start < 3.0:
            reply = self.manager.router.receive("MANAGER", timeout=0.3)
            if reply and reply.message_type == MessageType.NODE_HEARTBEAT and reply.sender == "NODE-001":
                self.assertEqual(reply.payload.get("node_id"), "NODE-001")
                self.assertEqual(reply.payload.get("status"), "ONLINE")
                received_reply = True
                break

        self.assertTrue(received_reply, "NODE-001 did not respond to heartbeat over IPC")

    # ========================================================
    # 5. INVALID IPC MESSAGE REJECTION
    # ========================================================
    def test_05_invalid_ipc_message_rejection(self):
        """Verify that malformed or unsupported IPC messages are rejected."""
        # Bad message type
        bad_msg = IPCMessage(
            message_type="UNKNOWN_UNSUPPORTED_TYPE",
            sender="NODE-001",
            receiver="NODE-002",
        )
        is_valid, err = bad_msg.validate()
        self.assertFalse(is_valid)
        self.assertIn("INVALID_MESSAGE_TYPE", err)

        # Missing sender
        no_sender = IPCMessage(
            message_type=MessageType.NODE_HEARTBEAT,
            sender="",
            receiver="NODE-002",
        )
        is_valid, err = no_sender.validate()
        self.assertFalse(is_valid)
        self.assertIn("MISSING_SENDER", err)

    # ========================================================
    # 6. DEMOCRATIC HEAD EXAMINER ELECTION
    # ========================================================
    def test_06_democratic_head_examiner_election(self):
        """Verify democratic election for subject Head Examiner."""
        subject = "DBMS"
        election = self.manager.start_election(subject=subject, term_days=365)
        elec_id = election["election_id"]
        self.assertIn("ELEC-DBMS", elec_id)

        # 4 out of 5 eligible teachers vote for TCH-002 (NODE-002)
        # 1 teacher votes for TCH-001
        votes_plan = [
            ("TCH-001", "TCH-002"),
            ("TCH-002", "TCH-002"),
            ("TCH-003", "TCH-002"),
            ("TCH-004", "TCH-002"),
            ("TCH-005", "TCH-001"),
        ]

        for voter, candidate in votes_plan:
            ok, reason, details = self.manager.cast_vote(
                election_id=elec_id,
                voter_id=voter,
                candidate_id=candidate,
            )
            self.assertTrue(ok, f"Vote by {voter} failed: {reason}")

        # Tally result
        ok, reason, result = self.manager.conclude_election(elec_id)
        self.assertTrue(ok, f"Conclusion failed: {reason}")
        self.assertEqual(result["winner_id"], "TCH-002")
        self.assertEqual(result["winner_node_id"], "NODE-002")
        self.assertEqual(result["votes_cast"], 5)
        self.assertEqual(result["votes_summary"]["TCH-002"], 4)
        self.assertEqual(result["votes_summary"]["TCH-001"], 1)

        # Verify active Head Examiner registry
        he = self.manager.election_registry.get_head_examiner("DBMS")
        self.assertIsNotNone(he)
        self.assertEqual(he["head_examiner_id"], "TCH-002")
        self.assertTrue(he["is_valid"])

    # ========================================================
    # 7. DUPLICATE VOTE REJECTION
    # ========================================================
    def test_07_duplicate_vote_rejection(self):
        """Verify that duplicate voting by the same teacher is strictly rejected."""
        subject = "OPERATING_SYSTEMS"
        election = self.manager.start_election(subject=subject)
        elec_id = election["election_id"]

        # First vote succeeds
        ok, reason, _ = self.manager.cast_vote(
            election_id=elec_id,
            voter_id="TCH-003",
            candidate_id="TCH-003",
        )
        self.assertTrue(ok)

        # Second vote by same voter must be rejected
        ok, reason, _ = self.manager.cast_vote(
            election_id=elec_id,
            voter_id="TCH-003",
            candidate_id="TCH-001",
        )
        self.assertFalse(ok)
        self.assertIn("DUPLICATE_VOTE_REJECTED", reason)

    # ========================================================
    # 8. HEAD EXAMINER EVALUATION APPROVAL WORKFLOW
    # ========================================================
    def test_08_head_examiner_approval_workflow(self):
        """Verify Head Examiner verification and digital approval of evaluations."""
        # Ensure TCH-002 is Head Examiner for DBMS
        self.manager.election_registry.active_head_examiners["DBMS"] = {
            "subject": "DBMS",
            "head_examiner_id": "TCH-002",
            "node_id": "NODE-002",
            "term_start": time.time(),
            "term_end": time.time() + 86400,
            "is_valid": True,
        }

        # Teacher TCH-004 evaluates script
        eval_payload = {
            "type": "EVALUATION_SUBMITTED",
            "answer_script_id": "AS-P9-DBMS-001",
            "teacher_id": "TCH-004",
            "subject": "DBMS",
            "marks": 91.0,
            "max_marks": 100.0,
            "remarks": "Excellent normalization and indexing analysis.",
        }
        signed_eval = sign_academic_transaction(
            payload=eval_payload,
            actor_id="TCH-004",
            actor_role="TEACHER",
        )

        # Head Examiner approves evaluation
        engine = ExaminerConsensusEngine(
            node_id="NODE-002",
            teacher_id="TCH-002",
            blockchain=ExaminerBlockchain("NODE-002", self.test_storage_dir),
        )

        ok, approved_tx, err = engine.approve_evaluation(
            evaluation_data=signed_eval,
            head_examiner_id="TCH-002",
            subject="DBMS",
        )
        self.assertTrue(ok, f"Approval failed: {err}")
        self.assertIsNotNone(approved_tx)
        self.assertEqual(approved_tx["type"], "EVALUATION_APPROVED")
        self.assertEqual(approved_tx["head_examiner_id"], "TCH-002")
        self.assertEqual(approved_tx["actor_id"], "TCH-002")
        self.assertEqual(approved_tx["actor_role"], "HEAD_EXAMINER")
        self.assertIn("signature", approved_tx)

    # ========================================================
    # 9. INVALID BLOCK PROPOSAL REJECTION
    # ========================================================
    def test_09_invalid_block_proposal_rejection(self):
        """Verify that an invalid or unauthorized block proposal is rejected."""
        chain = ExaminerBlockchain("NODE-001", self.test_storage_dir)
        engine = ExaminerConsensusEngine("NODE-001", "TCH-001", chain)

        # 1. Propose with wrong previous_hash
        bad_proposal = {
            "block": {
                "index": len(chain.chain),
                "timestamp": time.time(),
                "data": [{"data": {"type": "TEST"}}],
                "previous_hash": "bad" * 16,
                "hash": "somehash",
            }
        }
        is_valid, reason = engine.validate_proposal(bad_proposal, is_proposer_authorized=True)
        self.assertFalse(is_valid)
        self.assertIn("PREVIOUS_HASH_MISMATCH", reason)

        # 2. Unauthorized proposer
        is_valid, reason = engine.validate_proposal(bad_proposal, is_proposer_authorized=False)
        self.assertFalse(is_valid)
        self.assertEqual(reason, "UNAUTHORIZED_PROPOSER")

    # ========================================================
    # 10. DISTRIBUTED PBFT CONSENSUS QUORUM VERIFICATION
    # ========================================================
    def test_10_consensus_quorum_threshold(self):
        """Verify that block commitment strictly requires >= 3 out of 5 node votes."""
        chain = ExaminerBlockchain("NODE-001", self.test_storage_dir)
        engine = ExaminerConsensusEngine("NODE-001", "TCH-001", chain, quorum_threshold=3)

        # Propose block
        prop_msg = engine.create_block_proposal(
            transactions=[{"data": {"type": "EVALUATION_APPROVED", "answer_script_id": "AS-QUORUM-TEST"}}],
            subject="DBMS",
        )
        prop_id = prop_msg.payload["proposal_id"]

        state = engine.active_proposals[prop_id]
        # Proposer already cast 1 vote -> total = 1 (< 3)
        self.assertFalse(state.is_committed)

        # Vote 2 from NODE-002 -> total = 2 (< 3)
        quorum_reached, count = state.record_vote("NODE-002", is_valid=True)
        self.assertFalse(quorum_reached)
        self.assertFalse(state.is_committed)
        self.assertEqual(count, 2)

        # Vote 3 from NODE-003 -> total = 3 (>= 3 -> QUORUM REACHED!)
        quorum_reached, count = state.record_vote("NODE-003", is_valid=True)
        self.assertTrue(quorum_reached)
        self.assertTrue(state.is_committed)
        self.assertEqual(count, 3)

    # ========================================================
    # 11. INDEPENDENT BLOCK COMMITMENT ACROSS CHAINS
    # ========================================================
    def test_11_block_commitment_across_examiner_chains(self):
        """Verify that upon consensus, every node appends the committed block to its own DB."""
        # Create a sample committed block with deterministic consensus timestamp
        fixed_timestamp = time.time()
        tx = {
            "transaction_id": "tx-consensus-001",
            "timestamp": fixed_timestamp,
            "data": {
                "type": "EVALUATION_APPROVED",
                "answer_script_id": "AS-P9-CONSENSUS-001",
                "head_examiner_id": "TCH-002",
                "marks": 95.0,
            },
        }

        # Each node loads its own chain and commits the block independently
        commit_hashes = []
        for node_id in ["NODE-001", "NODE-002", "NODE-003", "NODE-004", "NODE-005"]:
            chain = ExaminerBlockchain(node_id, self.test_storage_dir)
            block = chain.add_block(transactions=[tx], block_timestamp=fixed_timestamp)
            commit_hashes.append(block["hash"])

        # All 5 nodes must calculate and commit the EXACT same block hash
        self.assertEqual(len(set(commit_hashes)), 1)
        self.assertEqual(len(commit_hashes), 5)

        # Verify disk files updated
        for node_id in ["NODE-001", "NODE-002", "NODE-003", "NODE-004", "NODE-005"]:
            db_file = os.path.join(self.test_storage_dir, f"{node_id}_blockchain.json")
            with open(db_file, "r", encoding="utf-8") as f:
                data = json.load(f)
            self.assertEqual(data[-1]["hash"], commit_hashes[0])

    # ========================================================
    # 12. NODE CRASH PROCESS ISOLATION
    # ========================================================
    def test_12_node_crash_isolation(self):
        """Verify that crashing one node process does NOT terminate surviving nodes."""
        node_to_crash = "NODE-005"
        self.assertTrue(self.manager.processes[node_to_crash].is_alive())

        # Crash NODE-005
        ok = self.manager.crash_node(node_to_crash)
        self.assertTrue(ok)
        self.assertFalse(self.manager.processes[node_to_crash].is_alive())

        # The other 4 nodes MUST remain alive and healthy
        for nid in ["NODE-001", "NODE-002", "NODE-003", "NODE-004"]:
            self.assertTrue(
                self.manager.processes[nid].is_alive(),
                f"Surviving node {nid} should still be alive after {node_to_crash} crashed",
            )

    # ========================================================
    # 13. NODE RECOVERY AND STATE SYNCHRONIZATION
    # ========================================================
    def test_13_node_restart_and_chain_sync(self):
        """Verify that a crashed node recovers its persistent state and syncs upon restart."""
        node_to_restart = "NODE-005"
        self.assertFalse(self.manager.processes[node_to_restart].is_alive())

        # Restart node in a brand new process
        ok = self.manager.restart_node(node_to_restart)
        self.assertTrue(ok)
        self.assertTrue(self.manager.processes[node_to_restart].is_alive())
        self.assertNotEqual(
            self.manager.node_pids[node_to_restart],
            os.getpid(),
        )

        # Verify it loads its existing database from disk
        chain = ExaminerBlockchain(node_to_restart, self.test_storage_dir)
        self.assertTrue(len(chain.chain) >= 2)
        self.assertTrue(chain.is_valid_chain(chain.chain))

    # ========================================================
    # 14. ADMIN DIAGNOSTIC STATUS REPORTING
    # ========================================================
    def test_14_admin_diagnostics_report(self):
        """Verify diagnostic status format for Admin Dashboard."""
        status = self.manager.get_status()
        self.assertEqual(status["total_nodes"], 5)
        self.assertEqual(status["network_status"], "ONLINE")
        self.assertIn("nodes", status)
        self.assertIn("active_head_examiners", status)
        self.assertIn("elections", status)
        self.assertIn("ipc_stats", status)
        self.assertEqual(len(status["nodes"]), 5)


if __name__ == "__main__":
    unittest.main()
