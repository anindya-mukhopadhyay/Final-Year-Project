"""
AnswerChain Phase 9.1: Distributed BFT / Permissioned Consensus Engine.

Implements a hardened, multi-stage permissioned consensus protocol:
1. Request / Pre-Prepare
2. Prepare & Prepare Quorum Certificate (QC)
3. Commit & Commit Quorum Certificate (QC)
4. Independent Block Commitment with Embedded QC
5. Durable consensus state, append-only WAL & equivocation prevention (no double voting)
6. Persistent locking & highest prepared proposal preservation across View-Changes
7. Mathematical Quorum Definition:
   - Byzantine Fault Tolerance (BFT): N=5, f=1 Byzantine node -> Q = 4 (80%, N >= 3f + 1)
   - Crash Fault Tolerance (CFT): N=5, f=2 Crash failures -> Q = 3 (60%, N >= 2f + 1)
"""

import copy
import hashlib
import json
import logging
import os
import time
import uuid
from typing import Any, Dict, List, Optional, Set, Tuple

from backend.crypto import (
    canonicalize_transaction_payload,
    get_actor_public_key,
    get_or_create_actor_keys,
    sign_academic_transaction,
    sign_payload,
    verify_academic_transaction,
    verify_signature,
)
from backend.examiner.blockchain import ExaminerBlockchain
from backend.examiner.messages import IPCMessage, MessageType

logger = logging.getLogger("examiner.consensus")

# Canonical 5-node cluster membership
ALL_EXAMINER_NODES = ["NODE-001", "NODE-002", "NODE-003", "NODE-004", "NODE-005"]


class ConsensusStage:
    IDLE = "IDLE"
    PRE_PREPARE = "PRE_PREPARE"
    PREPARED = "PREPARED"
    COMMITTED = "COMMITTED"
    VIEW_CHANGE = "VIEW_CHANGE"


class ConsensusMode:
    BFT = "BFT"  # Byzantine Fault Tolerance: Q=4 for N=5, f=1 (PBFT: N >= 3f + 1)
    CFT = "CFT"  # Crash Fault Tolerance: Q=3 for N=5, f=2 (Raft/Paxos: N >= 2f + 1)


def validate_fault_model(mode: str, cluster_size: int = 5) -> Tuple[int, int]:
    """
    Returns (f_max, quorum_required).
    Strictly asserts mathematical consensus bounds:
    - BFT: N >= 3f + 1 => for N=5, f <= (5-1)//3 = 1. Quorum Q = N - f = 4 (80%).
           NEVER claims to tolerate 2 Byzantine nodes on a 5-node network.
    - CFT: N >= 2f + 1 => for N=5, f <= (5-1)//2 = 2. Quorum Q = (N//2) + 1 = 3 (60%).
           CFT strictly assumes crash-stop failures (zero malicious/equivocating behavior).
    """
    clean_mode = str(mode).strip().upper()
    if clean_mode == ConsensusMode.BFT:
        f_max = (cluster_size - 1) // 3
        q = cluster_size - f_max
        return f_max, q
    elif clean_mode == ConsensusMode.CFT:
        f_max = (cluster_size - 1) // 2
        q = (cluster_size // 2) + 1
        return f_max, q
    else:
        raise ValueError(f"Unknown consensus mode: {mode}")


class QuorumCertificate:
    """
    Verifiable Quorum Certificate (QC) proving that a quorum of authorized
    examiner nodes independently authenticated and voted for a proposal.
    Cryptographically bound to network ID, block height, block hash, proposal ID, and view.
    """

    def __init__(
        self,
        stage: str,
        view: int,
        block_height: int,
        proposal_id: str,
        block_hash: str,
        signatures: Optional[Dict[str, str]] = None,
        created_at: Optional[float] = None,
        network_id: str = "AnswerChain",
    ) -> None:
        self.stage = str(stage).strip().upper()  # "PREPARE" or "COMMIT"
        self.view = int(view)
        self.block_height = int(block_height)
        self.proposal_id = str(proposal_id).strip()
        self.block_hash = str(block_hash).strip()
        self.network_id = str(network_id).strip()
        # Node ID -> Ed25519 hex signature
        self.signatures: Dict[str, str] = dict(signatures or {})
        self.created_at = float(created_at if created_at is not None else time.time())

    def canonical_bytes(self) -> bytes:
        """Deterministic canonical bytes representation for signing and verification."""
        payload = {
            "block_hash": self.block_hash,
            "block_height": self.block_height,
            "network_id": self.network_id,
            "proposal_id": self.proposal_id,
            "stage": self.stage,
            "view": self.view,
        }
        return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")

    def add_signature(self, node_id: str, signature: str) -> None:
        """Add an authenticated signature from an examiner node."""
        self.signatures[str(node_id).strip().upper()] = str(signature).strip()

    def verify(
        self,
        eligible_nodes: Optional[List[str]] = None,
        required_quorum: int = 3,
        expected_network_id: Optional[str] = None,
    ) -> Tuple[bool, Optional[str]]:
        """
        Independently verify all digital signatures in this Quorum Certificate:
        1. Network ID check.
        2. Quorum count check (>= required_quorum unique signatures).
        3. All signers belong to eligible active nodes.
        4. Ed25519 signature validity against signers' public keys.
        """
        if expected_network_id and self.network_id != expected_network_id:
            return False, f"NETWORK_ID_MISMATCH: expected {expected_network_id}, got {self.network_id}"

        allowed = set(eligible_nodes or ALL_EXAMINER_NODES)
        clean_sigs = {k.strip().upper(): v for k, v in self.signatures.items()}

        if len(clean_sigs) < required_quorum:
            return False, f"INSUFFICIENT_QUORUM: have {len(clean_sigs)}, require {required_quorum}"

        canon_bytes = self.canonical_bytes()

        for node_id, sig in clean_sigs.items():
            if node_id not in allowed:
                return False, f"UNAUTHORIZED_SIGNER_IN_QC: {node_id}"

            pub_key = get_actor_public_key(node_id)
            if not pub_key:
                return False, f"PUBLIC_KEY_NOT_FOUND: {node_id}"

            if not verify_signature(pub_key, canon_bytes, sig):
                return False, f"INVALID_QC_SIGNATURE_BY_NODE: {node_id}"

        return True, None

    def to_dict(self) -> Dict[str, Any]:
        """Serialize Quorum Certificate to JSON-compatible dictionary."""
        return {
            "stage": self.stage,
            "view": self.view,
            "block_height": self.block_height,
            "proposal_id": self.proposal_id,
            "block_hash": self.block_hash,
            "network_id": self.network_id,
            "signatures": self.signatures,
            "created_at": self.created_at,
            "voters_count": len(self.signatures),
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "QuorumCertificate":
        """Reconstruct QuorumCertificate from dictionary."""
        if not isinstance(data, dict):
            raise ValueError("QC data must be a dictionary")
        return cls(
            stage=data.get("stage", "COMMIT"),
            view=data.get("view", 0),
            block_height=data.get("block_height", 0),
            proposal_id=data.get("proposal_id", ""),
            block_hash=data.get("block_hash", ""),
            network_id=data.get("network_id", "AnswerChain"),
            signatures=data.get("signatures", {}),
            created_at=data.get("created_at"),
        )


class DurableConsensusState:
    """
    Durable persistent state for an examiner node.
    Combines an atomic JSON snapshot with an append-only fsynced Write-Ahead Log (WAL).
    Persists voting decisions and block locks BEFORE votes are transmitted, ensuring
    strict equivocation prevention (no double voting) and locking across node restarts.
    """

    def __init__(self, node_id: str, storage_dir: str) -> None:
        self.node_id = str(node_id).strip().upper()
        self.storage_dir = storage_dir
        os.makedirs(self.storage_dir, exist_ok=True)
        self.state_file = os.path.join(self.storage_dir, f"consensus_state_{self.node_id}.json")
        self.wal_file = os.path.join(self.storage_dir, f"consensus_wal_{self.node_id}.log")

        self.current_view: int = 0
        self.highest_prepared_view: int = -1
        self.highest_prepared_height: int = -1

        # Persistent Locking Rules across views (PBFT lock)
        self.locked_block_hash: Optional[str] = None
        self.locked_view: int = -1
        self.locked_height: int = -1
        self.highest_prepared_qc: Optional[Dict[str, Any]] = None
        self.highest_prepared_block: Optional[Dict[str, Any]] = None

        # Key: "{height}_{view}" -> block_hash
        self.voted_proposals: Dict[str, str] = {}
        # Message ID replay cache
        self.seen_messages: List[str] = []
        # Proposal ID -> Prepare QC dict
        self.prepare_qcs: Dict[str, Dict[str, Any]] = {}
        # Proposal ID -> Commit QC dict
        self.commit_qcs: Dict[str, Dict[str, Any]] = {}
        # Byzantine / Invalid alert log
        self.alerts: List[Dict[str, Any]] = []

        self.load()

    def append_wal(self, entry_type: str, payload: Dict[str, Any]) -> None:
        """Append an entry to the append-only WAL and fsync immediately."""
        entry = {
            "type": entry_type,
            "payload": payload,
            "timestamp": time.time(),
        }
        line = json.dumps(entry, sort_keys=True) + "\n"
        with open(self.wal_file, "a", encoding="utf-8") as f:
            f.write(line)
            f.flush()
            os.fsync(f.fileno())

    def save(self) -> None:
        """Atomically persist consensus snapshot state to disk with fsync."""
        data = {
            "node_id": self.node_id,
            "current_view": self.current_view,
            "highest_prepared_view": self.highest_prepared_view,
            "highest_prepared_height": self.highest_prepared_height,
            "locked_block_hash": self.locked_block_hash,
            "locked_view": self.locked_view,
            "locked_height": self.locked_height,
            "highest_prepared_qc": self.highest_prepared_qc,
            "highest_prepared_block": self.highest_prepared_block,
            "voted_proposals": self.voted_proposals,
            "seen_messages": self.seen_messages[-500:],  # Bound memory
            "prepare_qcs": self.prepare_qcs,
            "commit_qcs": self.commit_qcs,
            "alerts": self.alerts[-100:],
            "updated_at": time.time(),
        }
        tmp_file = f"{self.state_file}.tmp"
        with open(tmp_file, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, sort_keys=True)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp_file, self.state_file)

    def load(self) -> None:
        """Load durable consensus state from disk and replay WAL entries."""
        if os.path.isfile(self.state_file):
            try:
                with open(self.state_file, "r", encoding="utf-8") as f:
                    data = json.load(f)
                self.current_view = int(data.get("current_view", 0))
                self.highest_prepared_view = int(data.get("highest_prepared_view", -1))
                self.highest_prepared_height = int(data.get("highest_prepared_height", -1))
                self.locked_block_hash = data.get("locked_block_hash")
                self.locked_view = int(data.get("locked_view", -1))
                self.locked_height = int(data.get("locked_height", -1))
                self.highest_prepared_qc = data.get("highest_prepared_qc")
                self.highest_prepared_block = data.get("highest_prepared_block")
                self.voted_proposals = dict(data.get("voted_proposals", {}))
                self.seen_messages = list(data.get("seen_messages", []))
                self.prepare_qcs = dict(data.get("prepare_qcs", {}))
                self.commit_qcs = dict(data.get("commit_qcs", {}))
                self.alerts = list(data.get("alerts", []))
            except Exception as e:
                logger.warning("[%s] Failed to load consensus snapshot: %s", self.node_id, e)

        # Replay WAL to capture any writes since the snapshot
        if os.path.isfile(self.wal_file):
            try:
                with open(self.wal_file, "r", encoding="utf-8") as f:
                    for line in f:
                        line = line.strip()
                        if not line:
                            continue
                        entry = json.loads(line)
                        etype = entry.get("type")
                        p = entry.get("payload", {})
                        if etype == "RECORD_VOTE":
                            k = f"{p['height']}_{p['view']}"
                            self.voted_proposals[k] = p["block_hash"]
                        elif etype == "SET_LOCK":
                            self.locked_height = int(p.get("height", -1))
                            self.locked_view = int(p.get("view", -1))
                            self.locked_block_hash = p.get("block_hash")
                            self.highest_prepared_qc = p.get("prepare_qc")
                            self.highest_prepared_block = p.get("block_data")
                        elif etype == "CLEAR_LOCK":
                            self.locked_block_hash = None
                            self.locked_view = -1
                            self.locked_height = -1
                        elif etype == "VIEW_CHANGE":
                            self.current_view = int(p.get("view", self.current_view))
            except Exception as e:
                logger.warning("[%s] Failed replaying WAL log: %s", self.node_id, e)

    def is_message_seen(self, message_id: str) -> bool:
        """Check if message has already been processed to prevent replay."""
        return message_id in self.seen_messages

    def mark_message_seen(self, message_id: str) -> None:
        """Record seen message ID and persist."""
        if message_id not in self.seen_messages:
            self.seen_messages.append(message_id)
            if len(self.seen_messages) > 1000:
                self.seen_messages = self.seen_messages[-500:]
            self.save()

    def has_conflicting_vote(self, height: int, view: int, block_hash: str) -> bool:
        """
        Equivocation check: returns True if node has already cast a vote
        for a DIFFERENT block hash at the same (height, view).
        """
        key = f"{height}_{view}"
        prev_hash = self.voted_proposals.get(key)
        if prev_hash is not None and prev_hash != block_hash:
            return True
        return False

    def record_vote(self, height: int, view: int, block_hash: str) -> None:
        """Persist vote decision to append-only WAL and snapshot before transmitting."""
        key = f"{height}_{view}"
        self.voted_proposals[key] = block_hash
        self.append_wal("RECORD_VOTE", {"height": height, "view": view, "block_hash": block_hash})
        self.save()

    def set_lock(
        self,
        height: int,
        view: int,
        block_hash: str,
        prepare_qc: Optional[Dict[str, Any]] = None,
        block_data: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Acquire persistent lock on a prepared block across view changes."""
        self.locked_height = int(height)
        self.locked_view = int(view)
        self.locked_block_hash = str(block_hash)
        self.highest_prepared_qc = prepare_qc
        self.highest_prepared_block = block_data
        self.highest_prepared_view = max(self.highest_prepared_view, int(view))
        self.highest_prepared_height = max(self.highest_prepared_height, int(height))
        self.append_wal("SET_LOCK", {
            "height": height,
            "view": view,
            "block_hash": block_hash,
            "prepare_qc": prepare_qc,
            "block_data": block_data,
        })
        self.save()

    def clear_lock(self) -> None:
        """Release lock when block is committed to the blockchain."""
        self.locked_block_hash = None
        self.locked_view = -1
        self.locked_height = -1
        self.append_wal("CLEAR_LOCK", {})
        self.save()

    def record_alert(self, alert_type: str, details: Dict[str, Any]) -> None:
        """Record a Byzantine anomaly or invalid proposal alert."""
        self.alerts.append({
            "type": alert_type,
            "details": details,
            "timestamp": time.time(),
        })
        self.save()


class ConsensusState:
    """Tracks in-memory multi-stage voting progress for a specific block proposal."""

    def __init__(
        self,
        proposal_id: str,
        proposer_id: str,
        subject: str,
        block_data: Dict[str, Any],
        view: int = 0,
        block_height: int = 1,
        quorum_required: int = 3,
        network_id: str = "AnswerChain",
    ) -> None:
        self.proposal_id = proposal_id
        self.proposer_id = proposer_id
        self.subject = subject.strip().upper()
        self.block_data = block_data
        self.view = int(view)
        self.block_height = int(block_height)
        self.quorum_required = quorum_required
        self.network_id = network_id
        self.created_at = time.time()
        self.block_hash = block_data.get("hash", "")

        # Stage tracking
        self.stage = ConsensusStage.PRE_PREPARE

        # Prepare stage votes: voter_node -> signature
        self.prepare_votes: Dict[str, str] = {}
        self.prepare_qc: Optional[QuorumCertificate] = None

        # Commit stage votes: voter_node -> signature
        self.commit_votes: Dict[str, str] = {}
        self.commit_qc: Optional[QuorumCertificate] = None

        # Legacy backward-compatible votes dictionary
        self.votes: Dict[str, Dict[str, Any]] = {}
        self.is_committed = False
        self.committed_at: Optional[float] = None
        self._locally_appended = False

    def record_vote(
        self,
        voter_id: str,
        is_valid: bool,
        signature: Optional[str] = None,
        reason: Optional[str] = None,
    ) -> Tuple[bool, int]:
        """Legacy 1-round compatibility method."""
        clean_voter = voter_id.strip().upper()
        self.votes[clean_voter] = {
            "valid": bool(is_valid),
            "reason": reason or ("VALID" if is_valid else "INVALID"),
            "signature": signature,
            "timestamp": time.time(),
        }

        affirmative_votes = sum(1 for v in self.votes.values() if v["valid"])
        quorum_reached = affirmative_votes >= self.quorum_required

        if quorum_reached and not self.is_committed:
            self.is_committed = True
            self.committed_at = time.time()

        return quorum_reached, affirmative_votes

    def record_prepare_vote(self, voter_id: str, signature: str) -> Tuple[bool, int]:
        """Record an authenticated PREPARE vote."""
        clean_voter = voter_id.strip().upper()
        self.prepare_votes[clean_voter] = signature

        affirmative = len(self.prepare_votes)
        quorum_reached = affirmative >= self.quorum_required

        if quorum_reached and not self.prepare_qc:
            self.prepare_qc = QuorumCertificate(
                stage="PREPARE",
                view=self.view,
                block_height=self.block_height,
                proposal_id=self.proposal_id,
                block_hash=self.block_hash,
                signatures=dict(self.prepare_votes),
                network_id=self.network_id,
            )
            self.stage = ConsensusStage.PREPARED

        return quorum_reached, affirmative

    def record_commit_vote(self, voter_id: str, signature: str) -> Tuple[bool, int]:
        """Record an authenticated COMMIT vote."""
        clean_voter = voter_id.strip().upper()
        self.commit_votes[clean_voter] = signature

        affirmative = len(self.commit_votes)
        quorum_reached = affirmative >= self.quorum_required

        if quorum_reached and not self.commit_qc:
            self.commit_qc = QuorumCertificate(
                stage="COMMIT",
                view=self.view,
                block_height=self.block_height,
                proposal_id=self.proposal_id,
                block_hash=self.block_hash,
                signatures=dict(self.commit_votes),
                network_id=self.network_id,
            )
            self.stage = ConsensusStage.COMMITTED
            self.is_committed = True
            self.committed_at = time.time()

        return quorum_reached, affirmative


class ExaminerConsensusEngine:
    """
    Multi-stage permissioned consensus engine for examiner nodes.
    Supports Byzantine Fault Tolerance (BFT) and Crash Fault Tolerance (CFT) modes.
    """

    def __init__(
        self,
        node_id: str,
        teacher_id: str,
        blockchain: ExaminerBlockchain,
        quorum_threshold: Optional[int] = None,
        consensus_mode: str = ConsensusMode.BFT,
        storage_dir: Optional[str] = None,
        network_id: str = "AnswerChain",
    ) -> None:
        self.node_id = str(node_id).strip().upper()
        self.teacher_id = str(teacher_id).strip().upper()
        self.blockchain = blockchain
        self.consensus_mode = consensus_mode.strip().upper()
        self.network_id = network_id

        # Validate fault model mathematically
        f_max, default_q = validate_fault_model(self.consensus_mode, len(ALL_EXAMINER_NODES))
        if quorum_threshold is not None:
            self.quorum_threshold = int(quorum_threshold)
            if self.consensus_mode == ConsensusMode.BFT and self.quorum_threshold < default_q:
                logger.warning(
                    "[%s] Quorum threshold %d is below required BFT quorum (%d/%d). "
                    "Cannot guarantee Byzantine safety against f=%d malicious nodes.",
                    self.node_id,
                    self.quorum_threshold,
                    default_q,
                    len(ALL_EXAMINER_NODES),
                    f_max,
                )
        else:
            self.quorum_threshold = default_q

        logger.info(
            "[%s] Initialized consensus engine: mode=%s, quorum=%d/%d, max_faults(f)=%d",
            self.node_id,
            self.consensus_mode,
            self.quorum_threshold,
            len(ALL_EXAMINER_NODES),
            f_max if self.quorum_threshold >= default_q else 0,
        )

        # Durable persistent consensus state
        effective_dir = (
            storage_dir
            if storage_dir is not None
            else os.path.dirname(self.blockchain.chain_file)
        )
        self.durable_state = DurableConsensusState(self.node_id, effective_dir)
        self.current_view: int = self.durable_state.current_view

        self.active_proposals: Dict[str, ConsensusState] = {}
        # View change tracking: view -> {voter -> signature}
        self.view_change_votes: Dict[int, Dict[str, str]] = {}
        self.view_change_payloads: Dict[int, Dict[str, Dict[str, Any]]] = {}
        self.stage = ConsensusStage.IDLE

    # ----------------------------------------------------
    # LEADER & VIEW SELECTION
    # ----------------------------------------------------
    def get_leader_for_view(self, view: int, subject: Optional[str] = None) -> str:
        """
        Determine deterministic consensus leader for a given view:
        Round-robin across all 5 nodes based on view number.
        """
        idx = (int(view) % len(ALL_EXAMINER_NODES))
        return ALL_EXAMINER_NODES[idx]

    # ----------------------------------------------------
    # HEAD EXAMINER EVALUATION APPROVAL
    # ----------------------------------------------------
    def approve_evaluation(
        self,
        evaluation_data: Dict[str, Any],
        head_examiner_id: str,
        subject: str,
        remarks: str = "Approved by Head Examiner",
        allow_self_approval: bool = False,
    ) -> Tuple[bool, Optional[Dict[str, Any]], Optional[str]]:
        """
        Head Examiner verifies and digitally signs an evaluation record.
        Strictly enforces anti-self-approval rule unless university override is explicit.
        """
        marks = evaluation_data.get("marks")
        max_marks = evaluation_data.get("max_marks", 100.0)
        answer_script_id = evaluation_data.get("answer_script_id")
        examiner_id = evaluation_data.get("teacher_id")

        if marks is None or not answer_script_id or not examiner_id:
            return False, None, "INVALID_EVALUATION_PAYLOAD"

        if float(marks) < 0 or float(marks) > float(max_marks):
            return False, None, "MARKS_OUT_OF_BOUNDS"

        # Anti-Self-Approval Enforcement
        clean_examiner = str(examiner_id).strip().upper()
        clean_head = str(head_examiner_id).strip().upper()
        if clean_examiner == clean_head and not allow_self_approval:
            return False, None, "SELF_APPROVAL_PROHIBITED: Head Examiner cannot approve their own evaluation"

        # Verify original examiner signature if present
        if evaluation_data.get("signature"):
            valid, err = verify_academic_transaction(evaluation_data)
            if not valid:
                return False, None, f"EXAMINER_SIGNATURE_INVALID: {err}"

        # Construct signed approval transaction
        approval_payload = {
            "type": "EVALUATION_APPROVED",
            "answer_script_id": answer_script_id,
            "teacher_id": examiner_id,
            "head_examiner_id": clean_head,
            "subject": subject.strip().upper(),
            "marks": float(marks),
            "max_marks": float(max_marks),
            "remarks": remarks,
            "approved_at": time.time(),
            "status": "APPROVED",
        }

        signed_approval = sign_academic_transaction(
            payload=approval_payload,
            actor_id=clean_head,
            actor_role="HEAD_EXAMINER",
        )

        return True, signed_approval, None

    # ----------------------------------------------------
    # MULTI-STAGE CONSENSUS: PRE-PREPARE
    # ----------------------------------------------------
    def create_pre_prepare(
        self,
        transactions: List[Dict[str, Any]],
        subject: str,
        view: Optional[int] = None,
    ) -> Tuple[bool, Optional[IPCMessage], Optional[str]]:
        """
        Leader constructs and broadcasts a PRE_PREPARE message.
        Preserves highest prepared proposal across view changes (locking rule).
        """
        latest_block = self.blockchain.get_latest_block()
        next_index = int(latest_block["index"]) + 1
        previous_hash = latest_block["hash"]
        timestamp = time.time()

        if view is not None:
            curr_view = int(view)
        else:
            curr_view = self.current_view
            # Auto-advance view if current view was already used at this height for a different proposal
            while self.durable_state.has_conflicting_vote(next_index, curr_view, "placeholder"):
                curr_view += 1
            self.current_view = curr_view
            self.durable_state.current_view = curr_view

        proposal_id = f"PROP-{self.node_id}-v{curr_view}-h{next_index}-{uuid.uuid4().hex[:6]}"

        # View-change preservation: if a prepared block was locked at this height, leader must repropose it
        if self.durable_state.locked_block_hash and self.durable_state.locked_height == next_index:
            if self.durable_state.highest_prepared_block:
                proposed_block = copy.deepcopy(self.durable_state.highest_prepared_block)
                proposed_block["view"] = curr_view
                proposed_block["proposal_id"] = proposal_id
                block_hash = self.durable_state.locked_block_hash
                transactions = proposed_block.get("data", transactions)
            else:
                proposed_block = {
                    "index": next_index,
                    "timestamp": timestamp,
                    "data": transactions,
                    "previous_hash": previous_hash,
                    "proposer_node": self.node_id,
                    "proposer_teacher": self.teacher_id,
                    "subject": subject.strip().upper(),
                    "proposal_id": proposal_id,
                    "view": curr_view,
                }
                block_hash = self.blockchain.calculate_hash(
                    proposed_block["index"],
                    proposed_block["timestamp"],
                    proposed_block["data"],
                    proposed_block["previous_hash"],
                )
                proposed_block["hash"] = block_hash
        else:
            proposed_block = {
                "index": next_index,
                "timestamp": timestamp,
                "data": transactions,
                "previous_hash": previous_hash,
                "proposer_node": self.node_id,
                "proposer_teacher": self.teacher_id,
                "subject": subject.strip().upper(),
                "proposal_id": proposal_id,
                "view": curr_view,
            }
            block_hash = self.blockchain.calculate_hash(
                proposed_block["index"],
                proposed_block["timestamp"],
                proposed_block["data"],
                proposed_block["previous_hash"],
            )
            proposed_block["hash"] = block_hash

        # Leader signature over proposal
        priv, _ = get_or_create_actor_keys(self.node_id)
        canon_bytes = json.dumps(
            {"block_hash": block_hash, "height": next_index, "proposal_id": proposal_id, "view": curr_view},
            sort_keys=True,
        ).encode("utf-8")
        sig = sign_payload(priv, canon_bytes)
        proposed_block["signature"] = sig

        # Equivocation protection check on self
        if self.durable_state.has_conflicting_vote(next_index, curr_view, block_hash):
            return False, None, "EQUIVOCATION_REJECTED: Already voted for conflicting proposal at this height and view"

        # Record vote in durable state
        self.durable_state.record_vote(next_index, curr_view, block_hash)

        # Register proposal state locally
        state = ConsensusState(
            proposal_id=proposal_id,
            proposer_id=self.node_id,
            subject=subject,
            block_data=proposed_block,
            view=curr_view,
            block_height=next_index,
            quorum_required=self.quorum_threshold,
            network_id=self.network_id,
        )
        self.active_proposals[proposal_id] = state

        # Leader prepares itself
        prep_qc_item = QuorumCertificate(
            stage="PREPARE",
            view=curr_view,
            block_height=next_index,
            proposal_id=proposal_id,
            block_hash=block_hash,
            network_id=self.network_id,
        )
        leader_prep_sig = sign_payload(priv, prep_qc_item.canonical_bytes())
        state.record_prepare_vote(self.node_id, leader_prep_sig)

        # Proposer automatically casts affirmative vote for legacy compatibility
        state.record_vote(
            voter_id=self.node_id,
            is_valid=True,
            signature=sig,
            reason="PROPOSER_VALID",
        )

        msg = IPCMessage(
            message_type=MessageType.PRE_PREPARE,
            sender=self.node_id,
            receiver="*",
            payload={
                "network_id": self.network_id,
                "proposal_id": proposal_id,
                "view": curr_view,
                "block_height": next_index,
                "block_hash": block_hash,
                "block": proposed_block,
                "subject": subject.strip().upper(),
                "leader_signature": sig,
            },
            signature=sig,
        )
        return True, msg, None

    def create_block_proposal(
        self,
        transactions: List[Dict[str, Any]],
        subject: str,
    ) -> IPCMessage:
        """Legacy compatibility wrapper for BLOCK_PROPOSAL."""
        ok, msg, _ = self.create_pre_prepare(transactions, subject)
        if ok and msg:
            msg.message_type = MessageType.BLOCK_PROPOSAL
            return msg

        return IPCMessage(
            message_type=MessageType.BLOCK_PROPOSAL,
            sender=self.node_id,
            receiver="*",
            payload={"proposal_id": "error", "block": {}},
        )

    # ----------------------------------------------------
    # VALIDATION LOGIC
    # ----------------------------------------------------
    def validate_proposal(
        self,
        proposal_payload: Dict[str, Any],
        is_proposer_authorized: bool = True,
    ) -> Tuple[bool, str]:
        """
        Independently validate a block proposal:
        1. Proposer authorization.
        2. Index continuity (index == latest + 1).
        3. previous_hash continuity.
        4. Recalculated block hash match.
        5. Transaction signatures and Head Examiner authorization.
        6. Duplicate transaction prevention.
        """
        block = proposal_payload.get("block", {})
        if not block:
            return False, "EMPTY_BLOCK_IN_PROPOSAL"

        if not is_proposer_authorized:
            return False, "UNAUTHORIZED_PROPOSER"

        latest = self.blockchain.get_latest_block()
        expected_index = int(latest["index"]) + 1
        if block.get("index") != expected_index:
            return False, f"INDEX_MISMATCH: expected {expected_index}, got {block.get('index')}"

        if block.get("previous_hash") != latest["hash"]:
            return False, f"PREVIOUS_HASH_MISMATCH: expected {latest['hash']}, got {block.get('previous_hash')}"

        calc_hash = self.blockchain.calculate_hash(
            block["index"],
            block["timestamp"],
            block["data"],
            block["previous_hash"],
        )
        if calc_hash != block.get("hash"):
            return False, f"BLOCK_HASH_INVALID: calculated {calc_hash}, got {block.get('hash')}"

        txs = block.get("data", [])
        if not isinstance(txs, list) or not txs:
            return False, "BLOCK_DATA_MUST_BE_NONEMPTY_LIST"

        for tx in txs:
            if not isinstance(tx, dict):
                return False, "MALFORMED_TRANSACTION"
            tx_data = tx.get("data", {})
            if isinstance(tx_data, dict) and tx_data.get("signature"):
                is_valid, err = verify_academic_transaction(tx_data)
                if not is_valid:
                    return False, f"TRANSACTION_VERIFICATION_FAILED: {err}"

            # Check duplicates on committed local chain
            tx_type = tx_data.get("type")
            if tx_type == "EVALUATION_APPROVED":
                as_id = tx_data.get("answer_script_id")
                if self.blockchain.find_transaction("EVALUATION_APPROVED", "answer_script_id", as_id):
                    return False, f"DUPLICATE_APPROVAL_REJECTED: {as_id}"

        return True, "PROPOSAL_VALID"

    # ----------------------------------------------------
    # MULTI-STAGE CONSENSUS: HANDLE PRE-PREPARE -> PREPARE
    # ----------------------------------------------------
    def handle_pre_prepare(
        self,
        message: IPCMessage,
        is_leader_authorized: bool = True,
    ) -> Tuple[bool, Optional[IPCMessage], str]:
        """
        Process PRE_PREPARE message:
        1. Check message replay.
        2. Validate sender is authorized leader.
        3. Validate proposed block invariants.
        4. Persistent locking rule: reject conflicting proposals across views unless higher proof exists.
        5. Check equivocation: reject if already voted for another hash at this (height, view).
        6. If valid, cast and persist PREPARE vote, returning PREPARE IPCMessage.
        """
        if self.durable_state.is_message_seen(message.message_id):
            return False, None, "REPLAYED_MESSAGE_REJECTED"
        self.durable_state.mark_message_seen(message.message_id)

        payload = message.payload
        proposal_id = payload.get("proposal_id", "")
        view = int(payload.get("view", 0))
        block_height = int(payload.get("block_height", 0))
        block_hash = payload.get("block_hash", "")
        block = payload.get("block", {})
        subject = payload.get("subject", "")

        if not is_leader_authorized:
            self.durable_state.record_alert("UNAUTHORIZED_LEADER_PROPOSAL", {"sender": message.sender, "view": view})
            return False, None, "UNAUTHORIZED_LEADER_PROPOSAL"

        is_valid, reason = self.validate_proposal(payload, is_proposer_authorized=is_leader_authorized)
        if not is_valid:
            return False, None, reason

        # Persistent Locking Rule: honest nodes cannot approve conflicting blocks across views
        locked_hash = self.durable_state.locked_block_hash
        locked_view = self.durable_state.locked_view
        locked_height = self.durable_state.locked_height

        if locked_hash and locked_height == block_height:
            if block_hash != locked_hash:
                # Check for unlocking proof: a valid prepare QC from view > locked_view
                proof_qc_data = payload.get("proof_prepared_qc") or (payload.get("new_view_cert") or {}).get("highest_prepared_qc")
                is_unlocked = False
                if proof_qc_data:
                    try:
                        proof_qc = QuorumCertificate.from_dict(proof_qc_data)
                        if proof_qc.view > locked_view and proof_qc.block_hash == block_hash:
                            valid_p, _ = proof_qc.verify(
                                required_quorum=self.quorum_threshold,
                                expected_network_id=self.network_id,
                            )
                            if valid_p:
                                is_unlocked = True
                    except Exception:
                        pass

                if not is_unlocked:
                    self.durable_state.record_alert("LOCKED_BLOCK_CONFLICT", {
                        "height": block_height,
                        "view": view,
                        "locked_hash": locked_hash,
                        "attempted_hash": block_hash,
                        "locked_view": locked_view,
                    })
                    return False, None, f"LOCKED_BLOCK_CONFLICT: Node is locked on block {locked_hash[:16]} from view {locked_view}"

        # Equivocation prevention
        if self.durable_state.has_conflicting_vote(block_height, view, block_hash):
            self.durable_state.record_alert("EQUIVOCATION_DETECTED", {
                "height": block_height,
                "view": view,
                "attempted_hash": block_hash,
                "sender": message.sender,
            })
            return False, None, "EQUIVOCATION_REJECTED: Conflicting proposal at same height and view"

        # Record vote in durable state
        self.durable_state.record_vote(block_height, view, block_hash)

        # Initialize consensus tracking
        state = ConsensusState(
            proposal_id=proposal_id,
            proposer_id=message.sender,
            subject=subject,
            block_data=block,
            view=view,
            block_height=block_height,
            quorum_required=self.quorum_threshold,
            network_id=self.network_id,
        )
        self.active_proposals[proposal_id] = state

        # Sign PREPARE payload
        priv, _ = get_or_create_actor_keys(self.node_id)
        qc_template = QuorumCertificate(
            stage="PREPARE",
            view=view,
            block_height=block_height,
            proposal_id=proposal_id,
            block_hash=block_hash,
            network_id=self.network_id,
        )
        prep_sig = sign_payload(priv, qc_template.canonical_bytes())
        state.record_prepare_vote(self.node_id, prep_sig)

        prep_msg = IPCMessage(
            message_type=MessageType.PREPARE,
            sender=self.node_id,
            receiver="*",
            payload={
                "network_id": self.network_id,
                "proposal_id": proposal_id,
                "view": view,
                "block_height": block_height,
                "block_hash": block_hash,
                "is_valid": True,
                "signature": prep_sig,
            },
            signature=prep_sig,
        )
        return True, prep_msg, "PREPARE_CAST"

    # ----------------------------------------------------
    # MULTI-STAGE CONSENSUS: HANDLE PREPARE -> COMMIT
    # ----------------------------------------------------
    def handle_prepare(
        self,
        message: IPCMessage,
    ) -> Tuple[bool, Optional[IPCMessage], str]:
        """
        Process PREPARE message:
        1. Verify voter signature over canonical prepare payload.
        2. Tally vote towards Prepare Quorum Certificate.
        3. If quorum reached: construct Prepare QC, acquire persistent lock, and broadcast COMMIT.
        """
        payload = message.payload
        proposal_id = payload.get("proposal_id", "")
        view = int(payload.get("view", 0))
        block_height = int(payload.get("block_height", 0))
        block_hash = payload.get("block_hash", "")
        sig = payload.get("signature")

        voter = message.sender.strip().upper()
        if voter not in ALL_EXAMINER_NODES:
            return False, None, "UNAUTHORIZED_VOTER"

        state = self.active_proposals.get(proposal_id)
        if not state:
            return False, None, "UNKNOWN_PROPOSAL"

        # Verify voter's digital signature
        pub_key = get_actor_public_key(voter)
        if not pub_key:
            return False, None, f"PUBLIC_KEY_NOT_FOUND: {voter}"

        qc_template = QuorumCertificate(
            stage="PREPARE",
            view=view,
            block_height=block_height,
            proposal_id=proposal_id,
            block_hash=block_hash,
            network_id=self.network_id,
        )
        if not verify_signature(pub_key, qc_template.canonical_bytes(), sig):
            self.durable_state.record_alert("INVALID_VOTE_SIGNATURE", {"voter": voter, "proposal_id": proposal_id})
            return False, None, "INVALID_VOTE_SIGNATURE"

        # Record vote
        quorum_reached, total = state.record_prepare_vote(voter, sig)

        if quorum_reached and not getattr(state, "_commit_broadcast", False):
            state._commit_broadcast = True
            # Persist Prepare QC in durable state and acquire persistent lock
            self.durable_state.prepare_qcs[proposal_id] = state.prepare_qc.to_dict()
            self.durable_state.set_lock(
                height=block_height,
                view=view,
                block_hash=block_hash,
                prepare_qc=state.prepare_qc.to_dict(),
                block_data=state.block_data,
            )

            # Sign COMMIT payload
            priv, _ = get_or_create_actor_keys(self.node_id)
            commit_qc_template = QuorumCertificate(
                stage="COMMIT",
                view=view,
                block_height=block_height,
                proposal_id=proposal_id,
                block_hash=block_hash,
                network_id=self.network_id,
            )
            commit_sig = sign_payload(priv, commit_qc_template.canonical_bytes())
            state.record_commit_vote(self.node_id, commit_sig)

            commit_msg = IPCMessage(
                message_type=MessageType.COMMIT,
                sender=self.node_id,
                receiver="*",
                payload={
                    "network_id": self.network_id,
                    "proposal_id": proposal_id,
                    "view": view,
                    "block_height": block_height,
                    "block_hash": block_hash,
                    "prepare_qc": state.prepare_qc.to_dict(),
                    "signature": commit_sig,
                },
                signature=commit_sig,
            )
            return True, commit_msg, "PREPARE_QUORUM_REACHED"

        return False, None, f"PREPARE_VOTES: {total}/{self.quorum_threshold}"

    # ----------------------------------------------------
    # MULTI-STAGE CONSENSUS: HANDLE COMMIT -> LOCAL APPEND
    # ----------------------------------------------------
    def handle_commit(
        self,
        message: IPCMessage,
    ) -> Tuple[bool, Optional[Dict[str, Any]], Optional[IPCMessage], str]:
        """
        Process COMMIT message:
        1. Verify voter signature over canonical commit payload.
        2. Tally vote towards Commit Quorum Certificate.
        3. If quorum reached: construct Commit QC, independently append block to local DB,
           release persistent lock, and broadcast BLOCK_COMMITTED.
        """
        payload = message.payload
        proposal_id = payload.get("proposal_id", "")
        view = int(payload.get("view", 0))
        block_height = int(payload.get("block_height", 0))
        block_hash = payload.get("block_hash", "")
        sig = payload.get("signature")

        voter = message.sender.strip().upper()
        if voter not in ALL_EXAMINER_NODES:
            return False, None, None, "UNAUTHORIZED_VOTER"

        state = self.active_proposals.get(proposal_id)
        if not state:
            return False, None, None, "UNKNOWN_PROPOSAL"

        pub_key = get_actor_public_key(voter)
        if not pub_key:
            return False, None, None, f"PUBLIC_KEY_NOT_FOUND: {voter}"

        qc_template = QuorumCertificate(
            stage="COMMIT",
            view=view,
            block_height=block_height,
            proposal_id=proposal_id,
            block_hash=block_hash,
            network_id=self.network_id,
        )
        if not verify_signature(pub_key, qc_template.canonical_bytes(), sig):
            self.durable_state.record_alert("INVALID_COMMIT_SIGNATURE", {"voter": voter, "proposal_id": proposal_id})
            return False, None, None, "INVALID_COMMIT_SIGNATURE"

        quorum_reached, total = state.record_commit_vote(voter, sig)

        if quorum_reached and not getattr(state, "_locally_appended", False):
            state._locally_appended = True

            # Verify complete Commit QC
            commit_qc = state.commit_qc
            valid_qc, qc_err = commit_qc.verify(
                eligible_nodes=ALL_EXAMINER_NODES,
                required_quorum=self.quorum_threshold,
                expected_network_id=self.network_id,
            )
            if not valid_qc:
                return False, None, None, f"INVALID_COMMIT_QC: {qc_err}"

            # Persist Commit QC in durable state
            self.durable_state.commit_qcs[proposal_id] = commit_qc.to_dict()
            self.durable_state.highest_prepared_height = block_height
            self.durable_state.highest_prepared_view = view
            self.durable_state.save()

            # Append block independently to local blockchain
            block_data = state.block_data
            committed_block = self.blockchain.add_block(
                transactions=block_data.get("data", []),
                previous_hash=block_data.get("previous_hash"),
                block_timestamp=block_data.get("timestamp"),
                quorum_certificate=commit_qc.to_dict(),
            )

            # Release persistent lock now that the block is finalized on disk
            self.durable_state.clear_lock()

            comm_msg = IPCMessage(
                message_type=MessageType.BLOCK_COMMITTED,
                sender=self.node_id,
                receiver="*",
                payload={
                    "proposal_id": proposal_id,
                    "block_index": committed_block["index"],
                    "block_hash": committed_block["hash"],
                    "view": view,
                    "committed_by": self.node_id,
                    "commit_qc": commit_qc.to_dict(),
                },
            )
            return True, committed_block, comm_msg, "BLOCK_COMMITTED"

        return False, None, None, f"COMMIT_VOTES: {total}/{self.quorum_threshold}"

    # ----------------------------------------------------
    # VIEW CHANGE PROTOCOL
    # ----------------------------------------------------
    def trigger_view_change(self, target_view: Optional[int] = None) -> IPCMessage:
        """
        Initiate a View Change when leader fails or progress stalls.
        Includes highest prepared QC and block data to preserve safety across views.
        """
        new_view = (self.current_view + 1) if target_view is None else int(target_view)
        self.current_view = new_view
        self.durable_state.current_view = new_view
        self.durable_state.save()
        self.stage = ConsensusStage.VIEW_CHANGE

        # Find highest prepared QC if any to preserve
        highest_prepared_qc = self.durable_state.highest_prepared_qc
        highest_prepared_block = self.durable_state.highest_prepared_block

        priv, _ = get_or_create_actor_keys(self.node_id)
        canon = json.dumps(
            {
                "latest_hash": self.blockchain.get_latest_block().get("hash"),
                "network_id": self.network_id,
                "new_view": new_view,
                "node_id": self.node_id,
            },
            sort_keys=True,
        ).encode("utf-8")
        sig = sign_payload(priv, canon)

        vc_msg = IPCMessage(
            message_type=MessageType.VIEW_CHANGE,
            sender=self.node_id,
            receiver="*",
            payload={
                "network_id": self.network_id,
                "new_view": new_view,
                "sender_node": self.node_id,
                "highest_prepared_qc": highest_prepared_qc,
                "highest_prepared_block": highest_prepared_block,
                "locked_block_hash": self.durable_state.locked_block_hash,
                "latest_hash": self.blockchain.get_latest_block().get("hash"),
                "signature": sig,
            },
            signature=sig,
        )
        return vc_msg

    def handle_view_change(self, message: IPCMessage) -> Tuple[bool, Optional[IPCMessage], str]:
        """
        Process incoming VIEW_CHANGE message.
        If this node is the leader for the new view and collects Q view changes,
        it preserves the highest prepared proposal, transitions to new view and emits NEW_VIEW.
        """
        payload = message.payload
        new_view = int(payload.get("new_view", 0))
        sender = message.sender.strip().upper()
        sig = payload.get("signature")

        if sender not in ALL_EXAMINER_NODES:
            return False, None, "UNAUTHORIZED_SENDER"

        # Verify signature
        pub_key = get_actor_public_key(sender)
        canon = json.dumps(
            {
                "latest_hash": payload.get("latest_hash"),
                "network_id": payload.get("network_id", self.network_id),
                "new_view": new_view,
                "node_id": sender,
            },
            sort_keys=True,
        ).encode("utf-8")
        if not verify_signature(pub_key, canon, sig):
            return False, None, "INVALID_VIEW_CHANGE_SIGNATURE"

        if new_view not in self.view_change_votes:
            self.view_change_votes[new_view] = {}
            self.view_change_payloads[new_view] = {}
        self.view_change_votes[new_view][sender] = sig
        self.view_change_payloads[new_view][sender] = payload

        # Check if this node is the designated leader for new_view
        expected_leader = self.get_leader_for_view(new_view)
        if expected_leader == self.node_id:
            votes_count = len(self.view_change_votes[new_view])
            if votes_count >= self.quorum_threshold and not getattr(self, f"_new_view_{new_view}_broadcast", False):
                setattr(self, f"_new_view_{new_view}_broadcast", True)
                self.current_view = new_view
                self.durable_state.current_view = new_view

                # Preserve highest prepared proposal across all view-change messages
                all_prepared_qcs = []
                for s, vc_payload in self.view_change_payloads.get(new_view, {}).items():
                    p_qc = vc_payload.get("highest_prepared_qc")
                    if p_qc:
                        all_prepared_qcs.append((
                            int(p_qc.get("view", -1)),
                            p_qc,
                            vc_payload.get("highest_prepared_block"),
                        ))

                preserved_qc = None
                preserved_block = None
                if all_prepared_qcs:
                    all_prepared_qcs.sort(key=lambda x: x[0], reverse=True)
                    _, preserved_qc, preserved_block = all_prepared_qcs[0]
                    self.durable_state.highest_prepared_qc = preserved_qc
                    self.durable_state.highest_prepared_block = preserved_block
                    self.durable_state.locked_block_hash = preserved_qc.get("block_hash")
                    self.durable_state.locked_view = preserved_qc.get("view", new_view)
                    self.durable_state.locked_height = preserved_qc.get("block_height", -1)

                self.durable_state.save()
                self.stage = ConsensusStage.IDLE

                priv, _ = get_or_create_actor_keys(self.node_id)
                nv_canon = json.dumps({
                    "leader": self.node_id,
                    "network_id": self.network_id,
                    "new_view": new_view,
                }, sort_keys=True).encode("utf-8")
                nv_sig = sign_payload(priv, nv_canon)

                nv_msg = IPCMessage(
                    message_type=MessageType.NEW_VIEW,
                    sender=self.node_id,
                    receiver="*",
                    payload={
                        "network_id": self.network_id,
                        "new_view": new_view,
                        "leader": self.node_id,
                        "view_change_signatures": dict(self.view_change_votes[new_view]),
                        "preserved_prepared_qc": preserved_qc,
                        "signature": nv_sig,
                    },
                    signature=nv_sig,
                )
                return True, nv_msg, f"NEW_VIEW_ESTABLISHED: view {new_view}"

        return False, None, f"VIEW_CHANGE_VOTES: {len(self.view_change_votes.get(new_view, {}))}/{self.quorum_threshold}"

    # ----------------------------------------------------
    # LEGACY WRAPPERS FOR BACKWARD COMPATIBILITY
    # ----------------------------------------------------
    def handle_proposal_message(
        self,
        message: IPCMessage,
        is_proposer_authorized: bool = True,
    ) -> Optional[IPCMessage]:
        """Legacy compatibility wrapper for BLOCK_PROPOSAL -> CONSENSUS_VOTE."""
        payload = message.payload
        proposal_id = payload.get("proposal_id", "")
        block = payload.get("block", {})
        subject = payload.get("subject", "")

        is_valid, reason = self.validate_proposal(payload, is_proposer_authorized=is_proposer_authorized)

        # Equivocation check
        height = int(block.get("index", 1))
        view = int(block.get("view", 0))
        b_hash = block.get("hash", "")

        if is_valid and self.durable_state.has_conflicting_vote(height, view, b_hash):
            is_valid = False
            reason = "EQUIVOCATION_REJECTED: Conflicting proposal at same height"

        if is_valid:
            self.durable_state.record_vote(height, view, b_hash)

        # Initialize consensus tracking
        state = ConsensusState(
            proposal_id=proposal_id,
            proposer_id=message.sender,
            subject=subject,
            block_data=block,
            view=view,
            block_height=height,
            quorum_required=self.quorum_threshold,
            network_id=self.network_id,
        )
        self.active_proposals[proposal_id] = state

        # Cast our vote
        priv, _ = get_or_create_actor_keys(self.node_id)
        canon = json.dumps({"proposal_id": proposal_id, "valid": is_valid}, sort_keys=True).encode("utf-8")
        sig = sign_payload(priv, canon)

        state.record_vote(
            voter_id=self.node_id,
            is_valid=is_valid,
            signature=sig,
            reason=reason,
        )

        return IPCMessage(
            message_type=MessageType.CONSENSUS_VOTE,
            sender=self.node_id,
            receiver="*",
            payload={
                "proposal_id": proposal_id,
                "is_valid": is_valid,
                "reason": reason,
                "signature": sig,
            },
        )

    def handle_vote_message(
        self,
        message: IPCMessage,
    ) -> Tuple[bool, Optional[Dict[str, Any]], Optional[IPCMessage]]:
        """Legacy compatibility wrapper for CONSENSUS_VOTE."""
        payload = message.payload
        proposal_id = payload.get("proposal_id", "")
        is_valid = bool(payload.get("is_valid", False))
        sig = payload.get("signature")
        reason = payload.get("reason")

        state = self.active_proposals.get(proposal_id)
        if not state:
            return False, None, None

        quorum_reached, affirmative = state.record_vote(
            voter_id=message.sender,
            is_valid=is_valid,
            signature=sig,
            reason=reason,
        )

        if quorum_reached and not getattr(state, "_locally_appended", False):
            state._locally_appended = True

            # Construct Commit QC from valid votes
            sigs = {
                v: data["signature"]
                for v, data in state.votes.items()
                if data.get("valid") and data.get("signature")
            }
            qc = QuorumCertificate(
                stage="COMMIT",
                view=state.view,
                block_height=state.block_height,
                proposal_id=proposal_id,
                block_hash=state.block_hash,
                signatures=sigs,
                network_id=self.network_id,
            )

            block_data = state.block_data
            committed_block = self.blockchain.add_block(
                transactions=block_data.get("data", []),
                previous_hash=block_data.get("previous_hash"),
                block_timestamp=block_data.get("timestamp"),
                quorum_certificate=qc.to_dict(),
            )

            committed_msg = IPCMessage(
                message_type=MessageType.BLOCK_COMMITTED,
                sender=self.node_id,
                receiver="*",
                payload={
                    "proposal_id": proposal_id,
                    "block_index": committed_block["index"],
                    "block_hash": committed_block["hash"],
                    "committed_by": self.node_id,
                    "commit_qc": qc.to_dict(),
                },
            )
            return True, committed_block, committed_msg

        return False, None, None

    def get_consensus_diagnostics(self) -> Dict[str, Any]:
        """Return real-time consensus telemetry for observability and Admin dashboard."""
        return {
            "node_id": self.node_id,
            "consensus_mode": self.consensus_mode,
            "quorum_threshold": self.quorum_threshold,
            "current_view": self.current_view,
            "current_leader": self.get_leader_for_view(self.current_view),
            "stage": self.stage,
            "active_proposals_count": len(self.active_proposals),
            "highest_prepared_height": self.durable_state.highest_prepared_height,
            "total_qcs_committed": len(self.durable_state.commit_qcs),
            "alerts_count": len(self.durable_state.alerts),
            "recent_alerts": self.durable_state.alerts[-5:],
        }
