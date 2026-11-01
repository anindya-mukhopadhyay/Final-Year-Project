"""
AnswerChain Phase 9: Multi-Process Examiner Network Manager.

Orchestrates the 5 independent examiner processes, IPC queues, democratic
subject elections, consensus dispatch, process health tracking, and fault recovery.
"""

import logging
import multiprocessing
import os
import time
from typing import Any, Dict, List, Optional, Tuple

from backend.crypto import sign_academic_transaction
from backend.examiner.election import (
    DEFAULT_ELIGIBLE_TEACHERS,
    EXAMINER_TEACHER_MAP,
    HeadExaminerRegistry,
    SubjectElection,
)
from backend.examiner.ipc import IPCRouter
from backend.examiner.messages import IPCMessage, MessageType
from backend.examiner.node_process import run_examiner_node_process

logger = logging.getLogger("examiner.manager")


class ExaminerNetworkManager:
    """Central orchestration manager for the Phase 9 examiner cluster."""

    def __init__(
        self,
        node_mapping: Optional[Dict[str, str]] = None,
        storage_base_dir: Optional[str] = None,
    ) -> None:
        self.node_mapping: Dict[str, str] = dict(node_mapping or EXAMINER_TEACHER_MAP)
        self.storage_base_dir = storage_base_dir or os.path.abspath(
            os.path.join(
                os.path.dirname(__file__),
                "..",
                "..",
                "blockchain_data",
                "examiner_nodes",
            )
        )
        os.makedirs(self.storage_base_dir, exist_ok=True)

        self.inbox_queues: Dict[str, multiprocessing.Queue] = {}
        self.manager_queue: multiprocessing.Queue = multiprocessing.Queue()
        self.processes: Dict[str, multiprocessing.Process] = {}
        self.stop_events: Dict[str, multiprocessing.Event] = {}
        self.crash_events: Dict[str, multiprocessing.Event] = {}
        self.router: Optional[IPCRouter] = None

        self.election_registry = HeadExaminerRegistry(
            storage_path=os.path.join(self.storage_base_dir, "elections_registry.json")
        )
        self.is_running = False
        self.node_pids: Dict[str, int] = {}
        self.failure_history: List[Dict[str, Any]] = []

    def start(self) -> None:
        """Instantiate and launch all five independent examiner processes."""
        if self.is_running:
            return

        logger.info("Initializing Phase 9 Multi-Process Examiner Network (5 Nodes)...")

        # Create queues
        for node_id in self.node_mapping:
            self.inbox_queues[node_id] = multiprocessing.Queue()
            self.stop_events[node_id] = multiprocessing.Event()
            self.crash_events[node_id] = multiprocessing.Event()

        self.router = IPCRouter(
            node_ids=list(self.node_mapping.keys()),
            node_inboxes=self.inbox_queues,
            manager_queue=self.manager_queue,
        )

        # Launch independent processes
        for node_id, teacher_id in self.node_mapping.items():
            self._spawn_node_process(node_id, teacher_id)

        self.is_running = True
        logger.info("All 5 examiner processes successfully launched.")

        # Brief warmup to let processes initialize
        time.sleep(0.5)

    def _spawn_node_process(self, node_id: str, teacher_id: str) -> None:
        """Spawn a single node process."""
        self.stop_events[node_id].clear()
        self.crash_events[node_id].clear()

        p = multiprocessing.Process(
            target=run_examiner_node_process,
            kwargs={
                "node_id": node_id,
                "teacher_id": teacher_id,
                "inbox_queue": self.inbox_queues[node_id],
                "router_queues": self.inbox_queues,
                "manager_queue": self.manager_queue,
                "stop_event": self.stop_events[node_id],
                "crash_event": self.crash_events[node_id],
                "storage_dir": self.storage_base_dir,
            },
            name=f"Examiner-{node_id}",
        )
        p.daemon = True
        p.start()
        self.processes[node_id] = p
        self.node_pids[node_id] = p.pid or 0
        logger.info("Spawned %s process with PID %d", node_id, p.pid or 0)

    def stop(self) -> None:
        """Signal and cleanly terminate all examiner processes."""
        if not self.is_running:
            return

        logger.info("Stopping all examiner processes...")
        for node_id, event in self.stop_events.items():
            event.set()

        for node_id, p in self.processes.items():
            if p.is_alive():
                p.join(timeout=1.0)
                if p.is_alive():
                    p.terminate()

        self.is_running = False
        logger.info("All examiner processes stopped.")

    def crash_node(self, node_id: str) -> bool:
        """Simulate unexpected process failure for crash resilience testing."""
        clean_node = node_id.strip().upper()
        if clean_node not in self.processes:
            return False

        logger.warning("Simulating crash on %s...", clean_node)
        self.crash_events[clean_node].set()

        p = self.processes[clean_node]
        p.join(timeout=2.0)
        if p.is_alive():
            p.kill()

        self.failure_history.append({
            "node_id": clean_node,
            "event": "CRASHED",
            "timestamp": time.time(),
            "pid": self.node_pids.get(clean_node),
        })
        return True

    def restart_node(self, node_id: str) -> bool:
        """Restart a failed node in a new process; recovers state and triggers sync."""
        clean_node = node_id.strip().upper()
        if clean_node not in self.node_mapping:
            return False

        teacher_id = self.node_mapping[clean_node]
        logger.info("Restarting examiner node %s...", clean_node)

        # Re-create inbox if needed
        self.inbox_queues[clean_node] = multiprocessing.Queue()
        if self.router:
            self.router.register_node(clean_node, self.inbox_queues[clean_node])

        self._spawn_node_process(clean_node, teacher_id)

        self.failure_history.append({
            "node_id": clean_node,
            "event": "RECOVERED",
            "timestamp": time.time(),
            "pid": self.node_pids.get(clean_node),
        })

        # Request chain synchronization from peers
        time.sleep(0.3)
        self.sync_node(clean_node)
        return True

    def sync_node(self, node_id: str) -> None:
        """Broadcast CHAIN_SYNC_REQUEST from a specific node."""
        clean_node = node_id.strip().upper()
        if not self.router:
            return
        msg = IPCMessage(
            message_type=MessageType.CHAIN_SYNC_REQUEST,
            sender=clean_node,
            receiver="*",
        )
        self.router.send(msg)

    def get_status(self) -> Dict[str, Any]:
        """Collect diagnostic and operational metrics across all 5 nodes."""
        nodes_status = []
        sync_hashes = set()
        total_blocks_max = 0

        for node_id, teacher_id in self.node_mapping.items():
            proc = self.processes.get(node_id)
            is_alive = bool(proc and proc.is_alive())
            pid = self.node_pids.get(node_id, 0)

            # Inspect independent database file directly
            db_path = os.path.join(self.storage_base_dir, f"{node_id}_blockchain.json")
            db_exists = os.path.isfile(db_path)
            block_count = 0
            latest_hash = ""
            genesis_hash = ""
            is_valid = False

            if db_exists:
                try:
                    import json
                    with open(db_path, "r", encoding="utf-8") as f:
                        chain = json.load(f)
                    if isinstance(chain, list) and chain:
                        block_count = len(chain)
                        latest_hash = chain[-1].get("hash", "")
                        genesis_hash = chain[0].get("hash", "")
                        sync_hashes.add(latest_hash)
                        total_blocks_max = max(total_blocks_max, block_count)
                        is_valid = True
                except Exception:
                    pass

            state_path = os.path.join(self.storage_base_dir, f"consensus_state_{node_id}.json")
            node_view = 0
            alerts_count = 0
            qcs_count = 0
            if os.path.isfile(state_path):
                try:
                    with open(state_path, "r", encoding="utf-8") as sf:
                        sdata = json.load(sf)
                    node_view = int(sdata.get("current_view", 0))
                    alerts_count = len(sdata.get("alerts", []))
                    qcs_count = len(sdata.get("commit_qcs", {}))
                except Exception:
                    pass

            nodes_status.append({
                "node_id": node_id,
                "teacher_id": teacher_id,
                "pid": pid,
                "status": "ONLINE" if is_alive else "CRASHED",
                "database_file": db_path,
                "database_exists": db_exists,
                "block_count": block_count,
                "latest_block_hash": latest_hash,
                "genesis_hash": genesis_hash,
                "is_valid": is_valid,
                "current_view": node_view,
                "alerts_count": alerts_count,
                "qcs_count": qcs_count,
            })

        is_synchronized = len(sync_hashes) <= 1 and bool(sync_hashes)
        ipc_stats = self.router.get_stats() if self.router else {}
        cluster_view = max((n["current_view"] for n in nodes_status), default=0)
        consensus_leader = f"NODE-00{(cluster_view % 5) + 1}"

        return {
            "network_status": "ONLINE" if any(n["status"] == "ONLINE" for n in nodes_status) else "OFFLINE",
            "total_nodes": len(self.node_mapping),
            "online_nodes": sum(1 for n in nodes_status if n["status"] == "ONLINE"),
            "is_synchronized": is_synchronized,
            "max_block_height": total_blocks_max,
            "current_view": cluster_view,
            "consensus_leader": consensus_leader,
            "consensus_mode": "BFT",
            "quorum_required": 4,  # BFT quorum for N=5, f=1
            "cft_quorum_required": 3,  # CFT quorum for N=5, f=2
            "nodes": nodes_status,
            "active_head_examiners": self.election_registry.list_head_examiners(),
            "elections": self.election_registry.list_elections(),
            "failure_history": self.failure_history[-10:],
            "ipc_stats": ipc_stats,
        }

    # ========================================================
    # DEMOCRATIC HEAD EXAMINER ELECTIONS
    # ========================================================

    def start_election(
        self,
        subject: str,
        term_days: int = 365,
        initiated_by: str = "ADMIN-001",
    ) -> Dict[str, Any]:
        """Start a subject-wise Head Examiner election and broadcast to nodes."""
        election = self.election_registry.start_election(
            subject=subject,
            term_days=term_days,
            initiated_by=initiated_by,
        )

        # Broadcast election request via IPC
        if self.router:
            msg = IPCMessage(
                message_type=MessageType.HEAD_ELECTION_REQUEST,
                sender="MANAGER",
                receiver="*",
                payload={"election": election.to_dict()},
            )
            self.router.send(msg)

        return election.to_dict()

    def cast_vote(
        self,
        election_id: str,
        voter_id: str,
        candidate_id: str,
        signature: Optional[str] = None,
    ) -> Tuple[bool, str, Dict[str, Any]]:
        """Cast a cryptographically signed vote in an active election."""
        election = self.election_registry.elections.get(election_id)
        if not election:
            return False, f"ELECTION_NOT_FOUND: {election_id}", {}

        ok, reason = election.cast_vote(
            voter_id=voter_id,
            candidate_id=candidate_id,
            signature=signature,
        )
        if not ok:
            return False, reason, election.to_dict()

        self.election_registry.save()

        # Broadcast vote via IPC
        if self.router:
            msg = IPCMessage(
                message_type=MessageType.HEAD_ELECTION_VOTE,
                sender="MANAGER",
                receiver="*",
                payload={
                    "election_id": election_id,
                    "voter_id": voter_id,
                    "candidate_id": candidate_id,
                    "signature": signature,
                },
            )
            self.router.send(msg)

        # Check if all eligible teachers voted or quorum satisfied
        if len(election.votes) >= len(election.eligible_voters):
            self.conclude_election(election_id)

        return True, reason, election.to_dict()

    def conclude_election(self, election_id: str) -> Tuple[bool, str, Dict[str, Any]]:
        """Tally ballots, appoint Head Examiner, and broadcast result for block commitment."""
        election = self.election_registry.elections.get(election_id)
        if not election:
            return False, "ELECTION_NOT_FOUND", {}

        ok, reason, details = election.tally()
        if ok:
            self.election_registry.record_election_conclusion(election)

            # Broadcast HEAD_ELECTION_RESULT to all examiner nodes via IPC
            if self.router:
                msg = IPCMessage(
                    message_type=MessageType.HEAD_ELECTION_RESULT,
                    sender="MANAGER",
                    receiver="*",
                    payload={"result": details},
                )
                self.router.send(msg)

        return ok, reason, details

    # ========================================================
    # EVALUATION WORKFLOW & CONSENSUS INGESTION
    # ========================================================

    def submit_evaluation(
        self,
        answer_script_id: str,
        teacher_id: str,
        subject: str,
        marks: float,
        max_marks: float = 100.0,
        remarks: str = "Evaluated by faculty examiner",
        signature: Optional[str] = None,
    ) -> Tuple[bool, Optional[str], Dict[str, Any]]:
        """
        Submit signed evaluation into examiner cluster via IPC.
        Routes to the subject's Head Examiner for approval and block consensus.
        """
        clean_teacher = teacher_id.strip().upper()
        clean_sub = subject.strip().upper()

        # Auto-sign if signature not provided
        payload = {
            "type": "EVALUATION_SUBMITTED",
            "answer_script_id": answer_script_id,
            "teacher_id": clean_teacher,
            "subject": clean_sub,
            "marks": float(marks),
            "max_marks": float(max_marks),
            "remarks": remarks,
            "timestamp": time.time(),
        }

        signed_eval = sign_academic_transaction(
            payload=payload,
            actor_id=clean_teacher,
            actor_role="TEACHER",
        )

        # Find which node hosts the Head Examiner for this subject
        he_info = self.election_registry.get_head_examiner(clean_sub)
        target_node = he_info.get("node_id", "*") if he_info else "*"

        # Send via IPC
        if not self.router:
            return False, "ROUTER_NOT_INITIALIZED", {}

        msg = IPCMessage(
            message_type=MessageType.EVALUATION_SUBMITTED,
            sender=EXAMINER_TEACHER_MAP.get(clean_teacher, "NODE-001"),
            receiver=target_node,
            payload={
                "evaluation": signed_eval,
                "subject": clean_sub,
            },
        )
        ok, err = self.router.send(msg)
        return ok, err, signed_eval


# Global manager singleton
examiner_manager = ExaminerNetworkManager()

