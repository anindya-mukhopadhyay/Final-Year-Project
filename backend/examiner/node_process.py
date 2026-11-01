"""
AnswerChain Phase 9A & 9B: Independent Examiner Node Process Worker.

Runs as an independent OS process via Python multiprocessing.Process.
Maintains its own blockchain instance, independent database, unique cryptographic
identity, and event-driven IPC message dispatch loop.
"""

import logging
import os
import signal
import sys
import time
from typing import Any, Dict, List, Optional

# Ensure project root is in path
PROJECT_ROOT = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "..")
)
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from backend.examiner.blockchain import ExaminerBlockchain
from backend.examiner.consensus import ConsensusMode, ExaminerConsensusEngine
from backend.examiner.election import HeadExaminerRegistry, SubjectElection
from backend.examiner.ipc import IPCRouter
from backend.examiner.messages import IPCMessage, MessageType

logger = logging.getLogger("examiner.process")


def run_examiner_node_process(
    node_id: str,
    teacher_id: str,
    inbox_queue: Any,
    router_queues: Dict[str, Any],
    manager_queue: Any,
    stop_event: Any,
    crash_event: Any,
    storage_dir: Optional[str] = None,
    consensus_mode: str = "BFT",
) -> None:
    """
    Main worker entrypoint for an independent Examiner Node process.
    Executed in a dedicated multiprocessing.Process sandbox.
    """
    clean_node = str(node_id).strip().upper()
    clean_teacher = str(teacher_id).strip().upper()
    pid = os.getpid()

    # Configure logging with PID & Node ID attribution
    logging.basicConfig(
        level=logging.INFO,
        format=f"%(asctime)s [{clean_node}:pid={pid}] %(levelname)s: %(message)s",
    )
    logger.info("Starting Examiner Node %s (Teacher: %s, PID: %d)", clean_node, clean_teacher, pid)

    # 1. Initialize independent persistent blockchain instance
    blockchain = ExaminerBlockchain(node_id=clean_node, storage_dir=storage_dir)

    # 2. Initialize consensus engine with durable WAL
    consensus = ExaminerConsensusEngine(
        node_id=clean_node,
        teacher_id=clean_teacher,
        blockchain=blockchain,
        consensus_mode=consensus_mode,
        storage_dir=storage_dir,
    )

    # 3. Initialize local Head Examiner election registry
    registry = HeadExaminerRegistry()

    # 4. Initialize IPC router with process queues
    ipc = IPCRouter(
        node_ids=list(router_queues.keys()),
        node_inboxes=router_queues,
        manager_queue=manager_queue,
    )

    # Register self in cluster via IPC broadcast
    reg_msg = IPCMessage(
        message_type=MessageType.NODE_REGISTER,
        sender=clean_node,
        receiver="*",
        payload={
            "node_id": clean_node,
            "teacher_id": clean_teacher,
            "pid": pid,
            "block_count": len(blockchain.chain),
            "latest_hash": blockchain.get_latest_block().get("hash"),
        },
    )
    ipc.send(reg_msg)

    # Notify manager directly
    reg_mgr = IPCMessage(
        message_type=MessageType.NODE_REGISTER,
        sender=clean_node,
        receiver="MANAGER",
        payload={
            "node_id": clean_node,
            "teacher_id": clean_teacher,
            "pid": pid,
            "block_count": len(blockchain.chain),
            "latest_hash": blockchain.get_latest_block().get("hash"),
        },
    )
    ipc.send(reg_mgr)

    # Main IPC Event Loop
    while not stop_event.is_set():
        # Check for simulated fault-injection crash
        if crash_event.is_set():
            logger.warning("[%s] Fault injection triggered! Crashing process %d...", clean_node, pid)
            # Hard exit without clean shutdown to test crash resilience
            os._exit(42)

        msg: Optional[IPCMessage] = ipc.receive(clean_node, timeout=0.2)
        if not msg:
            continue

        try:
            mtype = msg.message_type

            # ----------------------------------------------------
            # 1. HEARTBEAT / STATUS PROBE
            # ----------------------------------------------------
            if mtype == MessageType.NODE_HEARTBEAT:
                latest = blockchain.get_latest_block()
                heartbeat_reply = IPCMessage(
                    message_type=MessageType.NODE_HEARTBEAT,
                    sender=clean_node,
                    receiver=msg.sender if msg.sender != "*" else "MANAGER",
                    payload={
                        "node_id": clean_node,
                        "teacher_id": clean_teacher,
                        "pid": pid,
                        "status": "ONLINE",
                        "block_count": len(blockchain.chain),
                        "latest_block_index": latest.get("index", 0),
                        "latest_block_hash": latest.get("hash", ""),
                        "genesis_hash": blockchain.chain[0]["hash"] if blockchain.chain else "",
                        "is_valid": blockchain.is_valid_chain(blockchain.chain),
                        "database_file": blockchain.chain_file,
                        "active_head_examiners": registry.list_head_examiners(),
                        "timestamp": time.time(),
                    },
                )
                ipc.send(heartbeat_reply)

            # ----------------------------------------------------
            # 2. EVALUATION SUBMITTED -> HEAD EXAMINER WORKFLOW
            # ----------------------------------------------------
            elif mtype == MessageType.EVALUATION_SUBMITTED:
                eval_data = msg.payload.get("evaluation", {})
                subject = msg.payload.get("subject", "DBMS").strip().upper()

                # Verify if this node represents the active Head Examiner for this subject
                is_he = registry.is_head_examiner(clean_teacher, subject) or registry.is_head_examiner(clean_node, subject)
                if is_he:
                    logger.info("[%s] Head Examiner received evaluation for %s from %s", clean_node, subject, msg.sender)

                    # Send acknowledgment
                    ack_msg = IPCMessage(
                        message_type=MessageType.EVALUATION_RECEIVED,
                        sender=clean_node,
                        receiver=msg.sender,
                        payload={
                            "status": "RECEIVED",
                            "answer_script_id": eval_data.get("answer_script_id"),
                            "head_examiner": clean_teacher,
                            "subject": subject,
                        },
                    )
                    ipc.send(ack_msg)

                    # Approve evaluation with Head Examiner digital signature
                    ok, approved_tx, err = consensus.approve_evaluation(
                        evaluation_data=eval_data,
                        head_examiner_id=clean_teacher,
                        subject=subject,
                    )
                    if ok and approved_tx:
                        # Create block proposal
                        prop_msg = consensus.create_block_proposal(
                            transactions=[approved_tx],
                            subject=subject,
                        )
                        logger.info("[%s] Broadcasting BLOCK_PROPOSAL %s", clean_node, prop_msg.payload.get("proposal_id"))
                        ipc.send(prop_msg)
                    else:
                        logger.warning("[%s] Evaluation rejected by Head Examiner: %s", clean_node, err)

            # ----------------------------------------------------
            # 3. BLOCK PROPOSAL & PRE-PREPARE -> VALIDATION
            # ----------------------------------------------------
            elif mtype == MessageType.PRE_PREPARE:
                subject = msg.payload.get("subject", "").strip().upper()
                leader = msg.sender
                view = int(msg.payload.get("view", 0))

                is_auth = (
                    registry.is_head_examiner(leader, subject)
                    or consensus.get_leader_for_view(view, subject) == leader
                )

                ok, prep_msg, reason = consensus.handle_pre_prepare(msg, is_leader_authorized=is_auth)
                if ok and prep_msg:
                    ipc.send(prep_msg)
                else:
                    logger.warning("[%s] PRE_PREPARE rejected from %s: %s", clean_node, leader, reason)

            elif mtype == MessageType.PREPARE:
                ok, commit_msg, reason = consensus.handle_prepare(msg)
                if ok and commit_msg:
                    ipc.send(commit_msg)

            elif mtype == MessageType.COMMIT:
                committed, block, commit_notice, reason = consensus.handle_commit(msg)
                if committed and commit_notice and block:
                    logger.info(
                        "[%s] Quorum Certificate verified! Block #%d committed independently (Hash: %s...)",
                        clean_node,
                        block["index"],
                        block["hash"][:16],
                    )
                    ipc.send(commit_notice)

                    mgr_notice = IPCMessage(
                        message_type=MessageType.BLOCK_COMMITTED,
                        sender=clean_node,
                        receiver="MANAGER",
                        payload={
                            "node_id": clean_node,
                            "block_index": block["index"],
                            "block_hash": block["hash"],
                            "block": block,
                        },
                    )
                    ipc.send(mgr_notice)

            elif mtype == MessageType.VIEW_CHANGE:
                ok, nv_msg, reason = consensus.handle_view_change(msg)
                if ok and nv_msg:
                    logger.info("[%s] New view established! Broadcasting NEW_VIEW (View %d)", clean_node, nv_msg.payload.get("new_view"))
                    ipc.send(nv_msg)

            elif mtype == MessageType.NEW_VIEW:
                new_v = int(msg.payload.get("new_view", 0))
                if new_v > consensus.current_view:
                    consensus.current_view = new_v
                    consensus.durable_state.current_view = new_v
                    consensus.durable_state.save()
                    consensus.stage = "IDLE"
                    logger.info("[%s] Transitioned to new view %d (Leader: %s)", clean_node, new_v, msg.sender)

            elif mtype == MessageType.BLOCK_PROPOSAL:
                subject = msg.payload.get("subject", "").strip().upper()
                proposer = msg.sender

                # Check if proposer is recognized Head Examiner or election winner
                is_auth = (
                    registry.is_head_examiner(proposer, subject)
                    or (subject == "" and proposer in ["NODE-001", "NODE-002", "NODE-003", "NODE-004", "NODE-005"])
                )

                vote_msg = consensus.handle_proposal_message(msg, is_proposer_authorized=is_auth)
                if vote_msg:
                    ipc.send(vote_msg)

            # ----------------------------------------------------
            # 4. CONSENSUS VOTE -> TALLY & QUORUM COMMIT (LEGACY)
            # ----------------------------------------------------
            elif mtype == MessageType.CONSENSUS_VOTE:
                committed, block, commit_msg = consensus.handle_vote_message(msg)
                if committed and commit_msg:
                    logger.info(
                        "[%s] Quorum reached! Block #%d committed locally (Hash: %s...)",
                        clean_node,
                        block["index"],
                        block["hash"][:16],
                    )
                    ipc.send(commit_msg)

                    # Also notify MANAGER
                    mgr_notice = IPCMessage(
                        message_type=MessageType.BLOCK_COMMITTED,
                        sender=clean_node,
                        receiver="MANAGER",
                        payload={
                            "node_id": clean_node,
                            "block_index": block["index"],
                            "block_hash": block["hash"],
                            "block": block,
                        },
                    )
                    ipc.send(mgr_notice)

            # ----------------------------------------------------
            # 5. DEMOCRATIC HEAD EXAMINER ELECTION
            # ----------------------------------------------------
            elif mtype == MessageType.HEAD_ELECTION_REQUEST:
                elec_dict = msg.payload.get("election", {})
                elec_id = elec_dict.get("election_id")
                subject = elec_dict.get("subject")
                if elec_id and subject:
                    if elec_id not in registry.elections:
                        election = SubjectElection(
                            election_id=elec_id,
                            subject=subject,
                            term_days=elec_dict.get("term_days", 365),
                            quorum_threshold=elec_dict.get("quorum_threshold", 3),
                        )
                        registry.elections[elec_id] = election

            elif mtype == MessageType.HEAD_ELECTION_VOTE:
                elec_id = msg.payload.get("election_id")
                voter_id = msg.payload.get("voter_id")
                candidate_id = msg.payload.get("candidate_id")
                signature = msg.payload.get("signature")

                election = registry.elections.get(elec_id)
                if election:
                    election.cast_vote(
                        voter_id=voter_id,
                        candidate_id=candidate_id,
                        signature=signature,
                    )

            elif mtype == MessageType.HEAD_ELECTION_RESULT:
                elec_data = msg.payload.get("result", {})
                subject = elec_data.get("subject")
                winner_id = elec_data.get("winner_id")
                winner_node = elec_data.get("winner_node_id")
                tx = elec_data.get("transaction")

                if subject and winner_id:
                    registry.active_head_examiners[subject] = {
                        "subject": subject,
                        "head_examiner_id": winner_id,
                        "node_id": winner_node,
                        "term_start": elec_data.get("term_start"),
                        "term_end": elec_data.get("term_end"),
                        "is_valid": True,
                    }
                    logger.info("[%s] Head Examiner registered for %s: %s (%s)", clean_node, subject, winner_id, winner_node)

                    # If this node is the winner node, broadcast block proposal for the election result!
                    if clean_node == winner_node and tx:
                        prop_msg = consensus.create_block_proposal(
                            transactions=[tx],
                            subject=subject,
                        )
                        ipc.send(prop_msg)

            # ----------------------------------------------------
            # 6. CHAIN SYNCHRONIZATION
            # ----------------------------------------------------
            elif mtype == MessageType.CHAIN_SYNC_REQUEST:
                sync_reply = IPCMessage(
                    message_type=MessageType.CHAIN_SYNC_RESPONSE,
                    sender=clean_node,
                    receiver=msg.sender,
                    payload={
                        "chain": blockchain.chain,
                        "latest_hash": blockchain.get_latest_block().get("hash"),
                        "block_count": len(blockchain.chain),
                    },
                )
                ipc.send(sync_reply)

            elif mtype == MessageType.CHAIN_SYNC_RESPONSE:
                peer_chain = msg.payload.get("chain", [])
                if isinstance(peer_chain, list) and len(peer_chain) > len(blockchain.chain):
                    replaced = blockchain.replace_chain(peer_chain, require_qc=False)
                    if replaced:
                        logger.info(
                            "[%s] Catch-up sync complete! Chain height now %d (synced from %s)",
                            clean_node,
                            len(blockchain.chain),
                            msg.sender,
                        )
                    else:
                        logger.warning(
                            "[%s] Chain sync rejected from %s: candidate chain failed validation or Quorum Certificate check",
                            clean_node,
                            msg.sender,
                        )

        except Exception as e:
            logger.error("[%s] Error handling message %s: %s", clean_node, msg, e, exc_info=True)

    # Clean shutdown
    blockchain.save_chain()
    logger.info("[%s] Examiner Node stopped cleanly (PID: %d)", clean_node, pid)

