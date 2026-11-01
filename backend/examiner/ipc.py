"""
AnswerChain Phase 9B: Inter-Process Communication (IPC) Transport.

Implements genuine IPC between examiner processes on one computer using
Python's multiprocessing.Queue. Decouples transport from consensus and ledger logic.
"""

import logging
import multiprocessing
import queue
import time
from typing import Any, Dict, List, Optional, Set, Tuple

from backend.examiner.messages import IPCMessage, MessageType

logger = logging.getLogger("examiner.ipc")


class IPCRouter:
    """
    Message router managing communication across independent process inboxes.
    Operates genuine multiprocessing.Queue channels for inter-process dispatch.
    """

    def __init__(
        self,
        node_ids: Optional[List[str]] = None,
        node_inboxes: Optional[Dict[str, multiprocessing.Queue]] = None,
        manager_queue: Optional[multiprocessing.Queue] = None,
    ) -> None:
        self.node_ids: List[str] = list(node_ids or ["NODE-001", "NODE-002", "NODE-003", "NODE-004", "NODE-005"])
        self.node_inboxes: Dict[str, multiprocessing.Queue] = (
            node_inboxes if node_inboxes is not None else {nid: multiprocessing.Queue() for nid in self.node_ids}
        )
        self.manager_queue: multiprocessing.Queue = (
            manager_queue if manager_queue is not None else multiprocessing.Queue()
        )
        self.stats: Dict[str, Any] = {
            "messages_sent": 0,
            "messages_received": 0,
            "dropped_messages": 0,
            "broadcasts": 0,
            "direct_messages": 0,
            "created_at": time.time(),
        }

    def register_node(self, node_id: str, inbox: multiprocessing.Queue) -> None:
        """Register a node's inbox queue."""
        self.node_inboxes[node_id] = inbox
        if node_id not in self.node_ids:
            self.node_ids.append(node_id)

    def send(self, message: IPCMessage) -> Tuple[bool, Optional[str]]:
        """
        Deliver message to target process inbox or broadcast to all nodes.
        Uses non-blocking or bounded put with timeout protection.
        """
        is_valid, err = message.validate()
        if not is_valid:
            self.stats["dropped_messages"] += 1
            return False, f"VALIDATION_FAILED: {err}"

        raw_dict = message.to_dict()

        try:
            # 1. Manager-targeted message
            if message.receiver == "MANAGER":
                self.manager_queue.put(raw_dict, timeout=1.0)
                self.stats["messages_sent"] += 1
                return True, None

            # 2. Broadcast message to all nodes
            if message.receiver == "*":
                delivered_count = 0
                for nid, q in self.node_inboxes.items():
                    # Do not echo back to sender on broadcast unless sender is MANAGER
                    if nid == message.sender and message.sender != "MANAGER":
                        continue
                    try:
                        q.put(raw_dict, timeout=0.5)
                        delivered_count += 1
                    except (queue.Full, Exception) as e:
                        logger.warning("Failed to queue broadcast to %s: %s", nid, e)
                        self.stats["dropped_messages"] += 1
                self.stats["broadcasts"] += 1
                self.stats["messages_sent"] += delivered_count
                return True, None

            # 3. Direct point-to-point message
            target_queue = self.node_inboxes.get(message.receiver)
            if not target_queue:
                self.stats["dropped_messages"] += 1
                return False, f"UNKNOWN_RECEIVER: {message.receiver}"

            target_queue.put(raw_dict, timeout=1.0)
            self.stats["direct_messages"] += 1
            self.stats["messages_sent"] += 1
            return True, None

        except queue.Full:
            self.stats["dropped_messages"] += 1
            return False, "QUEUE_FULL"
        except Exception as e:
            self.stats["dropped_messages"] += 1
            return False, f"IPC_ERROR: {str(e)}"

    def receive(self, node_id: str, timeout: float = 0.5) -> Optional[IPCMessage]:
        """
        Receive next message from node's inbox queue.
        Returns None if queue is empty after timeout.
        """
        q = self.node_inboxes.get(node_id) if node_id != "MANAGER" else self.manager_queue
        if not q:
            return None

        try:
            raw_dict = q.get(timeout=timeout)
            if not isinstance(raw_dict, dict):
                return None
            msg = IPCMessage.from_dict(raw_dict)
            self.stats["messages_received"] += 1
            return msg
        except (queue.Empty, Exception):
            return None

    def get_queue_size(self, node_id: str) -> int:
        """Approximate queue size (best-effort, platform-dependent)."""
        q = self.node_inboxes.get(node_id) if node_id != "MANAGER" else self.manager_queue
        if not q:
            return 0
        try:
            return q.qsize()
        except NotImplementedError:
            return 0

    def get_stats(self) -> Dict[str, Any]:
        """Return operational IPC statistics."""
        return {
            **self.stats,
            "registered_nodes": list(self.node_inboxes.keys()),
            "queue_sizes": {nid: self.get_queue_size(nid) for nid in self.node_inboxes},
        }

