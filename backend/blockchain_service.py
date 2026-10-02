"""
AnswerChain Blockchain Service.

Acts as the client bridge between Application Services and the Distributed
Node Network (node-1:5001, node-2:5002, node-3:5003).

Application logic never directly manipulates chain files or raw node internals;
instead, it invokes BlockchainService, ensuring complete separation of concerns.
"""

import logging
import os
from typing import Any, Dict, List, Optional
import requests

logger = logging.getLogger("blockchain_service")

# Node endpoint configurations
NODE_URLS = {
    "UNIVERSITY": os.environ.get("NODE_UNIVERSITY_URL", "http://127.0.0.1:5001"),
    "TEACHER": os.environ.get("NODE_TEACHER_URL", "http://127.0.0.1:5002"),
    "AUTHORITY": os.environ.get("NODE_AUTHORITY_URL", "http://127.0.0.1:5003"),
}

NODE_AUTH_TOKEN = os.environ.get("NODE_AUTH_TOKEN", "dev-node-peer-auth-token-389fbc8102")
DEFAULT_TIMEOUT = 5.0  # seconds


class BlockchainService:
    """Service to interact with the AnswerChain distributed node cluster."""

    def __init__(self, node_urls: Optional[Dict[str, str]] = None) -> None:
        self.node_urls = node_urls or NODE_URLS

    def _headers(self) -> Dict[str, str]:
        return {
            "Content-Type": "application/json",
            "X-Node-Auth-Token": NODE_AUTH_TOKEN,
        }

    def _post(self, node_role: str, path: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        base_url = self.node_urls.get(node_role, self.node_urls["UNIVERSITY"])
        url = f"{base_url}{path}"
        try:
            resp = requests.post(url, json=payload, headers=self._headers(), timeout=DEFAULT_TIMEOUT)
            try:
                data = resp.json()
            except Exception:
                data = {"raw": resp.text}
            return {
                "success": resp.status_code in (200, 201),
                "status_code": resp.status_code,
                "data": data,
            }
        except requests.RequestException as e:
            logger.error("Failed to POST %s: %s", url, e)
            return {
                "success": False,
                "status_code": 503,
                "data": {"error": f"Node ({node_role}) unreachable at {url}: {str(e)}"},
            }

    def _get(self, node_role: str, path: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        base_url = self.node_urls.get(node_role, self.node_urls["UNIVERSITY"])
        url = f"{base_url}{path}"
        try:
            resp = requests.get(url, params=params, headers=self._headers(), timeout=DEFAULT_TIMEOUT)
            try:
                data = resp.json()
            except Exception:
                data = {"raw": resp.text}
            return {
                "success": resp.status_code == 200,
                "status_code": resp.status_code,
                "data": data,
            }
        except requests.RequestException as e:
            logger.error("Failed to GET %s: %s", url, e)
            return {
                "success": False,
                "status_code": 503,
                "data": {"error": f"Node ({node_role}) unreachable at {url}: {str(e)}"},
            }

    # ========================================================
    # UNIVERSITY ACTIONS (Route to node-1: UNIVERSITY)
    # ========================================================

    def register_answer_script(
        self,
        university: str,
        exam_id: str,
        answer_script_id: str,
        file_name: str,
        file_hash: str,
        sig_meta: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Submit an ANSWER_SCRIPT_REGISTERED transaction to University node."""
        payload = {
            "university": university,
            "exam_id": exam_id,
            "answer_script_id": answer_script_id,
            "file_name": file_name,
            "file_hash": file_hash,
        }
        if sig_meta:
            payload.update(sig_meta)
        return self._post("UNIVERSITY", "/answer-scripts/register", payload)

    def assign_teacher(
        self,
        answer_script_id: str,
        teacher_id: str,
        assigned_by: str,
        sig_meta: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Submit an ANSWER_SCRIPT_ASSIGNED transaction to University node."""
        payload = {
            "answer_script_id": answer_script_id,
            "teacher_id": teacher_id,
            "assigned_by": assigned_by,
        }
        if sig_meta:
            payload.update(sig_meta)
        return self._post("UNIVERSITY", "/answer-scripts/assign", payload)

    # ========================================================
    # TEACHER ACTIONS (Route to node-2: TEACHER)
    # ========================================================

    def submit_evaluation(
        self,
        answer_script_id: str,
        teacher_id: str,
        marks: float,
        max_marks: float,
        sig_meta: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Submit an EVALUATION_SUBMITTED transaction to Teacher node."""
        payload = {
            "answer_script_id": answer_script_id,
            "teacher_id": teacher_id,
            "marks": marks,
            "max_marks": max_marks,
        }
        if sig_meta:
            payload.update(sig_meta)
        return self._post("TEACHER", "/evaluations/submit", payload)

    # ========================================================
    # AUTHORITY ACTIONS (Route to node-3: AUTHORITY)
    # ========================================================

    def finalize_result(
        self,
        answer_script_id: str,
        authority_id: str,
        sig_meta: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Submit a RESULT_FINALIZED transaction to Authority node."""
        payload = {
            "answer_script_id": answer_script_id,
            "authority_id": authority_id,
        }
        if sig_meta:
            payload.update(sig_meta)
        return self._post("AUTHORITY", "/results/finalize", payload)

    def generate_marksheet(
        self,
        answer_script_id: str,
        student_id: str,
        student_name: str,
        university: str,
        exam_name: str,
        sig_meta: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Request Marksheet generation and PDF creation on Authority node."""
        payload = {
            "answer_script_id": answer_script_id,
            "student_id": student_id,
            "student_name": student_name,
            "university": university,
            "exam_name": exam_name,
        }
        if sig_meta:
            payload.update(sig_meta)
        return self._post("AUTHORITY", "/marksheets/generate", payload)

    # ========================================================
    # VERIFICATION & QUERY (Can query any synchronized node)
    # ========================================================

    def verify_marksheet(
        self,
        marksheet_id: Optional[str] = None,
        marksheet_hash: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Verify logical marksheet hash on the blockchain."""
        payload: Dict[str, Any] = {}
        if marksheet_id:
            payload["marksheet_id"] = marksheet_id
        if marksheet_hash:
            payload["marksheet_hash"] = marksheet_hash
        return self._post("AUTHORITY", "/marksheets/verify", payload)

    def verify_marksheet_pdf(self, marksheet_id: str) -> Dict[str, Any]:
        """Verify the physical marksheet PDF against the on-chain SHA-256 hash."""
        return self._post("AUTHORITY", f"/marksheets/{marksheet_id}/verify-pdf", {})

    def get_answer_script_history(self, answer_script_id: str) -> Dict[str, Any]:
        """Retrieve full lifecycle history of an answer script."""
        return self._get("UNIVERSITY", f"/answer-scripts/{answer_script_id}")

    def get_blockchain(self, node_role: str = "UNIVERSITY") -> Dict[str, Any]:
        """Retrieve full blockchain ledger from a specific node."""
        return self._get(node_role, "/blockchain")

    def get_network_status(self, node_role: str = "UNIVERSITY") -> Dict[str, Any]:
        """Retrieve cluster network overview and peer status."""
        return self._get(node_role, "/network")

    def get_cluster_status(self) -> Dict[str, Any]:
        """
        Inspect all cluster nodes directly from the application service.
        Aggregates live node status, block counts, connected peers, and blockchain ledger.
        Logs internal health without exposing credentials or tokens.
        """
        cluster_defs = [
            {"id": "node-1", "role": "UNIVERSITY", "port": 5001},
            {"id": "node-2", "role": "TEACHER", "port": 5002},
            {"id": "node-3", "role": "AUTHORITY", "port": 5003},
        ]
        nodes_info = []
        statuses = {}
        pending_txs = 0

        for c in cluster_defs:
            node_id = c["id"]
            role = c["role"]
            port = c["port"]
            resp = self._get(role, "/node")
            if resp.get("success"):
                data = resp.get("data", {})
                b_count = int(data.get("blocks", 0))
                is_valid = bool(data.get("chain_valid", True))
                p_tx = int(data.get("pending_transactions", 0))
                pending_txs = max(pending_txs, p_tx)
                statuses[node_id] = "ONLINE"

                nodes_info.append({
                    "id": node_id,
                    "node_id": node_id,
                    "role": role,
                    "port": port,
                    "status": "ONLINE",
                    "blocks": b_count,
                    "block_count": b_count,
                    "chain_valid": is_valid,
                    "is_current": (node_id == "node-1"),
                })
            else:
                statuses[node_id] = "OFFLINE"
                nodes_info.append({
                    "id": node_id,
                    "node_id": node_id,
                    "role": role,
                    "port": port,
                    "status": "OFFLINE",
                    "blocks": 0,
                    "block_count": 0,
                    "chain_valid": False,
                    "is_current": (node_id == "node-1"),
                })

        logger.info(
            "Network check:\n  node-1 -> %s\n  node-2 -> %s\n  node-3 -> %s",
            statuses.get("node-1", "OFFLINE"),
            statuses.get("node-2", "OFFLINE"),
            statuses.get("node-3", "OFFLINE"),
        )

        online_nodes = [n for n in nodes_info if n["status"] == "ONLINE"]
        all_online = len(online_nodes) == len(cluster_defs)
        any_online = len(online_nodes) > 0

        connected_peers = max(0, len(online_nodes) - 1) if any_online else 0
        block_counts = [n["blocks"] for n in online_nodes]
        all_synced = (len(set(block_counts)) <= 1) if online_nodes else False
        max_blocks = max(block_counts) if block_counts else 0

        # Retrieve the confirmed chain from the node with the highest block count
        chain_blocks = []
        for n in sorted(online_nodes, key=lambda x: x["blocks"], reverse=True):
            b_resp = self.get_blockchain(n["role"])
            if b_resp.get("success"):
                blks = b_resp.get("data", {}).get("blocks") or b_resp.get("data", {}).get("chain")
                if blks:
                    chain_blocks = blks
                    break

        net_status = "ONLINE" if all_online else ("PARTIAL" if any_online else "OFFLINE")

        return {
            "network_status": net_status,
            "connected_peers_count": connected_peers,
            "total_nodes": len(cluster_defs),
            "all_chains_synchronized": all_synced,
            "blocks": max_blocks,
            "pending_transactions": pending_txs,
            "chain_valid": any_online and all(n.get("chain_valid", True) for n in online_nodes),
            "current_node": "node-1",
            "node_id": "node-1",
            "role": "UNIVERSITY",
            "port": 5001,
            "nodes": nodes_info,
            "peers": [f"127.0.0.1:{c['port']}" for c in cluster_defs if c["id"] != "node-1"],
            "chain": chain_blocks,
        }


# Singleton instance
blockchain_service = BlockchainService()
