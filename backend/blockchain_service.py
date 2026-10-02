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

DEFAULT_TIMEOUT = 5.0  # seconds


class BlockchainService:
    """Service to interact with the AnswerChain distributed node cluster."""

    def __init__(self, node_urls: Optional[Dict[str, str]] = None) -> None:
        self.node_urls = node_urls or NODE_URLS

    def _post(self, node_role: str, path: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        base_url = self.node_urls.get(node_role, self.node_urls["UNIVERSITY"])
        url = f"{base_url}{path}"
        try:
            resp = requests.post(url, json=payload, timeout=DEFAULT_TIMEOUT)
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
            resp = requests.get(url, params=params, timeout=DEFAULT_TIMEOUT)
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
    ) -> Dict[str, Any]:
        """Submit an ANSWER_SCRIPT_REGISTERED transaction to University node."""
        payload = {
            "university": university,
            "exam_id": exam_id,
            "answer_script_id": answer_script_id,
            "file_name": file_name,
            "file_hash": file_hash,
        }
        return self._post("UNIVERSITY", "/answer-scripts/register", payload)

    def assign_teacher(
        self,
        answer_script_id: str,
        teacher_id: str,
        assigned_by: str,
    ) -> Dict[str, Any]:
        """Submit an ANSWER_SCRIPT_ASSIGNED transaction to University node."""
        payload = {
            "answer_script_id": answer_script_id,
            "teacher_id": teacher_id,
            "assigned_by": assigned_by,
        }
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
    ) -> Dict[str, Any]:
        """Submit an EVALUATION_SUBMITTED transaction to Teacher node."""
        payload = {
            "answer_script_id": answer_script_id,
            "teacher_id": teacher_id,
            "marks": marks,
            "max_marks": max_marks,
        }
        return self._post("TEACHER", "/evaluations/submit", payload)

    # ========================================================
    # AUTHORITY ACTIONS (Route to node-3: AUTHORITY)
    # ========================================================

    def finalize_result(
        self,
        answer_script_id: str,
        authority_id: str,
    ) -> Dict[str, Any]:
        """Submit a RESULT_FINALIZED transaction to Authority node."""
        payload = {
            "answer_script_id": answer_script_id,
            "authority_id": authority_id,
        }
        return self._post("AUTHORITY", "/results/finalize", payload)

    def generate_marksheet(
        self,
        answer_script_id: str,
        student_id: str,
        student_name: str,
        university: str,
        exam_name: str,
    ) -> Dict[str, Any]:
        """Request Marksheet generation and PDF creation on Authority node."""
        payload = {
            "answer_script_id": answer_script_id,
            "student_id": student_id,
            "student_name": student_name,
            "university": university,
            "exam_name": exam_name,
        }
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


# Singleton instance
blockchain_service = BlockchainService()
