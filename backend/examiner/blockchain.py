"""
AnswerChain Phase 9A & 9F: Independent Examiner Blockchain Instance.

Each examiner process maintains its own dedicated blockchain ledger file
in a separate storage path. All instances share the network ID and deterministic
genesis block while validating chains and blocks independently.
"""

import copy
import hashlib
import json
import logging
import os
import time
from typing import Any, Dict, List, Optional, Tuple

from backend.crypto import verify_academic_transaction

logger = logging.getLogger("examiner.blockchain")


class ExaminerBlockchain:
    """Independent blockchain ledger instance for an examiner process."""

    def __init__(
        self,
        node_id: str,
        storage_dir: Optional[str] = None,
    ) -> None:
        self.node_id = str(node_id).strip().upper()
        self.storage_dir = (
            storage_dir
            if storage_dir is not None
            else os.path.abspath(
                os.path.join(
                    os.path.dirname(__file__),
                    "..",
                    "..",
                    "blockchain_data",
                    "examiner_nodes",
                )
            )
        )
        os.makedirs(self.storage_dir, exist_ok=True)
        self.chain_file = os.path.join(self.storage_dir, f"{self.node_id}_blockchain.json")

        self.chain: List[Dict[str, Any]] = []
        self.pending_transactions: List[Dict[str, Any]] = []

        # Load local database or initialize with canonical genesis block
        self.load_chain()
        if not self.chain:
            self.create_genesis_block()

    @staticmethod
    def calculate_hash(
        index: int,
        timestamp: float,
        data: Any,
        previous_hash: str,
    ) -> str:
        """Deterministic block SHA-256 calculation matching AnswerChain network standards."""
        block_string = (
            str(index)
            + str(timestamp)
            + json.dumps(
                data,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False,
            )
            + str(previous_hash)
        )
        return hashlib.sha256(block_string.encode("utf-8")).hexdigest()

    def create_genesis_block(self) -> Dict[str, Any]:
        """Generate canonical genesis block identical to the AnswerChain network."""
        timestamp = 0.0
        data = {
            "type": "GENESIS",
            "network": "AnswerChain",
            "version": "1.0",
        }
        block = {
            "index": 0,
            "timestamp": timestamp,
            "data": data,
            "previous_hash": "0",
        }
        block["hash"] = self.calculate_hash(
            block["index"],
            block["timestamp"],
            block["data"],
            block["previous_hash"],
        )
        self.chain = [block]
        self.save_chain()
        return block

    def save_chain(self) -> None:
        """Atomically persist chain to node's independent database file."""
        temp_file = f"{self.chain_file}.tmp"
        with open(temp_file, "w", encoding="utf-8") as f:
            json.dump(self.chain, f, indent=4, ensure_ascii=False, sort_keys=True)
        os.replace(temp_file, self.chain_file)

    def load_chain(self) -> None:
        """Load blockchain from independent persistent storage."""
        if not os.path.exists(self.chain_file):
            self.chain = []
            return
        try:
            with open(self.chain_file, "r", encoding="utf-8") as f:
                loaded = json.load(f)
            if isinstance(loaded, list) and loaded:
                self.chain = loaded
            else:
                self.chain = []
        except (json.JSONDecodeError, OSError) as e:
            logger.warning("[%s] Failed to load chain: %s", self.node_id, e)
            self.chain = []

    def get_latest_block(self) -> Dict[str, Any]:
        """Return the most recent committed block."""
        if not self.chain:
            self.create_genesis_block()
        return self.chain[-1]

    def add_transaction(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Add transaction to pending pool with SHA-256 identifier."""
        timestamp = time.time()
        tx_string = (
            json.dumps(
                data,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False,
            )
            + str(timestamp)
        )
        tx_id = hashlib.sha256(tx_string.encode("utf-8")).hexdigest()
        transaction = {
            "transaction_id": tx_id,
            "timestamp": timestamp,
            "data": data,
        }
        self.pending_transactions.append(transaction)
        return transaction

    def add_block(
        self,
        transactions: List[Dict[str, Any]],
        previous_hash: Optional[str] = None,
        block_timestamp: Optional[float] = None,
        quorum_certificate: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Append a new block to the local chain and save to disk."""
        latest = self.get_latest_block()
        expected_prev_hash = previous_hash or latest["hash"]
        index = int(latest["index"]) + 1
        timestamp = float(block_timestamp if block_timestamp is not None else time.time())

        block = {
            "index": index,
            "timestamp": timestamp,
            "data": transactions,
            "previous_hash": expected_prev_hash,
        }
        if quorum_certificate is not None:
            block["quorum_certificate"] = quorum_certificate

        block["hash"] = self.calculate_hash(
            block["index"],
            block["timestamp"],
            block["data"],
            block["previous_hash"],
        )

        self.chain.append(block)

        # Clear committed transactions from pending pool
        committed_ids = {
            tx.get("transaction_id")
            for tx in transactions
            if isinstance(tx, dict) and "transaction_id" in tx
        }
        self.pending_transactions = [
            tx for tx in self.pending_transactions
            if tx.get("transaction_id") not in committed_ids
        ]

        self.save_chain()
        return block

    def is_valid_chain(
        self,
        chain: List[Dict[str, Any]],
        require_qc: bool = False,
        required_quorum: int = 3,
    ) -> bool:
        """
        Independently validate any candidate chain:
        1. Valid genesis block structure and hash.
        2. Consecutive indices and previous_hash linkage.
        3. Recalculated block hash equivalence.
        4. Cryptographic signatures of all signed transactions.
        5. Quorum Certificate verification on committed blocks.
        6. Duplicate transaction prevention.
        """
        if not chain:
            return False

        genesis = chain[0]
        if genesis.get("index") != 0 or genesis.get("previous_hash") != "0":
            return False

        req_keys = ("index", "timestamp", "data", "previous_hash", "hash")
        if not all(k in genesis for k in req_keys):
            return False

        calc_genesis = self.calculate_hash(
            genesis["index"],
            genesis["timestamp"],
            genesis["data"],
            genesis["previous_hash"],
        )
        if calc_genesis != genesis["hash"]:
            return False

        # Lazy import to avoid circular dependency
        from backend.examiner.consensus import QuorumCertificate

        seen_tx_answer_scripts = set()

        for i in range(1, len(chain)):
            prev = chain[i - 1]
            curr = chain[i]

            if curr.get("index") != i:
                return False
            if curr.get("previous_hash") != prev.get("hash"):
                return False
            if not all(k in curr for k in req_keys):
                return False

            calc_curr = self.calculate_hash(
                curr["index"],
                curr["timestamp"],
                curr["data"],
                curr["previous_hash"],
            )
            if calc_curr != curr["hash"]:
                return False

            # Verify transaction signatures and duplicate prevention
            txs = curr.get("data")
            if isinstance(txs, list):
                for tx in txs:
                    if isinstance(tx, dict):
                        tx_data = tx.get("data", {})
                        if isinstance(tx_data, dict):
                            if tx_data.get("signature"):
                                is_valid, _ = verify_academic_transaction(tx_data)
                                if not is_valid:
                                    return False
                            as_id = tx_data.get("answer_script_id")
                            if as_id and tx_data.get("type") == "EVALUATION_APPROVED":
                                if as_id in seen_tx_answer_scripts:
                                    return False  # Duplicate approval
                                seen_tx_answer_scripts.add(as_id)

            # Quorum Certificate verification
            qc_data = curr.get("quorum_certificate")
            if qc_data is not None:
                try:
                    qc = QuorumCertificate.from_dict(qc_data)
                    # Verify QC refers to this block
                    if qc.block_height != curr["index"] or qc.block_hash != curr["hash"]:
                        return False
                    valid_qc, _ = qc.verify(required_quorum=required_quorum)
                    if not valid_qc:
                        return False
                except Exception:
                    return False
            elif require_qc:
                return False

        return True

    def replace_chain(
        self,
        new_chain: List[Dict[str, Any]],
        require_qc: bool = False,
        required_quorum: int = 3,
    ) -> bool:
        """
        Replace local chain if new chain is strictly longer, valid, and preserves committed prefix.
        In BFT consensus, locally committed blocks are final and irrevocable.
        A longer chain that conflicts with any already-committed local block is strictly
        rejected to prevent reorganization attacks (Prefix Consistency / Finality).
        """
        if len(new_chain) <= len(self.chain):
            return False

        # Prefix consistency check: committed blocks cannot be rewritten or forked
        for i in range(len(self.chain)):
            local_hash = self.chain[i].get("hash")
            candidate_hash = new_chain[i].get("hash") if i < len(new_chain) else None
            if local_hash != candidate_hash:
                logger.warning(
                    "[%s] Chain replacement REJECTED: Fork at committed block #%d (local: %s, candidate: %s)",
                    self.node_id,
                    i,
                    str(local_hash)[:16],
                    str(candidate_hash)[:16],
                )
                return False

        if not self.is_valid_chain(new_chain, require_qc=require_qc, required_quorum=required_quorum):
            return False

        self.chain = copy.deepcopy(new_chain)
        self.pending_transactions = []
        self.save_chain()
        return True

    def find_transaction(
        self,
        transaction_type: str,
        field: str,
        value: Any,
    ) -> Optional[Dict[str, Any]]:
        """Search committed chain for a matching transaction."""
        for block in self.chain:
            txs = block.get("data", [])
            if not isinstance(txs, list):
                continue
            for tx in txs:
                txd = tx.get("data", {})
                if txd.get("type") == transaction_type and txd.get(field) == value:
                    return tx
        return None

    def find_transactions(self, transaction_type: str) -> List[Dict[str, Any]]:
        """Return all committed transactions of a specific type."""
        results: List[Dict[str, Any]] = []
        for block in self.chain:
            txs = block.get("data", [])
            if not isinstance(txs, list):
                continue
            for tx in txs:
                txd = tx.get("data", {})
                if txd.get("type") == transaction_type:
                    results.append(tx)
        return results

    def get_database_info(self) -> Dict[str, Any]:
        """Return diagnostics about local database file."""
        exists = os.path.isfile(self.chain_file)
        size_bytes = os.path.getsize(self.chain_file) if exists else 0
        latest = self.get_latest_block()
        return {
            "node_id": self.node_id,
            "database_file": self.chain_file,
            "database_exists": exists,
            "size_bytes": size_bytes,
            "block_count": len(self.chain),
            "latest_block_index": latest.get("index", 0),
            "latest_block_hash": latest.get("hash", ""),
            "genesis_hash": self.chain[0]["hash"] if self.chain else "",
            "is_valid": self.is_valid_chain(self.chain),
        }

