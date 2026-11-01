"""
AnswerChain Phase 9B: Structured IPC Messages.

Defines the 13 required inter-process communication message types,
structured message validation, and serialization helpers.
"""

import json
import time
import uuid
from typing import Any, Dict, Optional, Tuple


class MessageType:
    NODE_REGISTER = "NODE_REGISTER"
    NODE_HEARTBEAT = "NODE_HEARTBEAT"
    EVALUATION_SUBMITTED = "EVALUATION_SUBMITTED"
    EVALUATION_RECEIVED = "EVALUATION_RECEIVED"
    HEAD_ELECTION_REQUEST = "HEAD_ELECTION_REQUEST"
    HEAD_ELECTION_VOTE = "HEAD_ELECTION_VOTE"
    HEAD_ELECTION_RESULT = "HEAD_ELECTION_RESULT"
    BLOCK_PROPOSAL = "BLOCK_PROPOSAL"
    BLOCK_VALIDATION = "BLOCK_VALIDATION"
    CONSENSUS_VOTE = "CONSENSUS_VOTE"
    BLOCK_COMMITTED = "BLOCK_COMMITTED"
    CHAIN_SYNC_REQUEST = "CHAIN_SYNC_REQUEST"
    CHAIN_SYNC_RESPONSE = "CHAIN_SYNC_RESPONSE"

    # Phase 9.1 Multi-Stage BFT / Permissioned Consensus Messages
    PRE_PREPARE = "PRE_PREPARE"
    PREPARE = "PREPARE"
    COMMIT = "COMMIT"
    VIEW_CHANGE = "VIEW_CHANGE"
    NEW_VIEW = "NEW_VIEW"

    ALL_TYPES = {
        NODE_REGISTER,
        NODE_HEARTBEAT,
        EVALUATION_SUBMITTED,
        EVALUATION_RECEIVED,
        HEAD_ELECTION_REQUEST,
        HEAD_ELECTION_VOTE,
        HEAD_ELECTION_RESULT,
        BLOCK_PROPOSAL,
        BLOCK_VALIDATION,
        CONSENSUS_VOTE,
        BLOCK_COMMITTED,
        CHAIN_SYNC_REQUEST,
        CHAIN_SYNC_RESPONSE,
        PRE_PREPARE,
        PREPARE,
        COMMIT,
        VIEW_CHANGE,
        NEW_VIEW,
    }


class IPCMessage:
    """Structured IPC message container for examiner network communication."""

    def __init__(
        self,
        message_type: str,
        sender: str,
        receiver: str = "*",
        payload: Optional[Dict[str, Any]] = None,
        message_id: Optional[str] = None,
        timestamp: Optional[float] = None,
        signature: Optional[str] = None,
    ) -> None:
        self.message_id = message_id or str(uuid.uuid4())
        self.message_type = str(message_type).strip().upper()
        self.sender = str(sender).strip()
        self.receiver = str(receiver).strip()
        self.payload = dict(payload if payload is not None else {})
        self.timestamp = float(timestamp if timestamp is not None else time.time())
        self.signature = signature

    def validate(self) -> Tuple[bool, Optional[str]]:
        """Validate the structural integrity and type conformance of the message."""
        if not self.message_id:
            return False, "MISSING_MESSAGE_ID"
        if self.message_type not in MessageType.ALL_TYPES:
            return False, f"INVALID_MESSAGE_TYPE: {self.message_type}"
        if not self.sender:
            return False, "MISSING_SENDER"
        if not self.receiver:
            return False, "MISSING_RECEIVER"
        if not isinstance(self.payload, dict):
            return False, "PAYLOAD_MUST_BE_DICT"
        if self.timestamp <= 0:
            return False, "INVALID_TIMESTAMP"
        return True, None

    def to_dict(self) -> Dict[str, Any]:
        """Convert message to a JSON-compatible dictionary."""
        return {
            "message_id": self.message_id,
            "message_type": self.message_type,
            "sender": self.sender,
            "receiver": self.receiver,
            "timestamp": self.timestamp,
            "payload": self.payload,
            "signature": self.signature,
        }

    def to_json(self) -> str:
        """Serialize message to JSON string."""
        return json.dumps(self.to_dict(), sort_keys=True)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "IPCMessage":
        """Reconstruct an IPCMessage from dictionary with validation."""
        if not isinstance(data, dict):
            raise ValueError("Message data must be a dictionary")
        msg = cls(
            message_type=data.get("message_type", ""),
            sender=data.get("sender", ""),
            receiver=data.get("receiver", "*"),
            payload=data.get("payload", {}),
            message_id=data.get("message_id"),
            timestamp=data.get("timestamp"),
            signature=data.get("signature"),
        )
        is_valid, err = msg.validate()
        if not is_valid:
            raise ValueError(f"Invalid IPC message: {err}")
        return msg

    @classmethod
    def from_json(cls, json_str: str) -> "IPCMessage":
        """Deserialize an IPCMessage from JSON string."""
        data = json.loads(json_str)
        return cls.from_dict(data)

    def __repr__(self) -> str:
        return (
            f"<IPCMessage id={self.message_id[:8]} type={self.message_type} "
            f"sender={self.sender} receiver={self.receiver}>"
        )

