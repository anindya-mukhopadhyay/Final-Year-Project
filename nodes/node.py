import hashlib
import json
import os
import sys
import time
from copy import deepcopy
from typing import Any, Dict, List, Optional

import requests
from flask import Flask, jsonify, request, send_file
from flask_cors import CORS


# ============================================================
# PROJECT ROOT
# ============================================================

PROJECT_ROOT = os.path.abspath(
    os.path.join(
        os.path.dirname(__file__),
        "..",
    )
)

if PROJECT_ROOT not in sys.path:
    sys.path.insert(
        0,
        PROJECT_ROOT,
    )


# ============================================================
# BACKEND IMPORTS
# ============================================================

from backend.marksheet import (  # noqa: E402
    calculate_marksheet_hash,
    generate_marksheet,
    verify_marksheet_hash,
)

from backend.marksheet_pdf import (  # noqa: E402
    calculate_pdf_hash,
    generate_marksheet_pdf,
    verify_pdf_hash,
)


# ============================================================
# CONFIGURATION
# ============================================================

NODE_ID = os.environ.get(
    "NODE_ID",
    "node-1",
)

PORT = int(
    os.environ.get(
        "NODE_PORT",
        "5001",
    )
)

DATA_DIR = os.path.join(
    PROJECT_ROOT,
    "blockchain_data",
)

GENERATED_MARKSHEETS_DIR = os.path.join(
    PROJECT_ROOT,
    "generated",
    "marksheets",
)

os.makedirs(
    DATA_DIR,
    exist_ok=True,
)

os.makedirs(
    GENERATED_MARKSHEETS_DIR,
    exist_ok=True,
)

CHAIN_FILE = os.path.join(
    DATA_DIR,
    f"{NODE_ID}_blockchain.json",
)


# ============================================================
# FLASK
# ============================================================

app = Flask(
    __name__
)

CORS(app)


# ============================================================
# BLOCKCHAIN
# ============================================================

class NodeBlockchain:

    def __init__(self) -> None:

        self.node_id = NODE_ID

        self.chain: List[
            Dict[str, Any]
        ] = []

        self.pending_transactions: List[
            Dict[str, Any]
        ] = []

        self.peers: set[str] = set()

        self.load_chain()

        if not self.chain:
            self.create_genesis_block()

    # ========================================================
    # HASHING
    # ========================================================

    @staticmethod
    def calculate_hash(
        index: int,
        timestamp: float,
        data: Any,
        previous_hash: str,
    ) -> str:

        block_string = (
            str(index)
            +
            str(timestamp)
            +
            json.dumps(
                data,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False,
            )
            +
            str(previous_hash)
        )

        return hashlib.sha256(
            block_string.encode(
                "utf-8"
            )
        ).hexdigest()

    # ========================================================
    # GENESIS BLOCK
    # ========================================================

    def create_genesis_block(
        self,
    ) -> None:

        # Every node uses the same deterministic genesis
        # block so independently started nodes can join
        # the same blockchain network.

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

        self.chain.append(
            block
        )

        self.save_chain()

    # ========================================================
    # PERSISTENCE
    # ========================================================

    def save_chain(
        self,
    ) -> None:

        temporary_file = (
            f"{CHAIN_FILE}.tmp"
        )

        with open(
            temporary_file,
            "w",
            encoding="utf-8",
        ) as file:

            json.dump(
                self.chain,
                file,
                indent=4,
                ensure_ascii=False,
            )

        os.replace(
            temporary_file,
            CHAIN_FILE,
        )

    def load_chain(
        self,
    ) -> None:

        if not os.path.exists(
            CHAIN_FILE
        ):
            return

        try:

            with open(
                CHAIN_FILE,
                "r",
                encoding="utf-8",
            ) as file:

                loaded = json.load(
                    file
                )

            if (
                isinstance(
                    loaded,
                    list,
                )
                and loaded
            ):

                self.chain = loaded

            else:

                self.chain = []

        except (
            json.JSONDecodeError,
            OSError,
        ):

            self.chain = []

    # ========================================================
    # TRANSACTIONS
    # ========================================================

    def add_transaction(
        self,
        data: Dict[str, Any],
    ) -> Dict[str, Any]:

        timestamp = time.time()

        transaction_string = (
            json.dumps(
                data,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False,
            )
            +
            str(timestamp)
        )

        transaction_id = hashlib.sha256(
            transaction_string.encode(
                "utf-8"
            )
        ).hexdigest()

        transaction = {
            "transaction_id":
                transaction_id,

            "timestamp":
                timestamp,

            "data":
                data,
        }

        self.pending_transactions.append(
            transaction
        )

        return transaction

    def transaction_exists(
        self,
        transaction_type: str,
        field: str,
        value: Any,
    ) -> bool:

        return (
            self.find_transaction(
                transaction_type,
                field,
                value,
            )
            is not None
            or
            self.find_pending_transaction(
                transaction_type,
                field,
                value,
            )
            is not None
        )

    def find_pending_transaction(
        self,
        transaction_type: str,
        field: str,
        value: Any,
    ) -> Optional[
        Dict[str, Any]
    ]:

        for transaction in (
            self.pending_transactions
        ):

            transaction_data = (
                transaction.get(
                    "data",
                    {},
                )
            )

            if (
                transaction_data.get(
                    "type"
                )
                ==
                transaction_type
                and
                transaction_data.get(
                    field
                )
                ==
                value
            ):

                return transaction

        return None

    def find_transaction(
        self,
        transaction_type: str,
        field: str,
        value: Any,
    ) -> Optional[
        Dict[str, Any]
    ]:

        for block in self.chain:

            transactions = block.get(
                "data",
                [],
            )

            if not isinstance(
                transactions,
                list,
            ):
                continue

            for transaction in transactions:

                transaction_data = (
                    transaction.get(
                        "data",
                        {},
                    )
                )

                if (
                    transaction_data.get(
                        "type"
                    )
                    ==
                    transaction_type
                    and
                    transaction_data.get(
                        field
                    )
                    ==
                    value
                ):

                    return transaction

        return None

    def find_transactions(
        self,
        transaction_type: str,
    ) -> List[
        Dict[str, Any]
    ]:

        results: List[
            Dict[str, Any]
        ] = []

        for block in self.chain:

            transactions = block.get(
                "data",
                [],
            )

            if not isinstance(
                transactions,
                list,
            ):
                continue

            for transaction in transactions:

                transaction_data = (
                    transaction.get(
                        "data",
                        {},
                    )
                )

                if (
                    transaction_data.get(
                        "type"
                    )
                    ==
                    transaction_type
                ):

                    results.append(
                        transaction
                    )

        return results

    # ========================================================
    # BLOCKS
    # ========================================================

    def add_block(
        self,
        transactions: List[
            Dict[str, Any]
        ],
    ) -> Dict[str, Any]:

        if not self.chain:
            self.create_genesis_block()

        previous_block = (
            self.chain[-1]
        )

        index = (
            int(
                previous_block[
                    "index"
                ]
            )
            +
            1
        )

        timestamp = time.time()

        block = {
            "index":
                index,

            "timestamp":
                timestamp,

            "data":
                transactions,

            "previous_hash":
                previous_block[
                    "hash"
                ],
        }

        block["hash"] = self.calculate_hash(
            block["index"],
            block["timestamp"],
            block["data"],
            block["previous_hash"],
        )

        self.chain.append(
            block
        )

        self.pending_transactions = []

        self.save_chain()

        return block

    def is_valid_chain(
        self,
        chain: List[
            Dict[str, Any]
        ],
    ) -> bool:

        if not chain:
            return False

        genesis = chain[0]

        if (
            genesis.get(
                "index"
            )
            !=
            0
        ):
            return False

        if (
            genesis.get(
                "previous_hash"
            )
            !=
            "0"
        ):
            return False

        required_genesis = (
            "index",
            "timestamp",
            "data",
            "previous_hash",
            "hash",
        )

        if not all(
            key in genesis
            for key in required_genesis
        ):
            return False

        calculated_genesis_hash = (
            self.calculate_hash(
                genesis["index"],
                genesis["timestamp"],
                genesis["data"],
                genesis["previous_hash"],
            )
        )

        if (
            calculated_genesis_hash
            !=
            genesis["hash"]
        ):
            return False

        if genesis.get(
            "data"
        ) != {
            "type":
                "GENESIS",

            "network":
                "AnswerChain",

            "version":
                "1.0",
        }:

            return False

        for index in range(
            1,
            len(chain),
        ):

            previous = chain[
                index - 1
            ]

            current = chain[
                index
            ]

            if (
                current.get(
                    "index"
                )
                !=
                index
            ):
                return False

            if (
                current.get(
                    "previous_hash"
                )
                !=
                previous.get(
                    "hash"
                )
            ):
                return False

            required = (
                "index",
                "timestamp",
                "data",
                "previous_hash",
                "hash",
            )

            if not all(
                key in current
                for key in required
            ):
                return False

            calculated_hash = (
                self.calculate_hash(
                    current["index"],
                    current["timestamp"],
                    current["data"],
                    current["previous_hash"],
                )
            )

            if (
                calculated_hash
                !=
                current["hash"]
            ):
                return False

        return True

    def replace_chain(
        self,
        new_chain: List[
            Dict[str, Any]
        ],
    ) -> bool:

        if (
            len(new_chain)
            <=
            len(self.chain)
        ):
            return False

        if not self.is_valid_chain(
            new_chain
        ):
            return False

        self.chain = deepcopy(
            new_chain
        )

        self.pending_transactions = []

        self.save_chain()

        return True

    # ========================================================
    # NETWORK BROADCAST
    # ========================================================

    def broadcast_transaction(
        self,
        transaction: Dict[str, Any],
    ) -> None:

        for peer in list(
            self.peers
        ):

            try:

                requests.post(
                    f"http://{peer}/receive-transaction",
                    json={
                        "transaction":
                            transaction
                    },
                    timeout=2,
                )

            except requests.RequestException:
                pass

    def broadcast_block(
        self,
        block: Dict[str, Any],
    ) -> None:

        for peer in list(
            self.peers
        ):

            try:

                requests.post(
                    f"http://{peer}/receive-block",
                    json={
                        "block":
                            block
                    },
                    timeout=2,
                )

            except requests.RequestException:
                pass

    # ========================================================
    # CONSENSUS
    # ========================================================

    def consensus(
        self,
    ) -> Dict[str, Any]:

        longest_chain = self.chain

        source_node = self.node_id

        for peer in list(
            self.peers
        ):

            try:

                response = requests.get(
                    f"http://{peer}/chain",
                    timeout=2,
                )

                if (
                    response.status_code
                    !=
                    200
                ):
                    continue

                peer_chain = (
                    response.json().get(
                        "chain",
                        [],
                    )
                )

                if (
                    isinstance(
                        peer_chain,
                        list,
                    )
                    and
                    len(peer_chain)
                    >
                    len(longest_chain)
                    and
                    self.is_valid_chain(
                        peer_chain
                    )
                ):

                    longest_chain = (
                        peer_chain
                    )

                    source_node = peer

            except (
                requests.RequestException,
                ValueError,
            ):

                pass

        replaced = False

        if (
            len(longest_chain)
            >
            len(self.chain)
        ):

            replaced = (
                self.replace_chain(
                    longest_chain
                )
            )

        return {
            "replaced":
                replaced,

            "source_node":
                source_node,
        }


# ============================================================
# BLOCKCHAIN INSTANCE
# ============================================================

blockchain = NodeBlockchain()


# ============================================================
# HELPER FUNCTIONS
# ============================================================

def add_and_broadcast_transaction(
    data: Dict[str, Any],
) -> Dict[str, Any]:

    transaction = (
        blockchain.add_transaction(
            data
        )
    )

    blockchain.broadcast_transaction(
        transaction
    )

    return transaction


def require_json() -> Dict[str, Any]:

    return (
        request.get_json(
            silent=True
        )
        or
        {}
    )


def find_marksheet_pdf_path(
    marksheet_id: str,
) -> str:

    return os.path.join(
        GENERATED_MARKSHEETS_DIR,
        f"{marksheet_id}.pdf",
    )


# ============================================================
# BASIC NODE ROUTES
# ============================================================

@app.route(
    "/",
    methods=["GET"],
)
def home():

    return jsonify(
        {
            "service":
                "AnswerChain Blockchain Node",

            "node_id":
                NODE_ID,

            "port":
                PORT,

            "status":
                "running",
        }
    )


@app.route(
    "/node",
    methods=["GET"],
)
def node_info():

    return jsonify(
        {
            "node_id":
                NODE_ID,

            "port":
                PORT,

            "blocks":
                len(
                    blockchain.chain
                ),

            "pending_transactions":
                len(
                    blockchain.pending_transactions
                ),

            "peers":
                sorted(
                    blockchain.peers
                ),

            "chain_valid":
                blockchain.is_valid_chain(
                    blockchain.chain
                ),
        }
    )


@app.route(
    "/peers",
    methods=["GET"],
)
def get_peers():

    return jsonify(
        {
            "node_id":
                NODE_ID,

            "peers":
                sorted(
                    blockchain.peers
                ),
        }
    )


@app.route(
    "/peers",
    methods=["POST"],
)
def add_peer():

    data = require_json()

    peer = str(
        data.get(
            "peer",
            "",
        )
    ).strip()

    if not peer:

        return jsonify(
            {
                "error":
                    "Peer address is required."
            }
        ), 400

    if (
        peer
        ==
        f"127.0.0.1:{PORT}"
    ):

        return jsonify(
            {
                "error":
                    "A node cannot add itself as a peer."
            }
        ), 400

    blockchain.peers.add(
        peer
    )

    return jsonify(
        {
            "message":
                "Peer added",

            "node_id":
                NODE_ID,

            "peers":
                sorted(
                    blockchain.peers
                ),
        }
    )


# ============================================================
# GENERIC TRANSACTION
# ============================================================

@app.route(
    "/transaction",
    methods=["POST"],
)
def create_transaction():

    data = require_json()

    if not data:

        return jsonify(
            {
                "error":
                    "Transaction data is required."
            }
        ), 400

    transaction = (
        add_and_broadcast_transaction(
            data
        )
    )

    return jsonify(
        {
            "message":
                "Transaction added",

            "node_id":
                NODE_ID,

            "transaction":
                transaction,
        }
    )


# ============================================================
# RECEIVE TRANSACTION
# ============================================================

@app.route(
    "/receive-transaction",
    methods=["POST"],
)
def receive_transaction():

    body = require_json()

    transaction = (
        body.get(
            "transaction"
        )
    )

    if not isinstance(
        transaction,
        dict,
    ):

        return jsonify(
            {
                "error":
                    "Transaction missing."
            }
        ), 400

    transaction_id = (
        transaction.get(
            "transaction_id"
        )
    )

    if not transaction_id:

        return jsonify(
            {
                "error":
                    "Transaction ID missing."
            }
        ), 400

    if any(
        item.get(
            "transaction_id"
        )
        ==
        transaction_id
        for item in (
            blockchain.pending_transactions
        )
    ):

        return jsonify(
            {
                "message":
                    "Transaction already exists."
            }
        )

    blockchain.pending_transactions.append(
        transaction
    )

    return jsonify(
        {
            "message":
                "Transaction received",

            "node_id":
                NODE_ID,
        }
    )


# ============================================================
# MINE
# ============================================================

@app.route(
    "/mine",
    methods=["POST"],
)
def mine():

    if not blockchain.pending_transactions:

        return jsonify(
            {
                "message":
                    "No pending transactions.",

                "node_id":
                    NODE_ID,
            }
        )

    transactions = deepcopy(
        blockchain.pending_transactions
    )

    block = (
        blockchain.add_block(
            transactions
        )
    )

    blockchain.broadcast_block(
        block
    )

    return jsonify(
        {
            "message":
                "Block created",

            "node_id":
                NODE_ID,

            "block":
                block,
        }
    )


# ============================================================
# RECEIVE BLOCK
# ============================================================

@app.route(
    "/receive-block",
    methods=["POST"],
)
def receive_block():

    body = require_json()

    block = body.get(
        "block"
    )

    if not isinstance(
        block,
        dict,
    ):

        return jsonify(
            {
                "error":
                    "Block missing."
            }
        ), 400

    required = (
        "index",
        "timestamp",
        "data",
        "previous_hash",
        "hash",
    )

    if not all(
        key in block
        for key in required
    ):

        return jsonify(
            {
                "message":
                    "Block rejected",

                "reason":
                    "Block fields are incomplete.",
            }
        ), 400

    latest_block = (
        blockchain.chain[-1]
    )

    if (
        block["index"]
        !=
        latest_block["index"] + 1
    ):

        return jsonify(
            {
                "message":
                    "Block rejected",

                "reason":
                    "Block index is not the next index.",
            }
        ), 409

    if (
        block["previous_hash"]
        !=
        latest_block["hash"]
    ):

        return jsonify(
            {
                "message":
                    "Block rejected",

                "reason":
                    "Previous hash mismatch.",
            }
        ), 409

    calculated_hash = (
        blockchain.calculate_hash(
            block["index"],
            block["timestamp"],
            block["data"],
            block["previous_hash"],
        )
    )

    if (
        calculated_hash
        !=
        block["hash"]
    ):

        return jsonify(
            {
                "message":
                    "Block rejected",

                "reason":
                    "Invalid block hash.",
            }
        ), 409

    blockchain.chain.append(
        block
    )

    blockchain.pending_transactions = []

    blockchain.save_chain()

    return jsonify(
        {
            "message":
                "Block accepted",

            "node_id":
                NODE_ID,
        }
    )


# ============================================================
# CHAIN
# ============================================================

@app.route(
    "/chain",
    methods=["GET"],
)
def get_chain():

    return jsonify(
        {
            "node_id":
                NODE_ID,

            "chain":
                blockchain.chain,
        }
    )


# ============================================================
# CONSENSUS
# ============================================================

@app.route(
    "/consensus",
    methods=["POST"],
)
def run_consensus():

    result = (
        blockchain.consensus()
    )

    return jsonify(
        {
            "message":
                "Consensus completed",

            "node_id":
                NODE_ID,

            "blocks":
                len(
                    blockchain.chain
                ),

            "chain_valid":
                blockchain.is_valid_chain(
                    blockchain.chain
                ),

            "replaced":
                result[
                    "replaced"
                ],

            "source_node":
                result[
                    "source_node"
                ],
        }
    )


# ============================================================
# ANSWER SCRIPT REGISTRATION
# ============================================================

@app.route(
    "/answer-scripts/register",
    methods=["POST"],
)
def register_answer_script():

    data = require_json()

    required_fields = [
        "university",
        "exam_id",
        "answer_script_id",
        "file_name",
        "file_hash",
    ]

    for field in required_fields:

        if not data.get(
            field
        ):

            return jsonify(
                {
                    "error":
                        f"{field} is required."
                }
            ), 400

    answer_script_id = str(
        data[
            "answer_script_id"
        ]
    )

    if blockchain.transaction_exists(
        "ANSWER_SCRIPT_REGISTERED",
        "answer_script_id",
        answer_script_id,
    ):

        return jsonify(
            {
                "answer_script_id":
                    answer_script_id,

                "error":
                    "Answer script already registered.",
            }
        ), 409

    transaction_data = {

        "type":
            "ANSWER_SCRIPT_REGISTERED",

        "university":
            data[
                "university"
            ],

        "exam_id":
            data[
                "exam_id"
            ],

        "answer_script_id":
            answer_script_id,

        "file_name":
            data[
                "file_name"
            ],

        "answer_script_hash":
            data[
                "file_hash"
            ],
    }

    transaction = (
        add_and_broadcast_transaction(
            transaction_data
        )
    )

    return jsonify(
        {
            "message":
                "Answer script registered.",

            "transaction":
                transaction,
        }
    )


# ============================================================
# TEACHER ASSIGNMENT
# ============================================================

@app.route(
    "/answer-scripts/assign",
    methods=["POST"],
)
def assign_answer_script():

    data = require_json()

    answer_script_id = data.get(
        "answer_script_id"
    )

    teacher_id = data.get(
        "teacher_id"
    )

    assigned_by = data.get(
        "assigned_by"
    )

    if not answer_script_id:

        return jsonify(
            {
                "error":
                    "answer_script_id is required."
            }
        ), 400

    if not teacher_id:

        return jsonify(
            {
                "error":
                    "teacher_id is required."
            }
        ), 400

    if not assigned_by:

        return jsonify(
            {
                "error":
                    "assigned_by is required."
            }
        ), 400

    registered = (
        blockchain.find_transaction(
            "ANSWER_SCRIPT_REGISTERED",
            "answer_script_id",
            answer_script_id,
        )
    )

    if not registered:

        return jsonify(
            {
                "error":
                    "Answer script does not exist."
            }
        ), 404

    existing = (
        blockchain.find_transaction(
            "ANSWER_SCRIPT_ASSIGNED",
            "answer_script_id",
            answer_script_id,
        )
    )

    if existing:

        return jsonify(
            {
                "error":
                    "Answer script is already assigned."
            }
        ), 409

    transaction_data = {

        "type":
            "ANSWER_SCRIPT_ASSIGNED",

        "answer_script_id":
            answer_script_id,

        "teacher_id":
            teacher_id,

        "assigned_by":
            assigned_by,

        "status":
            "ASSIGNED",
    }

    transaction = (
        add_and_broadcast_transaction(
            transaction_data
        )
    )

    return jsonify(
        {
            "message":
                "Answer script assigned to teacher.",

            "transaction":
                transaction,
        }
    )


# ============================================================
# EVALUATION
# ============================================================

@app.route(
    "/evaluations/submit",
    methods=["POST"],
)
def submit_evaluation():

    data = require_json()

    answer_script_id = data.get(
        "answer_script_id"
    )

    teacher_id = data.get(
        "teacher_id"
    )

    marks = data.get(
        "marks"
    )

    max_marks = data.get(
        "max_marks"
    )

    if not answer_script_id:

        return jsonify(
            {
                "error":
                    "answer_script_id is required."
            }
        ), 400

    if not teacher_id:

        return jsonify(
            {
                "error":
                    "teacher_id is required."
            }
        ), 400

    if marks is None:

        return jsonify(
            {
                "error":
                    "marks is required."
            }
        ), 400

    if max_marks is None:

        return jsonify(
            {
                "error":
                    "max_marks is required."
            }
        ), 400

    try:

        marks = float(
            marks
        )

        max_marks = float(
            max_marks
        )

    except (
        TypeError,
        ValueError,
    ):

        return jsonify(
            {
                "error":
                    "Marks must be numeric."
            }
        ), 400

    if max_marks <= 0:

        return jsonify(
            {
                "error":
                    "max_marks must be greater than zero."
            }
        ), 400

    if (
        marks < 0
        or
        marks > max_marks
    ):

        return jsonify(
            {
                "error":
                    "Invalid marks."
            }
        ), 400

    assignment = (
        blockchain.find_transaction(
            "ANSWER_SCRIPT_ASSIGNED",
            "answer_script_id",
            answer_script_id,
        )
    )

    if not assignment:

        return jsonify(
            {
                "error":
                    "Answer script is not assigned."
            }
        ), 404

    assignment_data = (
        assignment.get(
            "data",
            {}
        )
    )

    if (
        assignment_data.get(
            "teacher_id"
        )
        !=
        teacher_id
    ):

        return jsonify(
            {
                "error":
                    "This teacher is not assigned to this answer script."
            }
        ), 403

    if blockchain.transaction_exists(
        "EVALUATION_SUBMITTED",
        "answer_script_id",
        answer_script_id,
    ):

        return jsonify(
            {
                "error":
                    "Evaluation already submitted."
            }
        ), 409

    evaluation_id = (
        "EVAL-"
        +
        hashlib.sha256(
            (
                answer_script_id
                +
                str(teacher_id)
                +
                str(marks)
                +
                str(time.time())
            ).encode(
                "utf-8"
            )
        ).hexdigest()[
            :12
        ].upper()
    )

    transaction_data = {

        "type":
            "EVALUATION_SUBMITTED",

        "evaluation_id":
            evaluation_id,

        "answer_script_id":
            answer_script_id,

        "teacher_id":
            teacher_id,

        "marks":
            marks,

        "max_marks":
            max_marks,

        "status":
            "SUBMITTED",
    }

    transaction = (
        add_and_broadcast_transaction(
            transaction_data
        )
    )

    return jsonify(
        {
            "message":
                "Evaluation submitted.",

            "evaluation":
                transaction,
        }
    )


# ============================================================
# RESULT FINALIZATION
# ============================================================

@app.route(
    "/results/finalize",
    methods=["POST"],
)
def finalize_result():

    data = require_json()

    answer_script_id = data.get(
        "answer_script_id"
    )

    authority_id = data.get(
        "authority_id"
    )

    if not answer_script_id:

        return jsonify(
            {
                "error":
                    "answer_script_id is required."
            }
        ), 400

    if not authority_id:

        return jsonify(
            {
                "error":
                    "authority_id is required."
            }
        ), 400

    evaluation = (
        blockchain.find_transaction(
            "EVALUATION_SUBMITTED",
            "answer_script_id",
            answer_script_id,
        )
    )

    if not evaluation:

        return jsonify(
            {
                "error":
                    "No evaluation found."
            }
        ), 404

    existing_result = (
        blockchain.find_transaction(
            "RESULT_FINALIZED",
            "answer_script_id",
            answer_script_id,
        )
    )

    if existing_result:

        return jsonify(
            {
                "error":
                    "Result is already finalized.",

                "result":
                    existing_result,
            }
        ), 409

    evaluation_data = (
        evaluation.get(
            "data",
            {}
        )
    )

    result_id = (
        "RESULT-"
        +
        hashlib.sha256(
            (
                answer_script_id
                +
                evaluation_data[
                    "evaluation_id"
                ]
                +
                str(
                    authority_id
                )
            ).encode(
                "utf-8"
            )
        ).hexdigest()[
            :12
        ].upper()
    )

    transaction_data = {

        "type":
            "RESULT_FINALIZED",

        "result_id":
            result_id,

        "answer_script_id":
            answer_script_id,

        "evaluation_id":
            evaluation_data[
                "evaluation_id"
            ],

        "authority_id":
            authority_id,

        "final_marks":
            evaluation_data[
                "marks"
            ],

        "max_marks":
            evaluation_data[
                "max_marks"
            ],

        "status":
            "FINALIZED",
    }

    transaction = (
        add_and_broadcast_transaction(
            transaction_data
        )
    )

    return jsonify(
        {
            "message":
                "Result finalized successfully.",

            "result":
                transaction,
        }
    )


# ============================================================
# MARKSHEET GENERATION + PDF
# ============================================================

@app.route(
    "/marksheets/generate",
    methods=["POST"],
)
def generate_marksheet_endpoint():

    data = require_json()

    answer_script_id = data.get(
        "answer_script_id"
    )

    student_id = data.get(
        "student_id",
        "STUDENT-001",
    )

    student_name = data.get(
        "student_name",
        "Student",
    )

    university = data.get(
        "university",
        "TINT",
    )

    exam_name = data.get(
        "exam_name",
        "University Examination",
    )

    if not answer_script_id:

        return jsonify(
            {
                "error":
                    "answer_script_id is required."
            }
        ), 400

    finalized_result = (
        blockchain.find_transaction(
            "RESULT_FINALIZED",
            "answer_script_id",
            answer_script_id,
        )
    )

    if not finalized_result:

        return jsonify(
            {
                "error":
                    "Marksheet cannot be generated. No finalized result exists."
            }
        ), 403

    result_data = (
        finalized_result.get(
            "data",
            {}
        )
    )

    if (
        result_data.get(
            "status"
        )
        !=
        "FINALIZED"
    ):

        return jsonify(
            {
                "error":
                    "Only finalized results can generate marksheets."
            }
        ), 403

    existing_marksheet = (
        blockchain.find_transaction(
            "MARKSHEET_REGISTERED",
            "answer_script_id",
            answer_script_id,
        )
    )

    existing_pending_marksheet = (
        blockchain.find_pending_transaction(
            "MARKSHEET_REGISTERED",
            "answer_script_id",
            answer_script_id,
        )
    )

    if (
        existing_marksheet
        or
        existing_pending_marksheet
    ):

        existing = (
            existing_marksheet
            or
            existing_pending_marksheet
        )

        return jsonify(
            {
                "message":
                    "Marksheet already exists or is pending.",

                "marksheet":
                    existing,
            }
        ), 409

    marksheet = generate_marksheet(
        student_id=student_id,
        student_name=student_name,
        university=university,
        exam_name=exam_name,
        answer_script_id=answer_script_id,
        result_id=result_data[
            "result_id"
        ],
        evaluation_id=result_data[
            "evaluation_id"
        ],
        final_marks=result_data[
            "final_marks"
        ],
        max_marks=result_data[
            "max_marks"
        ],
    )

    # Hash the logical marksheet data.
    marksheet_data_hash = (
        calculate_marksheet_hash(
            marksheet
        )
    )

    marksheet_id = (
        "MARKSHEET-"
        +
        hashlib.sha256(
            (
                answer_script_id
                +
                result_data[
                    "result_id"
                ]
                +
                marksheet_data_hash
            ).encode(
                "utf-8"
            )
        ).hexdigest()[
            :12
        ].upper()
    )

    # Generate the final PDF first.
    #
    # The resulting PDF bytes are hashed after creation.
    # That PDF hash is then stored on the blockchain.

    pdf_info = generate_marksheet_pdf(
        marksheet=marksheet,
        marksheet_id=marksheet_id,
    )

    pdf_path = pdf_info[
        "pdf_path"
    ]

    pdf_filename = pdf_info[
        "pdf_filename"
    ]

    marksheet_pdf_hash = pdf_info[
        "pdf_hash"
    ]

    transaction_data = {

        "type":
            "MARKSHEET_REGISTERED",

        "marksheet_id":
            marksheet_id,

        "student_id":
            student_id,

        "student_name":
            student_name,

        "university":
            university,

        "exam_name":
            exam_name,

        "answer_script_id":
            answer_script_id,

        "result_id":
            result_data[
                "result_id"
            ],

        "evaluation_id":
            result_data[
                "evaluation_id"
            ],

        "marksheet_data_hash":
            marksheet_data_hash,

        "marksheet_pdf_hash":
            marksheet_pdf_hash,

        "pdf_filename":
            pdf_filename,

        "final_marks":
            result_data[
                "final_marks"
            ],

        "max_marks":
            result_data[
                "max_marks"
            ],

        "percentage":
            marksheet[
                "percentage"
            ],

        "status":
            "REGISTERED",
    }

    transaction = (
        add_and_broadcast_transaction(
            transaction_data
        )
    )

    return jsonify(
        {
            "message":
                "Marksheet generated and registered.",

            "marksheet_id":
                marksheet_id,

            "marksheet":
                marksheet,

            "marksheet_data_hash":
                marksheet_data_hash,

            "marksheet_pdf_hash":
                marksheet_pdf_hash,

            "pdf_filename":
                pdf_filename,

            "pdf_path":
                pdf_path,

            "transaction":
                transaction,

            "note":
                "Mine this node's pending transaction to commit the marksheet registration block.",
        }
    )


# ============================================================
# LOGICAL MARKSHEET VERIFICATION
# ============================================================

@app.route(
    "/marksheets/verify",
    methods=["POST"],
)
def verify_marksheet():

    data = require_json()

    marksheet_id = data.get(
        "marksheet_id"
    )

    marksheet_hash = data.get(
        "marksheet_hash"
    )

    if (
        not marksheet_id
        and
        not marksheet_hash
    ):

        return jsonify(
            {
                "error":
                    "Provide marksheet_id or marksheet_hash."
            }
        ), 400

    transaction = (
        None
    )

    if marksheet_id:

        transaction = (
            blockchain.find_transaction(
                "MARKSHEET_REGISTERED",
                "marksheet_id",
                marksheet_id,
            )
        )

    else:

        for item in blockchain.find_transactions(
            "MARKSHEET_REGISTERED"
        ):

            item_data = item.get(
                "data",
                {}
            )

            if (
                item_data.get(
                    "marksheet_data_hash"
                )
                ==
                marksheet_hash
            ):

                transaction = item
                break

            # Backward compatibility with the old field.
            if (
                item_data.get(
                    "marksheet_hash"
                )
                ==
                marksheet_hash
            ):

                transaction = item
                break

    if not transaction:

        return jsonify(
            {
                "verified":
                    False,

                "message":
                    "Marksheet not found on blockchain.",
            }
        )

    transaction_data = (
        transaction.get(
            "data",
            {}
        )
    )

    result_id = (
        transaction_data.get(
            "result_id"
        )
    )

    result = (
        blockchain.find_transaction(
            "RESULT_FINALIZED",
            "result_id",
            result_id,
        )
    )

    if not result:

        return jsonify(
            {
                "verified":
                    False,

                "message":
                    "Referenced finalized result does not exist.",
            }
        )

    result_data = (
        result.get(
            "data",
            {}
        )
    )

    if (
        result_data.get(
            "status"
        )
        !=
        "FINALIZED"
    ):

        return jsonify(
            {
                "verified":
                    False,

                "message":
                    "Referenced result is not finalized.",
            }
        )

    reconstructed_marksheet = (
        generate_marksheet(
            student_id=transaction_data[
                "student_id"
            ],

            student_name=transaction_data.get(
                "student_name",
                "Student",
            ),

            university=transaction_data.get(
                "university",
                "TINT",
            ),

            exam_name=transaction_data.get(
                "exam_name",
                "University Examination",
            ),

            answer_script_id=transaction_data[
                "answer_script_id"
            ],

            result_id=transaction_data[
                "result_id"
            ],

            evaluation_id=transaction_data[
                "evaluation_id"
            ],

            final_marks=transaction_data[
                "final_marks"
            ],

            max_marks=transaction_data[
                "max_marks"
            ],
        )
    )

    calculated_data_hash = (
        calculate_marksheet_hash(
            reconstructed_marksheet
        )
    )

    stored_data_hash = (
        transaction_data.get(
            "marksheet_data_hash",
            transaction_data.get(
                "marksheet_hash"
            ),
        )
    )

    data_hash_matches = (
        verify_marksheet_hash(
            reconstructed_marksheet,
            stored_data_hash
            or
            "",
        )
    )

    return jsonify(
        {
            "verified":
                bool(
                    data_hash_matches
                ),

            "message":
                (
                    "Marksheet verified successfully."
                    if data_hash_matches
                    else
                    "Marksheet hash verification failed."
                ),

            "marksheet":
                transaction_data,

            "stored_hash":
                stored_data_hash,

            "calculated_hash":
                calculated_data_hash,

            "result":
                result_data,

            "blockchain_transaction":
                transaction,
        }
    )


# ============================================================
# MARKSHEET PDF DOWNLOAD
# ============================================================

@app.route(
    "/marksheets/<marksheet_id>/pdf",
    methods=["GET"],
)
def download_marksheet_pdf(
    marksheet_id: str,
):

    transaction = (
        blockchain.find_transaction(
            "MARKSHEET_REGISTERED",
            "marksheet_id",
            marksheet_id,
        )
    )

    if not transaction:

        return jsonify(
            {
                "error":
                    "Marksheet not found on blockchain."
            }
        ), 404

    pdf_path = (
        find_marksheet_pdf_path(
            marksheet_id
        )
    )

    if not os.path.isfile(
        pdf_path
    ):

        return jsonify(
            {
                "error":
                    "Marksheet PDF is not available on this node.",

                "node_id":
                    NODE_ID,

                "marksheet_id":
                    marksheet_id,
            }
        ), 404

    return send_file(
        pdf_path,
        mimetype="application/pdf",
        as_attachment=True,
        download_name=(
            f"{marksheet_id}.pdf"
        ),
    )


# ============================================================
# MARKSHEET PDF VERIFICATION
# ============================================================

@app.route(
    "/marksheets/<marksheet_id>/verify-pdf",
    methods=["POST"],
)
def verify_marksheet_pdf(
    marksheet_id: str,
):

    transaction = (
        blockchain.find_transaction(
            "MARKSHEET_REGISTERED",
            "marksheet_id",
            marksheet_id,
        )
    )

    if not transaction:

        return jsonify(
            {
                "verified":
                    False,

                "message":
                    "Marksheet not found on blockchain.",
            }
        ), 404

    transaction_data = (
        transaction.get(
            "data",
            {}
        )
    )

    stored_pdf_hash = (
        transaction_data.get(
            "marksheet_pdf_hash"
        )
    )

    # Old marksheets created before PDF hash support
    # do not have this field.

    if not stored_pdf_hash:

        return jsonify(
            {
                "verified":
                    False,

                "message":
                    (
                        "This marksheet was registered before "
                        "PDF hash support and has no on-chain PDF hash."
                    ),

                "marksheet_id":
                    marksheet_id,
            }
        )

    pdf_path = (
        find_marksheet_pdf_path(
            marksheet_id
        )
    )

    if not os.path.isfile(
        pdf_path
    ):

        return jsonify(
            {
                "verified":
                    False,

                "message":
                    "PDF file is not available on this node.",

                "marksheet_id":
                    marksheet_id,

                "stored_pdf_hash":
                    stored_pdf_hash,
            }
        ), 404

    calculated_pdf_hash = (
        calculate_pdf_hash(
            pdf_path
        )
    )

    verified = (
        verify_pdf_hash(
            pdf_path,
            stored_pdf_hash,
        )
    )

    return jsonify(
        {
            "verified":
                bool(
                    verified
                ),

            "message":
                (
                    "PDF integrity verified successfully."
                    if verified
                    else
                    "PDF integrity verification failed."
                ),

            "marksheet_id":
                marksheet_id,

            "pdf_filename":
                transaction_data.get(
                    "pdf_filename"
                ),

            "stored_pdf_hash":
                stored_pdf_hash,

            "calculated_pdf_hash":
                calculated_pdf_hash,

            "pdf_path":
                pdf_path,

            "blockchain_transaction":
                transaction,
        }
    )


# ============================================================
# COMPLETE ANSWER SCRIPT HISTORY
# ============================================================

@app.route(
    "/answer-scripts/<answer_script_id>",
    methods=["GET"],
)
def get_answer_script(
    answer_script_id: str,
):

    result = {

        "answer_script":
            blockchain.find_transaction(
                "ANSWER_SCRIPT_REGISTERED",
                "answer_script_id",
                answer_script_id,
            ),

        "assignment":
            blockchain.find_transaction(
                "ANSWER_SCRIPT_ASSIGNED",
                "answer_script_id",
                answer_script_id,
            ),

        "evaluation":
            blockchain.find_transaction(
                "EVALUATION_SUBMITTED",
                "answer_script_id",
                answer_script_id,
            ),

        "final_result":
            blockchain.find_transaction(
                "RESULT_FINALIZED",
                "answer_script_id",
                answer_script_id,
            ),

        "marksheet":
            blockchain.find_transaction(
                "MARKSHEET_REGISTERED",
                "answer_script_id",
                answer_script_id,
            ),
    }

    if not any(
        result.values()
    ):

        return jsonify(
            {
                "error":
                    "Answer script not found."
            }
        ), 404

    return jsonify(
        result
    )


# ============================================================
# BLOCKCHAIN
# ============================================================

@app.route(
    "/blockchain",
    methods=["GET"],
)
def get_blockchain():

    return jsonify(
        {
            "node_id":
                NODE_ID,

            "blocks":
                blockchain.chain,
        }
    )


# ============================================================
# RUN NODE
# ============================================================

if __name__ == "__main__":

    print()

    print(
        "=============================="
    )

    print(
        "     ANSWERCHAIN NODE"
    )

    print(
        "=============================="
    )

    print()

    print(
        f"Node ID : {NODE_ID}"
    )

    print(
        f"Port    : {PORT}"
    )

    print(
        f"Chain   : {CHAIN_FILE}"
    )

    print()

    app.run(
        host="127.0.0.1",
        port=PORT,
        debug=False,
    )