import os
import sys
import json
import time
import hashlib
import requests
from copy import deepcopy

from flask import Flask, jsonify, request
from flask_cors import CORS


# ============================================================
# PROJECT ROOT
# ============================================================

PROJECT_ROOT = os.path.abspath(
    os.path.join(
        os.path.dirname(__file__),
        ".."
    )
)

if PROJECT_ROOT not in sys.path:

    sys.path.insert(
        0,
        PROJECT_ROOT
    )


# ============================================================
# BACKEND IMPORTS
# ============================================================

from backend.marksheet import (
    generate_marksheet,
    calculate_marksheet_hash,
    verify_marksheet_hash
)


# ============================================================
# CONFIGURATION
# ============================================================

NODE_ID = os.environ.get(
    "NODE_ID",
    "node-1"
)

PORT = int(
    os.environ.get(
        "NODE_PORT",
        "5001"
    )
)

DATA_DIR = os.path.join(
    PROJECT_ROOT,
    "blockchain_data"
)

os.makedirs(
    DATA_DIR,
    exist_ok=True
)

CHAIN_FILE = os.path.join(
    DATA_DIR,
    f"{NODE_ID}_blockchain.json"
)


# ============================================================
# FLASK
# ============================================================

app = Flask(__name__)

CORS(app)


# ============================================================
# BLOCKCHAIN
# ============================================================

class NodeBlockchain:

    def __init__(self):

        self.node_id = NODE_ID

        self.chain = []

        self.pending_transactions = []

        self.peers = set()

        self.load_chain()

        if not self.chain:

            self.create_genesis_block()


    # ========================================================
    # HASH
    # ========================================================

    def calculate_hash(
        self,
        index,
        timestamp,
        data,
        previous_hash
    ):

        block_string = (
            str(index)
            + str(timestamp)
            + json.dumps(
                data,
                sort_keys=True
            )
            + str(previous_hash)
        )

        return hashlib.sha256(
            block_string.encode()
        ).hexdigest()


    # ========================================================
    # GENESIS BLOCK
    # ========================================================

    def create_genesis_block(self):

        timestamp = time.time()

        data = {

            "type":
                "GENESIS",

            "node_id":
                self.node_id

        }

        block = {

            "index":
                0,

            "timestamp":
                timestamp,

            "data":
                data,

            "previous_hash":
                "0"

        }

        block["hash"] = self.calculate_hash(

            block["index"],

            block["timestamp"],

            block["data"],

            block["previous_hash"]

        )

        self.chain.append(
            block
        )

        self.save_chain()


    # ========================================================
    # SAVE BLOCKCHAIN
    # ========================================================

    def save_chain(self):

        with open(
            CHAIN_FILE,
            "w",
            encoding="utf-8"
        ) as file:

            json.dump(
                self.chain,
                file,
                indent=4
            )


    # ========================================================
    # LOAD BLOCKCHAIN
    # ========================================================

    def load_chain(self):

        if not os.path.exists(
            CHAIN_FILE
        ):

            return

        try:

            with open(
                CHAIN_FILE,
                "r",
                encoding="utf-8"
            ) as file:

                self.chain = json.load(
                    file
                )

        except (
            json.JSONDecodeError,
            OSError
        ):

            self.chain = []


    # ========================================================
    # ADD TRANSACTION
    # ========================================================

    def add_transaction(
        self,
        data
    ):

        timestamp = time.time()

        transaction_string = (

            json.dumps(
                data,
                sort_keys=True
            )

            + str(timestamp)

        )

        transaction_id = hashlib.sha256(
            transaction_string.encode()
        ).hexdigest()

        transaction = {

            "transaction_id":
                transaction_id,

            "timestamp":
                timestamp,

            "data":
                data

        }

        self.pending_transactions.append(
            transaction
        )

        return transaction


    # ========================================================
    # FIND TRANSACTION
    # ========================================================

    def find_transaction(
        self,
        transaction_type,
        field,
        value
    ):

        for block in self.chain:

            transactions = block.get(
                "data",
                []
            )

            if not isinstance(
                transactions,
                list
            ):

                continue

            for transaction in transactions:

                transaction_data = transaction.get(
                    "data",
                    {}
                )

                if (

                    transaction_data.get(
                        "type"
                    )
                    == transaction_type

                    and

                    transaction_data.get(
                        field
                    )
                    == value

                ):

                    return transaction

        return None


    # ========================================================
    # FIND ALL TRANSACTIONS
    # ========================================================

    def find_transactions(
        self,
        transaction_type
    ):

        results = []

        for block in self.chain:

            transactions = block.get(
                "data",
                []
            )

            if not isinstance(
                transactions,
                list
            ):

                continue

            for transaction in transactions:

                transaction_data = transaction.get(
                    "data",
                    {}
                )

                if transaction_data.get(
                    "type"
                ) == transaction_type:

                    results.append(
                        transaction
                    )

        return results


    # ========================================================
    # ADD BLOCK
    # ========================================================

    def add_block(
        self,
        transactions
    ):

        previous_block = self.chain[-1]

        index = (
            previous_block["index"]
            + 1
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
                previous_block["hash"]

        }

        block["hash"] = self.calculate_hash(

            block["index"],

            block["timestamp"],

            block["data"],

            block["previous_hash"]

        )

        self.chain.append(
            block
        )

        self.pending_transactions = []

        self.save_chain()

        return block


    # ========================================================
    # VALIDATE BLOCKCHAIN
    # ========================================================

    def is_valid_chain(
        self,
        chain
    ):

        if not chain:

            return False

        for index in range(
            1,
            len(chain)
        ):

            previous = chain[
                index - 1
            ]

            current = chain[
                index
            ]

            if (
                current["previous_hash"]
                != previous["hash"]
            ):

                return False

            calculated_hash = self.calculate_hash(

                current["index"],

                current["timestamp"],

                current["data"],

                current["previous_hash"]

            )

            if (
                calculated_hash
                != current["hash"]
            ):

                return False

        return True


    # ========================================================
    # REPLACE CHAIN
    # ========================================================

    def replace_chain(
        self,
        new_chain
    ):

        if len(new_chain) <= len(
            self.chain
        ):

            return False

        if not self.is_valid_chain(
            new_chain
        ):

            return False

        self.chain = deepcopy(
            new_chain
        )

        self.save_chain()

        return True


    # ========================================================
    # BROADCAST TRANSACTION
    # ========================================================

    def broadcast_transaction(
        self,
        transaction
    ):

        for peer in list(
            self.peers
        ):

            try:

                requests.post(

                    f"http://{peer}"
                    "/receive-transaction",

                    json={
                        "transaction":
                            transaction
                    },

                    timeout=2

                )

            except requests.RequestException:

                pass


    # ========================================================
    # BROADCAST BLOCK
    # ========================================================

    def broadcast_block(
        self,
        block
    ):

        for peer in list(
            self.peers
        ):

            try:

                requests.post(

                    f"http://{peer}"
                    "/receive-block",

                    json={
                        "block":
                            block
                    },

                    timeout=2

                )

            except requests.RequestException:

                pass


    # ========================================================
    # CONSENSUS
    # ========================================================

    def consensus(self):

        longest_chain = self.chain

        source_node = self.node_id

        for peer in list(
            self.peers
        ):

            try:

                response = requests.get(

                    f"http://{peer}"
                    "/chain",

                    timeout=2

                )

                if response.status_code != 200:

                    continue

                data = response.json()

                peer_chain = data.get(
                    "chain",
                    []
                )

                if (

                    len(peer_chain)
                    > len(longest_chain)

                    and

                    self.is_valid_chain(
                        peer_chain
                    )

                ):

                    longest_chain = peer_chain

                    source_node = peer

            except requests.RequestException:

                pass

        replaced = False

        if (
            len(longest_chain)
            > len(self.chain)
        ):

            replaced = self.replace_chain(
                longest_chain
            )

        return {

            "replaced":
                replaced,

            "source_node":
                source_node

        }


# ============================================================
# BLOCKCHAIN INSTANCE
# ============================================================

blockchain = NodeBlockchain()


# ============================================================
# HOME
# ============================================================

@app.route("/")
def home():

    return jsonify({

        "service":
            "AnswerChain Blockchain Node",

        "node_id":
            NODE_ID,

        "port":
            PORT,

        "status":
            "running"

    })


# ============================================================
# NODE INFORMATION
# ============================================================

@app.route(
    "/node",
    methods=["GET"]
)
def node_info():

    return jsonify({

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
            )

    })


# ============================================================
# PEERS
# ============================================================

@app.route(
    "/peers",
    methods=["GET"]
)
def get_peers():

    return jsonify({

        "node_id":
            NODE_ID,

        "peers":
            sorted(
                blockchain.peers
            )

    })


@app.route(
    "/peers",
    methods=["POST"]
)
def add_peer():

    data = request.get_json(
        silent=True
    ) or {}

    peer = data.get(
        "peer"
    )

    if not peer:

        return jsonify({

            "error":
                "Peer address is required."

        }), 400

    blockchain.peers.add(
        peer
    )

    return jsonify({

        "message":
            "Peer added",

        "node_id":
            NODE_ID,

        "peers":
            sorted(
                blockchain.peers
            )

    })


# ============================================================
# GENERIC TRANSACTION
# ============================================================

@app.route(
    "/transaction",
    methods=["POST"]
)
def create_transaction():

    data = request.get_json(
        silent=True
    ) or {}

    if not data:

        return jsonify({

            "error":
                "Transaction data is required."

        }), 400

    transaction = blockchain.add_transaction(
        data
    )

    blockchain.broadcast_transaction(
        transaction
    )

    return jsonify({

        "message":
            "Transaction added",

        "node_id":
            NODE_ID,

        "transaction":
            transaction

    })


# ============================================================
# RECEIVE TRANSACTION
# ============================================================

@app.route(
    "/receive-transaction",
    methods=["POST"]
)
def receive_transaction():

    body = request.get_json(
        silent=True
    ) or {}

    transaction = body.get(
        "transaction"
    )

    if not transaction:

        return jsonify({

            "error":
                "Transaction missing."

        }), 400

    transaction_id = transaction.get(
        "transaction_id"
    )

    for existing in (
        blockchain.pending_transactions
    ):

        if (
            existing.get(
                "transaction_id"
            )
            == transaction_id
        ):

            return jsonify({

                "message":
                    "Transaction already exists."

            })

    blockchain.pending_transactions.append(
        transaction
    )

    return jsonify({

        "message":
            "Transaction received",

        "node_id":
            NODE_ID

    })


# ============================================================
# MINE
# ============================================================

@app.route(
    "/mine",
    methods=["POST"]
)
def mine():

    if not blockchain.pending_transactions:

        return jsonify({

            "message":
                "No pending transactions.",

            "node_id":
                NODE_ID

        })

    transactions = deepcopy(
        blockchain.pending_transactions
    )

    block = blockchain.add_block(
        transactions
    )

    blockchain.broadcast_block(
        block
    )

    return jsonify({

        "message":
            "Block created",

        "node_id":
            NODE_ID,

        "block":
            block

    })


# ============================================================
# RECEIVE BLOCK
# ============================================================

@app.route(
    "/receive-block",
    methods=["POST"]
)
def receive_block():

    body = request.get_json(
        silent=True
    ) or {}

    block = body.get(
        "block"
    )

    if not block:

        return jsonify({

            "error":
                "Block missing."

        }), 400

    latest_block = blockchain.chain[-1]

    if (
        block["previous_hash"]
        != latest_block["hash"]
    ):

        return jsonify({

            "message":
                "Block rejected",

            "reason":
                "Previous hash mismatch."

        }), 409

    calculated_hash = blockchain.calculate_hash(

        block["index"],

        block["timestamp"],

        block["data"],

        block["previous_hash"]

    )

    if (
        calculated_hash
        != block["hash"]
    ):

        return jsonify({

            "message":
                "Block rejected",

            "reason":
                "Invalid block hash."

        }), 409

    blockchain.chain.append(
        block
    )

    blockchain.pending_transactions = []

    blockchain.save_chain()

    return jsonify({

        "message":
            "Block accepted",

        "node_id":
            NODE_ID

    })


# ============================================================
# CHAIN
# ============================================================

@app.route(
    "/chain",
    methods=["GET"]
)
def get_chain():

    return jsonify({

        "node_id":
            NODE_ID,

        "chain":
            blockchain.chain

    })


# ============================================================
# CONSENSUS
# ============================================================

@app.route(
    "/consensus",
    methods=["POST"]
)
def run_consensus():

    result = blockchain.consensus()

    return jsonify({

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
            result["replaced"],

        "source_node":
            result["source_node"]

    })


# ============================================================
# ANSWER SCRIPT REGISTRATION
# ============================================================

@app.route(
    "/answer-scripts/register",
    methods=["POST"]
)
def register_answer_script():

    data = request.get_json(
        silent=True
    ) or {}

    required_fields = [

        "university",
        "exam_id",
        "answer_script_id",
        "file_name",
        "file_hash"

    ]

    for field in required_fields:

        if not data.get(field):

            return jsonify({

                "error":
                    f"{field} is required."

            }), 400

    existing = blockchain.find_transaction(

        "ANSWER_SCRIPT_REGISTERED",

        "answer_script_id",

        data["answer_script_id"]

    )

    if existing:

        return jsonify({

            "answer_script_id":
                data["answer_script_id"],

            "error":
                "Answer script already registered."

        }), 409

    transaction_data = {

        "type":
            "ANSWER_SCRIPT_REGISTERED",

        "university":
            data["university"],

        "exam_id":
            data["exam_id"],

        "answer_script_id":
            data["answer_script_id"],

        "file_name":
            data["file_name"],

        "answer_script_hash":
            data["file_hash"]

    }

    transaction = blockchain.add_transaction(
        transaction_data
    )

    blockchain.broadcast_transaction(
        transaction
    )

    return jsonify({

        "message":
            "Answer script registered.",

        "transaction":
            transaction

    })


# ============================================================
# TEACHER ASSIGNMENT
# ============================================================

@app.route(
    "/answer-scripts/assign",
    methods=["POST"]
)
def assign_answer_script():

    data = request.get_json(
        silent=True
    ) or {}

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

        return jsonify({

            "error":
                "answer_script_id is required."

        }), 400

    if not teacher_id:

        return jsonify({

            "error":
                "teacher_id is required."

        }), 400

    if not assigned_by:

        return jsonify({

            "error":
                "assigned_by is required."

        }), 400

    registered = blockchain.find_transaction(

        "ANSWER_SCRIPT_REGISTERED",

        "answer_script_id",

        answer_script_id

    )

    if not registered:

        return jsonify({

            "error":
                "Answer script does not exist."

        }), 404

    existing = blockchain.find_transaction(

        "ANSWER_SCRIPT_ASSIGNED",

        "answer_script_id",

        answer_script_id

    )

    if existing:

        return jsonify({

            "error":
                "Answer script is already assigned."

        }), 409

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
            "ASSIGNED"

    }

    transaction = blockchain.add_transaction(
        transaction_data
    )

    blockchain.broadcast_transaction(
        transaction
    )

    return jsonify({

        "message":
            "Answer script assigned to teacher.",

        "transaction":
            transaction

    })


# ============================================================
# EVALUATION
# ============================================================

@app.route(
    "/evaluations/submit",
    methods=["POST"]
)
def submit_evaluation():

    data = request.get_json(
        silent=True
    ) or {}

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

        return jsonify({

            "error":
                "answer_script_id is required."

        }), 400

    if not teacher_id:

        return jsonify({

            "error":
                "teacher_id is required."

        }), 400

    if marks is None:

        return jsonify({

            "error":
                "marks is required."

        }), 400

    if max_marks is None:

        return jsonify({

            "error":
                "max_marks is required."

        }), 400

    try:

        marks = float(marks)

        max_marks = float(
            max_marks
        )

    except (
        TypeError,
        ValueError
    ):

        return jsonify({

            "error":
                "Marks must be numeric."

        }), 400

    if (
        marks < 0
        or
        marks > max_marks
    ):

        return jsonify({

            "error":
                "Invalid marks."

        }), 400

    assignment = blockchain.find_transaction(

        "ANSWER_SCRIPT_ASSIGNED",

        "answer_script_id",

        answer_script_id

    )

    if not assignment:

        return jsonify({

            "error":
                "Answer script is not assigned."

        }), 404

    assignment_data = assignment.get(
        "data",
        {}
    )

    if (
        assignment_data.get(
            "teacher_id"
        )
        != teacher_id
    ):

        return jsonify({

            "error":
                "This teacher is not assigned to this answer script."

        }), 403

    existing = blockchain.find_transaction(

        "EVALUATION_SUBMITTED",

        "answer_script_id",

        answer_script_id

    )

    if existing:

        return jsonify({

            "error":
                "Evaluation already submitted."

        }), 409

    evaluation_id = (

        "EVAL-"

        + hashlib.sha256(

            (

                answer_script_id
                + teacher_id
                + str(marks)
                + str(time.time())

            ).encode()

        ).hexdigest()[:12].upper()

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
            "SUBMITTED"

    }

    transaction = blockchain.add_transaction(
        transaction_data
    )

    blockchain.broadcast_transaction(
        transaction
    )

    return jsonify({

        "message":
            "Evaluation submitted.",

        "evaluation":
            transaction

    })


# ============================================================
# RESULT FINALIZATION
# ============================================================

@app.route(
    "/results/finalize",
    methods=["POST"]
)
def finalize_result():

    data = request.get_json(
        silent=True
    ) or {}

    answer_script_id = data.get(
        "answer_script_id"
    )

    authority_id = data.get(
        "authority_id"
    )

    if not answer_script_id:

        return jsonify({

            "error":
                "answer_script_id is required."

        }), 400

    if not authority_id:

        return jsonify({

            "error":
                "authority_id is required."

        }), 400

    evaluation = blockchain.find_transaction(

        "EVALUATION_SUBMITTED",

        "answer_script_id",

        answer_script_id

    )

    if not evaluation:

        return jsonify({

            "error":
                "No evaluation found."

        }), 404

    existing_result = blockchain.find_transaction(

        "RESULT_FINALIZED",

        "answer_script_id",

        answer_script_id

    )

    if existing_result:

        return jsonify({

            "error":
                "Result is already finalized.",

            "result":
                existing_result

        }), 409

    evaluation_data = evaluation.get(
        "data",
        {}
    )

    result_id = (

        "RESULT-"

        + hashlib.sha256(

            (

                answer_script_id
                + evaluation_data[
                    "evaluation_id"
                ]
                + authority_id

            ).encode()

        ).hexdigest()[:12].upper()

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
            "FINALIZED"

    }

    transaction = blockchain.add_transaction(
        transaction_data
    )

    blockchain.broadcast_transaction(
        transaction
    )

    return jsonify({

        "message":
            "Result finalized successfully.",

        "result":
            transaction

    })


# ============================================================
# MARKSHEET GENERATION
# ============================================================

@app.route(
    "/marksheets/generate",
    methods=["POST"]
)
def generate_marksheet_endpoint():

    data = request.get_json(
        silent=True
    ) or {}

    answer_script_id = data.get(
        "answer_script_id"
    )

    student_id = data.get(
        "student_id",
        "STUDENT-001"
    )

    student_name = data.get(
        "student_name",
        "Student"
    )

    university = data.get(
        "university",
        "TINT"
    )

    exam_name = data.get(
        "exam_name",
        "University Examination"
    )

    if not answer_script_id:

        return jsonify({

            "error":
                "answer_script_id is required."

        }), 400

    # --------------------------------------------------------
    # FIND FINALIZED RESULT
    # --------------------------------------------------------

    finalized_result = blockchain.find_transaction(

        "RESULT_FINALIZED",

        "answer_script_id",

        answer_script_id

    )

    if not finalized_result:

        return jsonify({

            "error":
                "Marksheet cannot be generated. No finalized result exists."

        }), 403

    result_data = finalized_result.get(
        "data",
        {}
    )

    if (
        result_data.get(
            "status"
        )
        != "FINALIZED"
    ):

        return jsonify({

            "error":
                "Only finalized results can generate marksheets."

        }), 403

    # --------------------------------------------------------
    # PREVENT DUPLICATE MARKSHEET
    # --------------------------------------------------------

    existing_marksheet = blockchain.find_transaction(

        "MARKSHEET_REGISTERED",

        "answer_script_id",

        answer_script_id

    )

    if existing_marksheet:

        return jsonify({

            "message":
                "Marksheet already exists.",

            "marksheet":
                existing_marksheet

        }), 409

    # --------------------------------------------------------
    # GENERATE MARKSHEET
    # --------------------------------------------------------

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
        ]

    )

    # --------------------------------------------------------
    # CALCULATE HASH
    # --------------------------------------------------------

    marksheet_hash = calculate_marksheet_hash(
        marksheet
    )

    # --------------------------------------------------------
    # CREATE MARKSHEET ID
    # --------------------------------------------------------

    marksheet_id = (

        "MARKSHEET-"

        + hashlib.sha256(

            (

                answer_script_id
                + result_data[
                    "result_id"
                ]
                + marksheet_hash

            ).encode()

        ).hexdigest()[:12].upper()

    )

    # --------------------------------------------------------
    # BLOCKCHAIN TRANSACTION
    # --------------------------------------------------------

    transaction_data = {

        "type":
            "MARKSHEET_REGISTERED",

        "marksheet_id":
            marksheet_id,

        "student_id":
            student_id,

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

        "marksheet_hash":
            marksheet_hash,

        "final_marks":
            result_data[
                "final_marks"
            ],

        "max_marks":
            result_data[
                "max_marks"
            ],

        "status":
            "REGISTERED"

    }

    transaction = blockchain.add_transaction(
        transaction_data
    )

    blockchain.broadcast_transaction(
        transaction
    )

    return jsonify({

        "message":
            "Marksheet generated and registered.",

        "marksheet_id":
            marksheet_id,

        "marksheet_hash":
            marksheet_hash,

        "marksheet":
            marksheet,

        "transaction":
            transaction

    })


# ============================================================
# MARKSHEET VERIFICATION
# ============================================================

@app.route(
    "/marksheets/verify",
    methods=["POST"]
)
def verify_marksheet():

    data = request.get_json(
        silent=True
    ) or {}

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

        return jsonify({

            "error":
                "Provide marksheet_id or marksheet_hash."

        }), 400

    transaction = None

    # --------------------------------------------------------
    # FIND BY ID
    # --------------------------------------------------------

    if marksheet_id:

        transaction = blockchain.find_transaction(

            "MARKSHEET_REGISTERED",

            "marksheet_id",

            marksheet_id

        )

    # --------------------------------------------------------
    # FIND BY HASH
    # --------------------------------------------------------

    else:

        transactions = blockchain.find_transactions(

            "MARKSHEET_REGISTERED"

        )

        for item in transactions:

            item_data = item.get(
                "data",
                {}
            )

            if (
                item_data.get(
                    "marksheet_hash"
                )
                == marksheet_hash
            ):

                transaction = item

                break

    if not transaction:

        return jsonify({

            "verified":
                False,

            "message":
                "Marksheet not found on blockchain."

        })

    transaction_data = transaction.get(
        "data",
        {}
    )

    # --------------------------------------------------------
    # VERIFY RESULT
    # --------------------------------------------------------

    result_id = transaction_data.get(
        "result_id"
    )

    result = blockchain.find_transaction(

        "RESULT_FINALIZED",

        "result_id",

        result_id

    )

    if not result:

        return jsonify({

            "verified":
                False,

            "message":
                "Referenced finalized result does not exist."

        })

    result_data = result.get(
        "data",
        {}
    )

    if (
        result_data.get(
            "status"
        )
        != "FINALIZED"
    ):

        return jsonify({

            "verified":
                False,

            "message":
                "Referenced result is not finalized."

        })

    # --------------------------------------------------------
    # VERIFY MARKSHEET HASH
    #
    # We reconstruct the original marksheet data.
    # --------------------------------------------------------

    reconstructed_marksheet = generate_marksheet(

        student_id=transaction_data[
            "student_id"
        ],

        student_name=(
            transaction_data.get(
                "student_name",
                "Student"
            )
        ),

        university=(
            transaction_data.get(
                "university",
                "TINT"
            )
        ),

        exam_name=(
            transaction_data.get(
                "exam_name",
                "University Examination"
            )
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
        ]

    )

    calculated_hash = calculate_marksheet_hash(
        reconstructed_marksheet
    )

    stored_hash = transaction_data.get(
        "marksheet_hash"
    )

    # The current transaction format stores
    # the blockchain hash. If the reconstructed
    # data matches, verification succeeds.
    hash_matches = (
        calculated_hash
        == stored_hash
    )

    return jsonify({

        "verified":
            bool(hash_matches),

        "message":
            (
                "Marksheet verified successfully."
                if hash_matches
                else
                "Marksheet hash verification failed."
            ),

        "marksheet":
            transaction_data,

        "stored_hash":
            stored_hash,

        "calculated_hash":
            calculated_hash,

        "result":
            result_data,

        "blockchain_transaction":
            transaction

    })


# ============================================================
# COMPLETE ANSWER-SCRIPT HISTORY
# ============================================================

@app.route(
    "/answer-scripts/<answer_script_id>",
    methods=["GET"]
)
def get_answer_script(
    answer_script_id
):

    result = {

        "answer_script":
            blockchain.find_transaction(

                "ANSWER_SCRIPT_REGISTERED",

                "answer_script_id",

                answer_script_id

            ),

        "assignment":
            blockchain.find_transaction(

                "ANSWER_SCRIPT_ASSIGNED",

                "answer_script_id",

                answer_script_id

            ),

        "evaluation":
            blockchain.find_transaction(

                "EVALUATION_SUBMITTED",

                "answer_script_id",

                answer_script_id

            ),

        "final_result":
            blockchain.find_transaction(

                "RESULT_FINALIZED",

                "answer_script_id",

                answer_script_id

            ),

        "marksheet":
            blockchain.find_transaction(

                "MARKSHEET_REGISTERED",

                "answer_script_id",

                answer_script_id

            )

    }

    if not any(
        result.values()
    ):

        return jsonify({

            "error":
                "Answer script not found."

        }), 404

    return jsonify(
        result
    )


# ============================================================
# BLOCKCHAIN
# ============================================================

@app.route(
    "/blockchain",
    methods=["GET"]
)
def get_blockchain():

    return jsonify({

        "node_id":
            NODE_ID,

        "blocks":
            blockchain.chain

    })


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

    print()

    app.run(

        host="127.0.0.1",

        port=PORT,

        debug=False

    )