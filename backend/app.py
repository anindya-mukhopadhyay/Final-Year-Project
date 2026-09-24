from flask import Flask, jsonify, request, send_from_directory
from flask_cors import CORS

import hashlib
import os

from blockchain import Blockchain


# --------------------------------
# Flask setup
# --------------------------------

app = Flask(
    __name__,
    static_folder="../frontend"
)

CORS(app)


# --------------------------------
# Create blockchain
# --------------------------------

blockchain = Blockchain()


# --------------------------------
# Home page
# --------------------------------

@app.route("/")
def home():

    return send_from_directory(
        "../frontend",
        "index.html"
    )


# --------------------------------
# Serve frontend files
# --------------------------------

@app.route("/<path:filename>")
def frontend_files(filename):

    return send_from_directory(
        "../frontend",
        filename
    )


# --------------------------------
# Upload answer script
# --------------------------------

@app.route(
    "/upload",
    methods=["POST"]
)
def upload_file():

    # Check whether file exists

    if "file" not in request.files:

        return jsonify({
            "error": "No file uploaded."
        }), 400


    file = request.files["file"]


    # Check filename

    if file.filename == "":

        return jsonify({
            "error": "No file selected."
        }), 400


    # Read file

    file_content = file.read()


    # Calculate SHA-256

    file_hash = hashlib.sha256(
        file_content
    ).hexdigest()


    # Add file to blockchain

    block = blockchain.add_answer_script(
        file_name=file.filename,
        file_hash=file_hash
    )


    # Return blockchain information

    return jsonify({

        "message":
            "Answer script registered successfully.",

        "file_name":
            file.filename,

        "file_hash":
            file_hash,

        "block": {

            "index":
                block.index,

            "timestamp":
                block.timestamp,

            "previous_hash":
                block.previous_hash,

            "hash":
                block.hash

        }

    })


# --------------------------------
# Verify answer script
# --------------------------------

@app.route(
    "/verify",
    methods=["POST"]
)
def verify_answer_script():

    if "file" not in request.files:

        return jsonify({
            "error": "No file uploaded."
        }), 400


    file = request.files["file"]


    if file.filename == "":

        return jsonify({
            "error": "No file selected."
        }), 400


    file_content = file.read()

    file_hash = hashlib.sha256(
        file_content
    ).hexdigest()

    verification = blockchain.verify_file(
        file_hash
    )

    if verification["verified"]:

        return jsonify({

            "verified": True,

            "message":
                "Answer script verified successfully.",

            "file_name":
                file.filename,

            "file_hash":
                file_hash,

            "block":
                verification["block"]

        })

    return jsonify({

        "verified": False,

        "message":
            "Answer script was not found in the blockchain.",

        "file_name":
            file.filename,

        "file_hash":
            file_hash,

        "block": None

    })


# --------------------------------
# Get entire blockchain
# --------------------------------

@app.route(
    "/blockchain",
    methods=["GET"]
)
def get_blockchain():

    return jsonify(
        blockchain.get_chain()
    )


# --------------------------------
# Run server
# --------------------------------

if __name__ == "__main__":

    port = int(os.environ.get("PORT", "5000"))
    app.run(
        host="127.0.0.1",
        port=port,
        debug=True
    )