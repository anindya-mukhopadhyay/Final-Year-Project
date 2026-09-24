import hashlib
import json
import os
from datetime import datetime, timezone


# --------------------------------
# Block
# --------------------------------

class Block:

    def __init__(
        self,
        index,
        timestamp,
        file_name,
        file_hash,
        previous_hash
    ):

        self.index = index

        self.timestamp = timestamp

        self.file_name = file_name

        self.file_hash = file_hash

        self.previous_hash = previous_hash

        self.hash = self.calculate_hash()


    # --------------------------------
    # Calculate block hash
    # --------------------------------

    def calculate_hash(self):

        block_data = (
            str(self.index)
            + str(self.timestamp)
            + str(self.file_name)
            + str(self.file_hash)
            + str(self.previous_hash)
        )

        return hashlib.sha256(
            block_data.encode("utf-8")
        ).hexdigest()


    # --------------------------------
    # Convert block to dictionary
    # --------------------------------

    def to_dict(self):

        return {

            "index": self.index,

            "timestamp": self.timestamp,

            "file_name": self.file_name,

            "file_hash": self.file_hash,

            "previous_hash": self.previous_hash,

            "hash": self.hash

        }


    # --------------------------------
    # Create block from dictionary
    # --------------------------------

    @classmethod
    def from_dict(cls, data):

        block = cls(
            index=data["index"],
            timestamp=data["timestamp"],
            file_name=data["file_name"],
            file_hash=data["file_hash"],
            previous_hash=data["previous_hash"]
        )

        # Preserve the stored hash

        block.hash = data["hash"]

        return block


# --------------------------------
# Blockchain
# --------------------------------

class Blockchain:

    def __init__(self):

        # Project root:
        #
        # AnswerChain-Python/
        #     backend/
        #     blockchain_data/
        #
        base_dir = os.path.dirname(
            os.path.dirname(
                os.path.abspath(__file__)
            )
        )


        self.data_directory = os.path.join(
            base_dir,
            "blockchain_data"
        )


        self.data_file = os.path.join(
            self.data_directory,
            "blockchain.json"
        )


        # Create blockchain_data folder

        os.makedirs(
            self.data_directory,
            exist_ok=True
        )


        # Load existing blockchain

        self.chain = self.load_chain()


        # If no blockchain exists,
        # create Genesis Block

        if len(self.chain) == 0:

            self.chain = [
                self.create_genesis_block()
            ]

            self.save_chain()


    # --------------------------------
    # Genesis block
    # --------------------------------

    def create_genesis_block(self):

        return Block(
            index=0,
            timestamp=datetime.now(
                timezone.utc
            ).isoformat(),
            file_name="GENESIS",
            file_hash="GENESIS",
            previous_hash="0"
        )


    # --------------------------------
    # Add answer script
    # --------------------------------

    def add_answer_script(
        self,
        file_name,
        file_hash
    ):

        previous_block = self.chain[-1]


        new_block = Block(

            index=previous_block.index + 1,

            timestamp=datetime.now(
                timezone.utc
            ).isoformat(),

            file_name=file_name,

            file_hash=file_hash,

            previous_hash=previous_block.hash

        )


        # Add block to chain

        self.chain.append(
            new_block
        )


        # IMPORTANT:
        # Save immediately

        self.save_chain()


        return new_block


    # --------------------------------
    # Save blockchain
    # --------------------------------

    def save_chain(self):

        data = [

            block.to_dict()

            for block in self.chain

        ]


        # Write safely to a temporary file first

        temporary_file = (
            self.data_file + ".tmp"
        )


        with open(
            temporary_file,
            "w",
            encoding="utf-8"
        ) as file:

            json.dump(
                data,
                file,
                indent=4
            )


        # Replace old blockchain file

        os.replace(
            temporary_file,
            self.data_file
        )


    # --------------------------------
    # Load blockchain
    # --------------------------------

    def load_chain(self):

        if not os.path.exists(
            self.data_file
        ):

            return []


        try:

            with open(
                self.data_file,
                "r",
                encoding="utf-8"
            ) as file:

                data = json.load(file)


            return [

                Block.from_dict(block)

                for block in data

            ]


        except (
            json.JSONDecodeError,
            KeyError,
            TypeError
        ):

            print(
                "Warning: blockchain.json is invalid."
            )

            print(
                "Starting a new blockchain."
            )

            return []


    # --------------------------------
    # Get blockchain
    # --------------------------------

    def get_chain(self):

        return [

            block.to_dict()

            for block in self.chain

        ]


    # --------------------------------
    # Verify answer script
    # --------------------------------

    def verify_file(
        self,
        file_hash
    ):

        for block in self.chain:

            if block.file_hash == file_hash:

                return {

                    "verified": True,

                    "block": block.to_dict()

                }


        return {

            "verified": False,

            "block": None

        }