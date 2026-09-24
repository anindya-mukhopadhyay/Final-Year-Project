import hashlib
import json
import time


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


    def calculate_hash(self):

        block_data = {
            "index": self.index,
            "timestamp": self.timestamp,
            "file_name": self.file_name,
            "file_hash": self.file_hash,
            "previous_hash": self.previous_hash
        }

        block_string = json.dumps(
            block_data,
            sort_keys=True
        )

        return hashlib.sha256(
            block_string.encode()
        ).hexdigest()


class Blockchain:

    def __init__(self):

        self.chain = []

        self.create_genesis_block()


    def create_genesis_block(self):

        genesis_block = Block(
            index=0,
            timestamp=time.time(),
            file_name="GENESIS",
            file_hash="GENESIS",
            previous_hash="0"
        )

        self.chain.append(genesis_block)


    def add_answer_script(
        self,
        file_name,
        file_hash
    ):

        previous_block = self.chain[-1]

        new_block = Block(
            index=len(self.chain),
            timestamp=time.time(),
            file_name=file_name,
            file_hash=file_hash,
            previous_hash=previous_block.hash
        )

        self.chain.append(new_block)

        return new_block


    def get_chain(self):

        result = []

        for block in self.chain:

            result.append({

                "index": block.index,

                "timestamp": block.timestamp,

                "file_name": block.file_name,

                "file_hash": block.file_hash,

                "previous_hash": block.previous_hash,

                "hash": block.hash

            })

        return result