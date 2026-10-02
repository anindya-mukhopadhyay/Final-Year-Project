#!/usr/bin/env python3
"""
AnswerChain Development Keypair Generation Utility (Phase 8).

Generates local Ed25519 keypairs for demo institutional actors:
- UNIVERSITY (UNIV-001)
- TEACHERS (TCH-001, TCH-002, TCH-003, TCH-004)
- AUTHORITY (AUTH-001)
- ADMIN (ADMIN-001)

Saves PEM files to the local keys/ directory (excluded from Git).
NOTE: For production deployments, private keys MUST be protected by a
Hardware Security Module (HSM), Key Management Service (KMS), or Vault.
"""

import os
import sys

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from backend.crypto import (
    KEY_STORAGE_DIR,
    export_public_key_hex,
    generate_keypair,
    save_keypair,
)

ACTORS = [
    ("UNIV-001", "UNIVERSITY", "Techno International New Town (Registrar)"),
    ("TCH-001", "TEACHER", "Prof. Alex Mercer (CSE)"),
    ("TCH-002", "TEACHER", "Prof. Sarah Jenkins (IT)"),
    ("TCH-003", "TEACHER", "Prof. Ramesh Guha (ECE)"),
    ("TCH-004", "TEACHER", "Prof. David K. (CSE)"),
    ("AUTH-001", "AUTHORITY", "Dr. S. K. Mukherjee (Controller of Examinations)"),
    ("ADMIN-001", "ADMIN", "AnswerChain Security Operations"),
]


def main():
    print(f"=== Generating AnswerChain Development Keypairs in {KEY_STORAGE_DIR} ===")
    os.makedirs(KEY_STORAGE_DIR, exist_ok=True)

    for actor_id, role, name in ACTORS:
        priv, pub = generate_keypair()
        priv_path, pub_path = save_keypair(actor_id, priv, key_dir=KEY_STORAGE_DIR)
        pub_hex = export_public_key_hex(pub)
        print(f"  ✓ {role} [{actor_id}] ({name})")
        print(f"    Public Key (Hex): {pub_hex}")
        print(f"    Private: {os.path.basename(priv_path)} | Public: {os.path.basename(pub_path)}")

    print("\n[SECURITY NOTICE]")
    print("These keys are for local development and integration testing only.")
    print("Private keys are restricted to file mode 0600 and excluded from Git by .gitignore.")
    print("In production, private keys MUST be stored in a cloud KMS or HSM.")


if __name__ == "__main__":
    main()
