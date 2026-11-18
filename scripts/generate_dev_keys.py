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
    ("TCH-005", "TEACHER", "Prof. Elena Rostova (CSE)"),
    ("NODE-001", "NODE", "Examiner Node 1 Process"),
    ("NODE-002", "NODE", "Examiner Node 2 Process"),
    ("NODE-003", "NODE", "Examiner Node 3 Process"),
    ("NODE-004", "NODE", "Examiner Node 4 Process"),
    ("NODE-005", "NODE", "Examiner Node 5 Process"),
    ("AUTH-001", "AUTHORITY", "Dr. S. K. Mukherjee (Controller of Examinations)"),
    ("ADMIN-001", "ADMIN", "AnswerChain Security Operations"),
]


def generate_x509_pki(force: bool = False):
    """Generate local development X.509 Root CA and Institutional Signer certs if missing."""
    import datetime
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    ca_key_path = os.path.join(KEY_STORAGE_DIR, "answerchain_ca_key.pem")
    ca_cert_path = os.path.join(KEY_STORAGE_DIR, "answerchain_ca_cert.pem")
    auth_key_path = os.path.join(KEY_STORAGE_DIR, "authority_pdf_key.pem")
    auth_cert_path = os.path.join(KEY_STORAGE_DIR, "authority_pdf_cert.pem")

    if not force and os.path.isfile(ca_cert_path) and os.path.isfile(auth_cert_path):
        print(f"  ✓ Existing Root CA: {os.path.basename(ca_cert_path)} (preserved)")
        print(f"  ✓ Existing Signer:  {os.path.basename(auth_cert_path)} (preserved)")
        return

    # 1. AnswerChain Root CA
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca_subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "IN"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "AnswerChain Trust Network"),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "Root Authority"),
        x509.NameAttribute(NameOID.COMMON_NAME, "AnswerChain Root Certificate Authority"),
    ])
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(ca_subject)
        .issuer_name(ca_subject)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=1))
        .not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(x509.KeyUsage(digital_signature=True, key_cert_sign=True, crl_sign=True, content_commitment=False, key_encipherment=False, data_encipherment=False, key_agreement=False, encipher_only=False, decipher_only=False), critical=True)
        .sign(ca_key, hashes.SHA256())
    )

    ca_key_path = os.path.join(KEY_STORAGE_DIR, "answerchain_ca_key.pem")
    ca_cert_path = os.path.join(KEY_STORAGE_DIR, "answerchain_ca_cert.pem")
    with open(ca_key_path, "wb") as f:
        f.write(ca_key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    with open(ca_cert_path, "wb") as f:
        f.write(ca_cert.public_bytes(serialization.Encoding.PEM))
    print(f"  ✓ Root CA: {os.path.basename(ca_cert_path)} [CN: AnswerChain Root Certificate Authority]")

    # 2. Institutional Signer Certificate
    signer_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    signer_subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "IN"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "AnswerChain Authorized Institution"),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "Examination Authority"),
        x509.NameAttribute(NameOID.COMMON_NAME, "AnswerChain Examination Authority"),
    ])
    signer_cert = (
        x509.CertificateBuilder()
        .subject_name(signer_subject)
        .issuer_name(ca_subject)
        .public_key(signer_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=1))
        .not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=1825))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=True, key_encipherment=False, data_encipherment=False, key_agreement=False, key_cert_sign=False, crl_sign=False, encipher_only=False, decipher_only=False), critical=True)
        .sign(ca_key, hashes.SHA256())
    )

    auth_key_path = os.path.join(KEY_STORAGE_DIR, "authority_pdf_key.pem")
    auth_cert_path = os.path.join(KEY_STORAGE_DIR, "authority_pdf_cert.pem")
    with open(auth_key_path, "wb") as f:
        f.write(signer_key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    with open(auth_cert_path, "wb") as f:
        f.write(signer_cert.public_bytes(serialization.Encoding.PEM))
    print(f"  ✓ Signer:  {os.path.basename(auth_cert_path)} [CN: AnswerChain Examination Authority]")

    # 3. Untrusted test CA & Signer (for testing Rule 8: untrusted issuer)
    untrusted_ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    untrusted_ca_subj = x509.Name([
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Rogue Fake Cert Authority"),
        x509.NameAttribute(NameOID.COMMON_NAME, "Rogue Root CA"),
    ])
    untrusted_ca_cert = (
        x509.CertificateBuilder()
        .subject_name(untrusted_ca_subj)
        .issuer_name(untrusted_ca_subj)
        .public_key(untrusted_ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=1))
        .not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(untrusted_ca_key, hashes.SHA256())
    )
    untrusted_signer_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    untrusted_signer_subj = x509.Name([
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Untrusted Third Party"),
        x509.NameAttribute(NameOID.COMMON_NAME, "Fake Exam Signer"),
    ])
    untrusted_signer_cert = (
        x509.CertificateBuilder()
        .subject_name(untrusted_signer_subj)
        .issuer_name(untrusted_ca_subj)
        .public_key(untrusted_signer_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=1))
        .not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(untrusted_ca_key, hashes.SHA256())
    )
    with open(os.path.join(KEY_STORAGE_DIR, "untrusted_ca_cert.pem"), "wb") as f:
        f.write(untrusted_ca_cert.public_bytes(serialization.Encoding.PEM))
    with open(os.path.join(KEY_STORAGE_DIR, "untrusted_pdf_key.pem"), "wb") as f:
        f.write(untrusted_signer_key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    with open(os.path.join(KEY_STORAGE_DIR, "untrusted_pdf_cert.pem"), "wb") as f:
        f.write(untrusted_signer_cert.public_bytes(serialization.Encoding.PEM))
    print("  ✓ Untrusted Test Keys generated.")


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

    # Institutional X.509 PKI for PDF Digital Signatures
    print("\n=== Generating AnswerChain X.509 Institutional PKI (PAdES PDF Signatures) ===")
    generate_x509_pki()

    print("\n[SECURITY NOTICE]")
    print("These keys are for local development and integration testing only.")
    print("Private keys are restricted to file mode 0600 and excluded from Git by .gitignore.")
    print("In production, private keys MUST be stored in a cloud KMS or HSM.")


if __name__ == "__main__":
    main()
