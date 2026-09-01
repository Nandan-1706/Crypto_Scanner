"""
Modern, currently-recommended cryptography examples for testing the scanner.
No real keys, credentials, or secrets - purely synthetic demonstration code.
"""

import hashlib

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.ciphers import algorithms


def hash_with_sha256(data: bytes) -> str:
    """SHA-256 is a currently accepted hash algorithm."""
    return hashlib.sha256(data).hexdigest()


def make_modern_rsa_key():
    """A currently reasonable RSA key size - explicit key_size should be captured."""
    return rsa.generate_private_key(public_exponent=65537, key_size=3072)


def make_ec_key():
    """Elliptic curve key generation."""
    return ec.generate_private_key(ec.SECP256R1())


def get_sha256_hasher():
    return hashes.SHA256()


def describe_aes():
    """References the AES cipher algorithm class (not actually invoked)."""
    return algorithms.AES
