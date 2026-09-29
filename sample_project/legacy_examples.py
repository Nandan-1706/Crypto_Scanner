"""
Synthetic examples of the expanded Phase 1 detection targets: DES, 3DES,
DSA, DH, additional SHA-2 variants, and PyCryptodome library usage.
No real keys, credentials, or secrets - purely synthetic demonstration code.
"""

import hashlib

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dh, dsa
from cryptography.hazmat.primitives.ciphers import algorithms

from Crypto.Cipher import AES as PyCryptoAES  # PyCryptodome - library-level detection only


def make_dsa_key():
    """DSA key generation - quantum-vulnerable public-key signature algorithm."""
    return dsa.generate_private_key(key_size=2048)


def make_dh_parameters():
    """Finite-field Diffie-Hellman - quantum-vulnerable key establishment."""
    return dh.generate_parameters(generator=2, key_size=2048)


def describe_3des():
    """References the (disallowed) Triple DES cipher class."""
    return algorithms.TripleDES


def describe_des():
    """References the (broken, withdrawn) DES cipher class."""
    return algorithms.DES


def hash_with_sha384(data: bytes) -> str:
    return hashlib.sha384(data).hexdigest()


def hash_with_sha512(data: bytes) -> str:
    return hashlib.sha512(data).hexdigest()


def get_sha224_hasher():
    return hashes.SHA224()


def get_sha512_hasher():
    return hashes.SHA512()
