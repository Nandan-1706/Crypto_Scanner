"""
Intentionally weak/legacy cryptography examples for testing the scanner.
No real keys, credentials, or secrets - purely synthetic demonstration code.
"""

import hashlib

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa


def hash_password_badly(password: str) -> str:
    """MD5 is cryptographically broken - this should be flagged as high risk."""
    return hashlib.md5(password.encode()).hexdigest()


def hash_with_sha1(data: bytes) -> str:
    """SHA-1 is deprecated for security-sensitive use."""
    return hashlib.sha1(data).hexdigest()


def make_small_rsa_key():
    """A small RSA key size - should be flagged for the explicit key_size."""
    return rsa.generate_private_key(public_exponent=65537, key_size=1024)


def get_md5_hasher():
    """Using the cryptography library's hazmat layer directly for MD5."""
    return hashes.MD5()
