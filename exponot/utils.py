"""
Utility functions
"""

from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidKey


def hkdf_derive(input_key, salt, info, length, hash_algo) -> bytes:
    """Derive key using HKDF"""
    backend = default_backend()
    hkdf = HKDF(
        algorithm=hash_algo,
        length=length,
        salt=salt,
        info=info,
        backend=backend,
    )
    return hkdf.derive(input_key)


def hkdf_verify(input_key, salt, info, length, derived_key, hash_algo) -> bool:
    """Verify output of HKDF"""
    backend = default_backend()
    hkdf = HKDF(
        algorithm=hash_algo,
        length=length,
        salt=salt,
        info=info,
        backend=backend,
    )
    try:
        hkdf.verify(input_key, derived_key)
        return True
    except InvalidKey:
        return False
