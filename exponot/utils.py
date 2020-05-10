"""
Utility functions
"""

from datetime import datetime

from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidKey


def mkdt(input) -> datetime:
    """Convert to datetime"""
    if isinstance(input, datetime):
        return input

    if isinstance(input, int):
        if input < 0:
            raise ValueError(f"Invalid input: {input}")
        day = input % 100
        input = input // 100
        month = input % 100
        year = input // 100
        return datetime(year, month, day)

    if isinstance(input, float):
        if input < 0:
            raise ValueError(f"Invalid input: {input}")
        input_float = input - int(input)
        input = int(input)
        day = input % 100
        input = input // 100
        month = input % 100
        year = input // 100
        hour = int(input_float * 100)
        minute = int(input_float * 10000) % 100
        second = int(input_float * 1000000) % 100
        return datetime(year, month, day, hour, minute, second)

    if isinstance(input, str) or isinstance(input, unicode):
        datetime.date.fromisoformat(input)

    raise ValueError(f"Cannot handle this format: {input}")


def hkdf_derive(
    input_key: bytes, salt: bytes, info: bytes, length: int, hash_algo
) -> bytes:
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


def hkdf_verify(
    input_key: bytes,
    salt: bytes,
    info: bytes,
    length: int,
    derived_key: bytes,
    hash_algo,
) -> bool:
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
