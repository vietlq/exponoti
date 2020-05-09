import os
from datetime import datetime

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidKey


def hkdf_derive(hash_algo, length, salt, info, input_key):
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


def hkdf_verify(hash_algo, length, salt, info, input_key, derived_key):
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


def run_example():
    """Usage example"""
    hash_algo = hashes.SHA256()
    salt = os.urandom(16)
    info = b"hkdf-example"

    input_key = b"input key"
    derived_key = hkdf_derive(
        hash_algo=hash_algo,
        length=32,
        salt=salt,
        info=info,
        input_key=input_key,
    )
    print(f"derived_key = {derived_key}")

    result = hkdf_verify(
        hash_algo=hash_algo,
        length=32,
        salt=salt,
        info=info,
        input_key=input_key,
        derived_key=derived_key,
    )
    print(f"result = {result}")


if __name__ == "__main__":
    run_example()
