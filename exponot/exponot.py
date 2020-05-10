"""
Exposure Notification.
"""

import os
from datetime import datetime
from collections import OrderedDict

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidKey


"""
The TEKRollingPeriod is the duration for which a Temporary Exposure Key
is valid (in multiples of 10 minutes). In our protocol, TEKRollingPeriod
is defined as 144, achieving a key validity of 24 hours.
"""
TEK_ROLLING_PERIOD = 144

_temporary_exposure_key = OrderedDict()


def interval_number(time_at_key_gen: datetime) -> int:
    """
    Implements the function ENIntervalNumber in specification.
    This function provides a number for each 10 minute time window that’s
    shared between all devices participating in the protocol. These time
    windows are derived from timestamps in Unix Epoch Time.
    ENIntervalNumber is encoded as a 32-bit (uint32_t) unsigned little-endian
    value.
    """
    timestamp = int(time_at_key_gen.timestamp())
    return timestamp // 600


def interval_number_now() -> int:
    """Returns ENIntervalNumber of the present timestamp."""
    return interval_number(datetime.utcnow())


def temporary_exposure_key() -> bytes:
    """
    Generates Temporary Exposure Key once for each TEKRollingPeriod (day).
    """
    global _temporary_exposure_key
    curr_interval_num = interval_number_now()
    curr_interval_day = curr_interval_num // 144
    if curr_interval_day not in _temporary_exposure_key:
        _temporary_exposure_key[curr_interval_day] = os.urandom(16)
    return _temporary_exposure_key[curr_interval_day]


def hkdf_derive(hash_algo, length, salt, info, input_key) -> bytes:
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


def hkdf_verify(hash_algo, length, salt, info, input_key, derived_key) -> bool:
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
