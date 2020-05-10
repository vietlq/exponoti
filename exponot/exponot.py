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
TEK_LIFETIME = 14
BYTES_RPIK_INFO = "EN-RPIK".encode("utf-8")

_temporary_exposure_keys = OrderedDict()
_rolling_proximity_id_keys = OrderedDict()


def _interval_number_impl(time_at_key_gen: datetime) -> int:
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


def interval_number() -> int:
    """Returns ENIntervalNumber of the present timestamp."""
    return _interval_number_impl(datetime.utcnow())


def temporary_exposure_key() -> bytes:
    """
    Generates Temporary Exposure Key once for each TEKRollingPeriod (day).
    Generation is done once a day and calculation is amortized.
    """
    global _temporary_exposure_keys
    curr_interval_num = interval_number()
    curr_interval_day = curr_interval_num // TEK_ROLLING_PERIOD

    if curr_interval_day not in _temporary_exposure_keys:
        _temporary_exposure_keys[curr_interval_day] = os.urandom(16)
        temp_dict = OrderedDict(
            {
                prev_key: _temporary_exposure_keys[prev_key]
                for prev_key in _temporary_exposure_keys
                if curr_interval_day - prev_key <= TEK_LIFETIME
            }
        )
        _temporary_exposure_keys = temp_dict

    return _temporary_exposure_keys[curr_interval_day]


def rolling_proximity_identifier_key():
    """
    The Rolling Proximity Identifier Key (RPIK) is derived from the
    Temporary Exposure Key and is used in order to derive the
    Rolling Proximity Identifiers.
    Generates RPIK once every given interval (block of 10 mins).
    """
    global _rolling_proximity_id_keys
    curr_interval_num = interval_number()

    if curr_interval_num not in _rolling_proximity_id_keys:
        curr_rpik = hkdf_derive(
            input_key=temporary_exposure_key(),
            salt=b"",
            info=BYTES_RPIK_INFO,
            length=16,
            hash_algo=hashes.SHA256(),
        )
        _rolling_proximity_id_keys[curr_interval_num] = curr_rpik

        # Clean up old RPIK values
        MAX_LIFETIME = TEK_ROLLING_PERIOD * TEK_LIFETIME
        temp_dict = OrderedDict(
            {
                prev_key: _rolling_proximity_id_keys[prev_key]
                for prev_key in _rolling_proximity_id_keys
                if curr_interval_num - prev_key <= MAX_LIFETIME
            }
        )
        _rolling_proximity_id_keys = temp_dict

    return _rolling_proximity_id_keys[curr_interval_num]


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


def run_example():
    """Usage example"""
    hash_algo = hashes.SHA256()
    salt = os.urandom(16)
    info = b"hkdf-example"

    input_key = b"input key"
    derived_key = hkdf_derive(
        input_key=input_key,
        salt=salt,
        info=info,
        length=32,
        hash_algo=hash_algo,
    )
    print(f"derived_key = {derived_key}")

    result = hkdf_verify(
        input_key=input_key,
        salt=salt,
        info=info,
        length=32,
        derived_key=derived_key,
        hash_algo=hash_algo,
    )
    print(f"result = {result}")


if __name__ == "__main__":
    run_example()
