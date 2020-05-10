"""
Exposure Notification reference implementation.
"""

import os
import struct
from datetime import datetime, timedelta
from collections import OrderedDict, namedtuple
from binascii import hexlify

from Crypto.Cipher import AES
from Crypto.Util import Counter

from cryptography.hazmat.primitives import hashes

from .utils import hkdf_derive, mkdt


"""
The TEKRollingPeriod is the duration for which a Temporary Exposure Key
is valid (in multiples of 10 minutes). In our protocol, TEKRollingPeriod
is defined as 144, achieving a key validity of 24 hours.
"""
SECONDS_PER_INTERVAL = 600
TEK_ROLLING_PERIOD = 144
TEK_LIFETIME = 14
BYTES_RPIK_INFO = "EN-RPIK".encode("utf-8")
BYTES_RPI = "EN-RPI".encode("utf-8")
BYTES_MID_PAD = b"\x00\x00\x00\x00\x00\x00"
BYTES_AEMK_INFO = "EN-AEMK".encode("utf-8")


ExposureInternals = namedtuple(
    "ExposureInternals", "interval_number,temp_exposure_key,rpik,rpid,aemk"
)


class Verifier:
    """
    Class to collect and verify if any of external Rolling Proximity
    Identifiers match given external Temporary Exposure Keys that were
    advertised as positive to Covid-19.
    """

    def __init__(self):
        self._external_rp_ids = OrderedDict()

    def add_external_rpi(self, external_rpi):
        """
        Collect external Rolling Proximity Identifier.
        """
        assert len(external_rpi) == 16
        if external_rpi not in self._external_rp_ids:
            self._external_rp_ids[external_rpi] = datetime.now()

    def was_exposed_to_key(self, temp_exposure_key):
        """
        Check if the user was exposed to the owner of given exposure key.
        """
        now_dt = datetime.now()
        interval_number = interval_number_now()
        past_dt = now_dt - timedelta(days=15)
        past_interval_num = interval_number_from(past_dt)

        while past_interval_num <= interval_number:
            past_rp_id = rolling_proximity_identifier(
                past_interval_num, temp_exposure_key
            )
            if past_rp_id in self._external_rp_ids:
                return True
            past_interval_num += 1

        return False


class ExposureNotification:
    """
    Simple wrapper around exposure notification functions.
    """

    def __init__(self):
        self._temporary_exposure_keys = OrderedDict()

    def get_temp_exposure_key(self):
        """Get current temporary exposure key"""
        interval_number = interval_number_now()
        return temporary_exposure_key(
            self._temporary_exposure_keys, interval_number
        )

    def internals(self):
        """
        Get current interval number, temporary exposure key and derived keys.
        """
        interval_number = interval_number_now()
        temp_exposure_key = self.get_temp_exposure_key()
        curr_rp_id_key = rolling_proximity_identifier_key(temp_exposure_key)
        curr_rp_id = rolling_proximity_identifier(
            interval_number, temp_exposure_key
        )
        curr_aemk = associated_encrypted_metadata_key(temp_exposure_key)
        return ExposureInternals(
            interval_number=interval_number,
            temp_exposure_key=temp_exposure_key,
            rpik=curr_rp_id_key,
            rpid=curr_rp_id,
            aemk=curr_aemk,
        )

    def encrypt(self, metadata):
        """
        Encrypt metadata.
        """
        # TODO: Consider keep AES CTR counter for the whole interval
        interval_number = interval_number_now()
        temp_exposure_key = self.get_temp_exposure_key()
        return associated_encrypted_metadata(
            interval_number, temp_exposure_key, metadata
        )


def interval_number_from(time_at_key_gen: datetime) -> int:
    """
    Implements the function ENIntervalNumber in specification.
    """
    timestamp = int(time_at_key_gen.timestamp())
    return timestamp // SECONDS_PER_INTERVAL


def interval_number_now() -> int:
    """
    ENIntervalNumber of the present timestamp.
    This function provides a number for each 10 minute time window that’s
    shared between all devices participating in the protocol. These time
    windows are derived from timestamps in Unix Epoch Time.
    """
    return interval_number_from(datetime.utcnow())


def temporary_exposure_key(key_manager, interval_number) -> bytes:
    """
    Generates Temporary Exposure Key once for each TEKRollingPeriod (day).
    Generation is done once a day and calculation is amortized.
    """
    curr_interval_period = interval_number // TEK_ROLLING_PERIOD

    if curr_interval_period not in key_manager:
        key_manager[curr_interval_period] = os.urandom(16)
        temp_dict = OrderedDict(
            {
                prev_key: key_manager[prev_key]
                for prev_key in key_manager
                if curr_interval_period - prev_key <= TEK_LIFETIME
            }
        )
        key_manager = temp_dict

    return key_manager[curr_interval_period]


def derive_rolling_key(temp_exposure_key: bytes, info: bytes) -> bytes:
    """Implements HKDF with caching"""
    return hkdf_derive(
        input_key=temp_exposure_key,
        salt=b"",
        info=info,
        length=16,
        hash_algo=hashes.SHA256(),
    )


def rolling_proximity_identifier_key(temp_exposure_key: bytes) -> bytes:
    """
    The Rolling Proximity Identifier Key (RPIK) is derived from the
    Temporary Exposure Key and is used in order to derive the
    Rolling Proximity Identifiers.
    Derives a new value of RPIK once every given TEKRollingPeriod (1 day).
    """
    return derive_rolling_key(temp_exposure_key, BYTES_RPIK_INFO)


def rolling_proximity_identifier(
    interval_number: int, temp_exposure_key: bytes
) -> bytes:
    """
    Rolling Proximity Identifiers are privacy-preserving identifiers that are
    broadcast in Bluetooth payloads. Each time the Bluetooth Low Energy MAC
    randomized address changes, we derive a new Rolling Proximity Identifier
    using the Rolling Proximity Identifier Key.
    ENIntervalNumber is encoded as a 32-bit (uint32_t) unsigned little-endian
    value.
    """
    curr_rpik = rolling_proximity_identifier_key(temp_exposure_key)
    padded_data = (
        BYTES_RPI + BYTES_MID_PAD + struct.pack("<I", interval_number)
    )
    cipher = AES.new(key=curr_rpik, mode=AES.MODE_ECB)
    return cipher.encrypt(padded_data)


def associated_encrypted_metadata_key(temp_exposure_key: bytes) -> bytes:
    """
    The Associated Encrypted Metadata Keys are derived from the
    Temporary Exposure Keys in order to encrypt additional metadata.
    Derives a new value of AEMK once every given TEKRollingPeriod (1 day).
    """
    return derive_rolling_key(temp_exposure_key, BYTES_AEMK_INFO)


def associated_encrypted_metadata(
    interval_number: int, temp_exposure_key: bytes, metadata: bytes
) -> bytes:
    """
    The Associated Encrypted Metadata is data encrypted along with the
    Rolling Proximity Identifier, and can only be decrypted later if the user
    broadcasting it tested positive and reveals their Temporary Exposure Key.
    The 16-byte Rolling Proximity Identifier and the appended encrypted
    metadata are broadcast over Bluetooth Low Energy wireless technology.
    """
    curr_aemk = associated_encrypted_metadata_key(temp_exposure_key)
    curr_rpi = rolling_proximity_identifier(interval_number, temp_exposure_key)
    curr_rpi_hex = hexlify(curr_rpi)
    curr_rpi_int = int(curr_rpi_hex, 16)
    counter = Counter.new(nbits=128, initial_value=curr_rpi_int)
    # TODO: Should cipher be created once every interval, not once per call?
    # Once per call creating will reset counter every time, will cause
    # the same metadata will have the same output.
    cipher = AES.new(key=curr_aemk, mode=AES.MODE_CTR, counter=counter)
    return cipher.encrypt(metadata)
