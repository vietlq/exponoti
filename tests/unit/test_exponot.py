import pytest

from exponot.exponot import (
    rolling_proximity_identifier,
    rolling_proximity_identifier_key,
    associated_encrypted_metadata,
    associated_encrypted_metadata_key,
    ExposureNotification,
    interval_number_from,
    ExposureInternals,
)
from exponot.utils import hkdf_derive, hkdf_verify


@pytest.mark.parametrize(
    "exposure_internals",
    [
        ExposureInternals(
            interval_number=2648535,
            temp_exposure_key=b"\x97I\xa6\x8e\x0f\xae\xfd\xa5\xffV\x04\x11#\x05\x0cc",
            rpik=b"\xa17[\x84)\xcc0\x91\x96\x9a\xbf\xc73.%\x1c",
            rpid=b",\xfa\xb6\x8c?\xf1w\xc3!\xd5\xb8-h\xfe\xdf2",
            aemk=b"S\x91\x16\xd2\x114\xbf\xc3.\x12\x15\xd9\xd5iU\xd6",
        ),
        ExposureInternals(
            interval_number=2648536,
            temp_exposure_key=b"\x97I\xa6\x8e\x0f\xae\xfd\xa5\xffV\x04\x11#\x05\x0cc",
            rpik=b"\xa17[\x84)\xcc0\x91\x96\x9a\xbf\xc73.%\x1c",
            rpid=b"\xfc\x9c\xe3z\x86t\xdd@\xb5\xfe\xc9\xe38-p\n",
            aemk=b"S\x91\x16\xd2\x114\xbf\xc3.\x12\x15\xd9\xd5iU\xd6",
        ),
    ],
)
def test_exponot(exposure_internals):
    assert exposure_internals.rpik == rolling_proximity_identifier_key(
        exposure_internals.temp_exposure_key
    )
    assert exposure_internals.rpid == rolling_proximity_identifier(
        exposure_internals.interval_number,
        exposure_internals.temp_exposure_key,
    )
    assert exposure_internals.aemk == associated_encrypted_metadata_key(
        exposure_internals.temp_exposure_key
    )
