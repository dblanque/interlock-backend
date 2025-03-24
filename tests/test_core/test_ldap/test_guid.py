import pytest
from pytest_mock import MockType
import struct
from typing import Union
from core.ldap.guid import GUID
from typing import Tuple

# ---------------------------------------------------------------------------- #
#                                    FIXTURES                                  #
# ---------------------------------------------------------------------------- #

@pytest.fixture(name="f_sample_guids")
def fixture_sample_guids() -> Tuple[Tuple[bytes, str], ...]:
	return (
		(
			# Bytes from sample 1
			b'\xde\xbe]\xb1\xc0\x7f\xbeG\x97;=\x05\x8a\n0`',
			# String from sample 1
			"b15dbede-7fc0-47be-973b-3d058a0a3060"
		),
		(
			# Bytes from sample 2
			b'\xb4c\xb7\xf3\xc3\xe2L@\xa5\xea7\x81[\xdd\xea\x08',
			# String from sample 2
			"f3b763b4-e2c3-404c-a5ea-37815bddea08"
		)
	)

@pytest.fixture(name="f_invalid_guids")
def fixture_invalid_guids() -> Tuple[Tuple[Union[bytes, str], str], ...]:
	return (
		(b'tooshort', "Invalid byte length"),  # 8 bytes (needs 16)
		("invalid-guid-format", "Invalid GUID format"),  # Wrong structure
		("missing-parts", "must have 5 parts"),  # Only 2 parts
		("a"*8 + "-" + "b"*4 + "-" + "c"*4 + "-" + "d"*4 + "-" + "e"*12, "invalid hex"),  # Invalid hex
	)

# ---------------------------------------------------------------------------- #
#                                   FROM_BYTES                                 #
# ---------------------------------------------------------------------------- #

@pytest.mark.parametrize("guid_bytes, expected_str", [
	pytest.param(
		b'\xde\xbe]\xb1\xc0\x7f\xbeG\x97;=\x05\x8a\n0`',
		"b15dbede-7fc0-47be-973b-3d058a0a3060",
		id="sample1"
	),
	pytest.param(
		b'\xb4c\xb7\xf3\xc3\xe2L@\xa5\xea7\x81[\xdd\xea\x08',
		"f3b763b4-e2c3-404c-a5ea-37815bddea08",
		id="sample2"
	)
])
def test_from_bytes_valid_conversion(guid_bytes: bytes, expected_str: str):
	"""Test converting valid byte sequences to GUID strings."""
	guid = GUID(guid_bytes)
	assert str(guid) == expected_str
	assert isinstance(guid.data, dict)
	assert len(guid.data) == 5  # 5 GUID components

def test_from_bytes_with_list_input(f_sample_guids):
	"""Test initializing GUID with a list containing bytearray."""
	sample_bytes, expected_str = f_sample_guids[0]
	guid = GUID([sample_bytes])  # Wrap in list
	assert str(guid) == expected_str

# ---------------------------------------------------------------------------- #
#                                   FROM_STR                                   #
# ---------------------------------------------------------------------------- #

@pytest.mark.parametrize("expected_bytes, guid_str", [
	pytest.param(
		b'\xde\xbe]\xb1\xc0\x7f\xbeG\x97;=\x05\x8a\n0`',
		"b15dbede-7fc0-47be-973b-3d058a0a3060",
		id="sample1"
	),
	pytest.param(
		b'\xb4c\xb7\xf3\xc3\xe2L@\xa5\xea7\x81[\xdd\xea\x08',
		"f3b763b4-e2c3-404c-a5ea-37815bddea08",
		id="sample2"
	)
])
def test_from_str_valid_conversion(guid_str: str, expected_bytes: bytes):
	"""Test converting valid GUID strings to byte sequences."""
	guid = GUID(guid_str)
	assert guid.data_bytes_raw == bytearray(expected_bytes)

# ---------------------------------------------------------------------------- #
#                                   INVALID INPUTS                             #
# ---------------------------------------------------------------------------- #

@pytest.mark.parametrize("invalid_input, expected_error", [
    pytest.param(
        b'tooshort',
        "unpack requires a buffer of 16 bytes",
        id="bytes-too-short"
    ),
    pytest.param(
        "invalid-guid-format",
        "badly formed hex",
        id="str-invalid-format"
    ),
    pytest.param(
        "missing-parts",
        "badly formed hex",
        id="str-missing-parts"
    ),
    pytest.param(
        "g"*8 + "-" + "b"*4 + "-" + "c"*4 + "-" + "d"*4 + "-" + "e"*12,
        "invalid literal for int() with base 16",
        id="str-invalid-hex"
    )
])
def test_invalid_inputs_raise_errors(invalid_input, expected_error):
    """Test invalid inputs raise appropriate errors with logging."""
    with pytest.raises((struct.error, ValueError)) as exc_info:
        GUID(invalid_input)
    assert expected_error in str(exc_info.value)

def test_invalid_string_logs_error(mocker):
    """Test invalid GUID string logs error."""
    m_logger = mocker.patch("core.ldap.guid.logger")
    invalid_str = "invalid-guid-format"
    
    with pytest.raises(ValueError):
        GUID(invalid_str)
    
    m_logger.error.assert_called_with(f"Invalid GUID string: {invalid_str}")

def test_invalid_byte_length_logs_error(mocker):
	"""Test invalid byte length logs error."""
	m_logger: MockType = mocker.patch("core.ldap.guid.logger", mocker.MagicMock())
	invalid_bytes = b'tooshort'  # 8 bytes
	
	with pytest.raises(struct.error):
		# Trigger conversion with invalid length
		GUID(invalid_bytes)
	
	# Verify error logging
	m_logger.error.assert_called_once()

# ---------------------------------------------------------------------------- #
#                               SPECIAL METHODS                                #
# ---------------------------------------------------------------------------- #

def test_str_and_repr(f_sample_guids):
	"""Test __str__ and __repr__ methods."""
	sample_bytes, expected_str = f_sample_guids[0]
	guid = GUID(sample_bytes)
	
	assert str(guid) == expected_str
	assert repr(guid) == f"GUID('{expected_str}')"
