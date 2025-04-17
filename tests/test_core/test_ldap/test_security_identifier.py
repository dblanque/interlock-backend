import pytest
from pytest_mock import MockType
from typing import Any

# We'll import the SID class here (assuming it's in a module named 'sid')
from core.ldap.security_identifier import SID


# Fixtures
@pytest.fixture
def f_valid_sid_bytearray() -> bytearray:
	"""Fixture providing a valid SID bytearray."""
	return bytearray(
		b"\x01\x05\x00\x00\x00\x00\x00\x05\x15\x00\x00\x00\x11^\xb3\x83j\x06\x94\x00\x80\xdbi\xaa\x87\x04\x00\x00"
	)


@pytest.fixture
def f_valid_sid_bytes() -> bytes:
	"""Fixture providing a valid SID bytearray."""
	return b"\x01\x05\x00\x00\x00\x00\x00\x05\x15\x00\x00\x00\x11^\xb3\x83j\x06\x94\x00\x80\xdbi\xaa\x87\x04\x00\x00"


@pytest.fixture
def f_valid_sid_str() -> str:
	"""Fixture providing the expected string representation of the valid SID."""
	return "S-1-5-21-2209570321-9700970-2859064192-1159"


@pytest.fixture
def f_list_wrapper() -> list:
	"""Fixture providing a list containing a SID bytearray."""
	return [
		b"\x01\x05\x00\x00\x00\x00\x00\x05\x15\x00\x00\x00\x11^\xb3\x83j\x06\x94\x00\x80\xdbi\xaa\x87\x04\x00\x00"
	]


@pytest.fixture
def f_object_wrapper(mocker: MockType) -> Any:
	"""Fixture providing an object with raw_values containing a SID bytearray."""
	mock_obj = mocker.MagicMock()
	mock_obj.raw_values = [
		b"\x01\x05\x00\x00\x00\x00\x00\x05\x15\x00\x00\x00\x11^\xb3\x83j\x06\x94\x00\x80\xdbi\xaa\x87\x04\x00\x00"
	]
	return mock_obj


@pytest.fixture
def f_logger(mocker: MockType) -> MockType:
	"""Fixture mocking the logger."""
	return mocker.patch("core.ldap.security_identifier.logger", autospec=True)


def test_init_with_bytearray(f_valid_sid_bytearray: bytearray, f_valid_sid_str: str):
	"""Test initialization with a direct bytearray."""
	sid = SID(f_valid_sid_bytearray)
	assert str(sid) == f_valid_sid_str
	assert sid.revision_level == 1
	assert sid.subauthority_count == 5
	assert sid.identifier_authority == 5
	assert sid.subauthorities == [21, 2209570321, 9700970, 2859064192, 1159]


def test_init_with_list(f_list_wrapper: list, f_valid_sid_str: str):
	"""Test initialization with a list containing bytearray."""
	sid = SID(f_list_wrapper)
	assert str(sid) == f_valid_sid_str


def test_init_with_bytes(f_valid_sid_bytes: bytes, f_valid_sid_str: str):
	"""Test initialization with a list containing bytearray."""
	sid = SID(f_valid_sid_bytes)
	assert str(sid) == f_valid_sid_str


def test_init_with_object(f_object_wrapper: Any, f_valid_sid_str: str):
	"""Test initialization with an object containing raw_values."""
	sid = SID(f_object_wrapper)
	assert str(sid) == f_valid_sid_str


def test_init_invalid_type():
	"""Test initialization with invalid type raises assertion."""
	with pytest.raises(ValueError, match="sid_byte_array must be a byte array."):
		SID("invalid_type")


def test_unpack_bytes_big_endian(f_valid_sid_bytearray: bytearray):
	"""Test the _unpack_bytes_big_endian helper method."""
	sid = SID(f_valid_sid_bytearray)
	# Test with various byte lengths
	assert sid._unpack_bytes_big_endian([0x00]) == 0
	assert sid._unpack_bytes_big_endian([0x01]) == 1
	assert sid._unpack_bytes_big_endian([0x00, 0x01]) == 1
	assert sid._unpack_bytes_big_endian([0x01, 0x00]) == 256
	assert sid._unpack_bytes_big_endian([0x01, 0x01]) == 257


def test_logging(f_valid_sid_bytearray: bytearray, f_logger: MockType):
	"""Test that appropriate logging calls are made."""
	sid = SID(f_valid_sid_bytearray)
	str(sid)  # Trigger __str__ which also logs

	# Check some basic logging calls were made
	assert f_logger.debug.call_count >= 5


def test_str_representation(f_valid_sid_bytearray: bytearray, f_valid_sid_str: str):
	"""Test the string representation of the SID."""
	sid = SID(f_valid_sid_bytearray)
	assert str(sid) == f_valid_sid_str
	assert sid.__str__() == f_valid_sid_str  # Explicit call test


def test_edge_case_empty_sid():
	"""Test edge case with minimal valid SID (no subauthorities)."""
	minimal_sid = bytearray(b"\x01\x00\x00\x00\x00\x00\x00")  # S-1-0
	sid = SID(minimal_sid)
	assert str(sid) == "S-1-0"
	assert sid.subauthorities == []


def test_invalid_bytearray_length():
	"""Test with bytearray that's too short."""
	with pytest.raises(IndexError):
		SID(bytearray(b"\x01\x01"))  # Too short to be valid
