import pytest
from core.models.validators.networking import (
	ipv4_validator,
	ipv6_validator,
	port_validator,
)
from rest_framework.serializers import ValidationError


# ipv4_validator tests
@pytest.mark.parametrize(
	"value, expected",
	[
		("192.168.1.1", True),
		("0.0.0.0", True),
		("255.255.255.255", True),
		("256.0.0.0", False),  # Invalid octet
		("192.168.1", False),  # Incomplete
		("192.168.1.1.1", False),  # Too many octets
		("192.168.1.x", False),  # Non-numeric
		("", False),  # Empty
		(None, False),  # None
	],
)
def test_ipv4_validator(value, expected):
	if not expected:
		with pytest.raises(ValidationError):
			ipv4_validator(value)
	else:
		ipv4_validator(value)


# ipv6_validator tests
@pytest.mark.parametrize(
	"value, expected",
	[
		("2001:0db8:85a3:0000:0000:8a2e:0370:7334", True),
		("2001:db8:85a3::8a2e:370:7334", True),  # Compressed
		("::1", True),  # Loopback
		("2001::85a3::8a2e", False),  # Double compression
		("2001:0db8:85a3:0000:0000:8a2e:0370:7334:9999", False),  # Too long
		("192.168.1.1", False),  # IPv4
		("", False),  # Empty
		(None, False),  # None
	],
)
def test_ipv6_validator(value, expected):
	if not expected:
		with pytest.raises(ValidationError):
			ipv6_validator(value)
	else:
		ipv6_validator(value)


@pytest.mark.parametrize(
	"value",
	(
		1,
		117,
		3492,
		65535,
	),
)
def test_port_validator(value):
	port_validator(value)


@pytest.mark.parametrize(
	"value",
	(
		"abc",
		"123.29",
		b"some_bytes",
		65537,
	),
)
def test_port_validator_raises(value):
	with pytest.raises(ValidationError):
		port_validator(value)
