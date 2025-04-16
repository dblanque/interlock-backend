import pytest
from core.models.validators.ldap_dns_record import (
	int32_validator,
	natural_validator,
	canonical_hostname_validator,
	domain_validator,
	ipv4_validator,
	ipv6_validator,
	ascii_validator,
)


# int32_validator tests
@pytest.mark.parametrize(
	"value, expected",
	[
		("0", True),
		("4294967295", True),  # Max 32-bit unsigned int
		("4294967296", False),  # Too large
		("1234567890", True),
		("-1", False),  # Negative
		("abc", False),  # Non-numeric
		("123.45", False),  # Float
		("", False),  # Empty
		(None, False),  # None
	],
)
def test_int32_validator(value, expected):
	assert int32_validator(value) == expected


# natural_validator tests
@pytest.mark.parametrize(
	"value, expected",
	[
		("0", True),
		("123", True),
		("00123", True),  # Leading zeros allowed
		("-123", False),  # Negative
		("12.34", False),  # Float
		("abc", False),  # Non-numeric
		("", False),  # Empty
		(None, False),  # None
	],
)
def test_natural_validator(value, expected):
	assert natural_validator(value) == expected


# canonicalHostname_validator tests
@pytest.mark.parametrize(
	"value, expected",
	[
		("example.com.", True),  # Standard with Trailing dot
		("example.", True),  # Single label
		("sub-domain.example.com.", True),
		("a" * 63 + ".com.", True),  # Max label length
		("example.com", False),
		("sub.example.com", False),
		("exa-mple.com", False),  # Hyphen
		("exa_mple.com", False),  # Underscore not allowed
		("example..com", False),  # Double dot
		(".example.com", False),  # Leading dot
		("example", False),  # Too short
		("a" * 64 + ".com", False),  # Too long label
		("", False),  # Empty
		(None, False),  # None
	],
)
def test_canonicalHostname_validator(value, expected):
	assert canonical_hostname_validator(value) == expected


# domain_validator tests
@pytest.mark.parametrize(
	"value, expected",
	[
		("example.com", True),
		("sub.example.com", True),  # Subdomain
		("sub.example.com", True),  # Subdomain with hyphen
		("example.com.", False),  # With Trailing Dot
		("exa-mple.com", True),  # Hyphen
		("exa_mple.com", True),  # Underscore allowed
		("example..com", False),  # Double dot
		(".example.com", False),  # Leading dot
		("example", True),  # Single label domain
		("a" * 63 + ".com", True),  # Max label length
		("a" * 64 + ".com", False),  # Too long label
		("", False),  # Empty
		(None, False),  # None
	],
)
def test_domain_validator(value, expected):
	assert domain_validator(value) == expected


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
	assert ipv4_validator(value) == expected


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
	assert ipv6_validator(value) == expected


# ascii_validator tests
@pytest.mark.parametrize(
	"value, expected",
	[
		("ASCII", True),
		("123!@#", True),
		("", True),  # Empty
		("こんにちは", False),  # Non-ASCII
		("✓", False),  # Checkmark symbol
		(b"bytes".decode("ascii"), True),  # ASCII bytes
		(None, False),  # None
	],
)
def test_ascii_validator(value, expected):
	assert ascii_validator(value) == expected


# Test error cases that should raise exceptions
@pytest.mark.parametrize(
	"validator, value",
	[
		(natural_validator, object()),  # Unconvertible object
		(canonical_hostname_validator, object()),
		(domain_validator, object()),
	],
)
def test_validator_exceptions(validator, value):
	assert validator(value) is False
