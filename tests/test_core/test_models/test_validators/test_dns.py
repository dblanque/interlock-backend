import pytest
from core.models.validators.dns import (
	canonical_hostname_validator,
	domain_validator,
)
from rest_framework.serializers import ValidationError

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
	if not expected:
		with pytest.raises(ValidationError):
			canonical_hostname_validator(value)
	else:
		canonical_hostname_validator(value)


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
	if not expected:
		with pytest.raises(ValidationError):
			domain_validator(value)
	else:
		domain_validator(value)

# Test error cases that should raise exceptions
@pytest.mark.parametrize(
	"validator, value",
	[
		(canonical_hostname_validator, object()),
		(domain_validator, object()),
	],
)
def test_validator_exceptions(validator, value):
	with pytest.raises(ValidationError):
		validator(value)
