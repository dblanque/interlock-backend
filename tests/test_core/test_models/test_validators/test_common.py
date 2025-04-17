import pytest
from core.models.validators.common import (
	ascii_validator,
	int32_validator,
	natural_validator
)
from rest_framework.serializers import ValidationError

@pytest.mark.parametrize(
	"value",
	[
		"0",
		"4294967295",  # Max 32-bit unsigned int
		"1234567890",
	],
)
def test_int32_validator(value):
	int32_validator(value)

@pytest.mark.parametrize(
	"value",
	[
		"4294967296" , # Too large
		"-1",  # Negative
		"abc",  # Non-numeric
		"123.45",  # Float
		"",  # Empty
		None, # None
	],
)
def test_int32_validator_raises(value):
	with pytest.raises(ValidationError):
		int32_validator(value)


@pytest.mark.parametrize(
	"value",
	[
		"0",
		"123",
		"00123",
	],
)
def test_natural_validator(value):
	natural_validator(value)

@pytest.mark.parametrize(
	"value",
	[
		"-123",  # Negative
		"12.34",  # Float
		"abc",  # Non-numeric
		"",  # Empty
		None,  # None
	],
)
def test_natural_validator_raises(value):
	with pytest.raises(ValidationError):
		natural_validator(value)

@pytest.mark.parametrize(
	"value",
	[
		"ASCII",
		"123!@#",
		"",  # Empty
		b"bytes".decode("ascii"),  # ASCII bytes
	],
)
def test_ascii_validator(value):
	ascii_validator(value)

@pytest.mark.parametrize(
	"value",
	[
		"こんにちは",  # Non-ASCII
		"✓",  # Checkmark symbol
		None,  # None
	],
)
def test_ascii_validator_raises(value):
	with pytest.raises(ValidationError):
		ascii_validator(value)