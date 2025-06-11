from core.utils.dns import get_dns_resolver
from dns.resolver import Resolver
import pytest


@pytest.mark.parametrize(
	"value",
	(
		None,
		[],
		"",
		False,
	),
)
def test_raises_value_error(value):
	with pytest.raises(ValueError, match="one or more Server Addresses"):
		get_dns_resolver(dns_addresses=value)


@pytest.mark.parametrize("value", (b"some_bytes", {"a": "dict"}))
def test_raises_type_error(value):
	with pytest.raises(TypeError, match="must be of type str, list"):
		get_dns_resolver(dns_addresses=value)


@pytest.mark.parametrize(
	"value, expected_exc",
	(
		(
			"someinvalidvalue",
			"Invalid IP Address",
		),
		(
			["8.8.8.8", "someinvalidvalue"],
			"is invalid",
		),
	),
)
def test_raises_on_bad_ip_values(value: str | list, expected_exc: str):
	with pytest.raises(ValueError, match=expected_exc):
		get_dns_resolver(value)


@pytest.mark.parametrize(
	"value",
	(
		"8.8.8.8",
		["8.8.8.8", "8.8.4.4"],
	),
)
def test_success(value: str | list):
	assert isinstance(get_dns_resolver(value), Resolver)
