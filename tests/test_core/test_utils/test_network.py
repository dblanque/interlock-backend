########################### Standard Pytest Imports ############################
import pytest
from pytest_mock import MockerFixture
################################################################################
import socket
from core.utils.network import ipv6_to_integer, net_port_test

@pytest.fixture
def f_socket(mocker: MockerFixture):
	yield mocker.patch("socket.socket")

class TestNetPortTest:
	@staticmethod
	def test_successful_connection(f_socket):
		mock_instance = f_socket.return_value
		mock_instance.connect.return_value = None

		result = net_port_test("127.0.0.1", 389)
		assert result is True
		mock_instance.connect.assert_called_once_with(("127.0.0.1", 389))
		mock_instance.settimeout.assert_any_call(5)
		mock_instance.settimeout.assert_any_call(None)
		mock_instance.shutdown.assert_called_once_with(2)

	@staticmethod
	def test_failed_connection(f_socket):
		mock_instance = f_socket.return_value
		mock_instance.connect.side_effect = socket.error

		result = net_port_test("127.0.0.1", 389)
		assert result is False


class TestIPv6ToInteger:
	@pytest.mark.parametrize("ipv6_addr, expected", [
		# Full IPv6 address (manually verified)
		("2001:0db8:85a3:0000:0000:8a2e:0370:7334", 
		0x20010db885a3000000008a2e03707334),
		
		# Compressed IPv6 (same as above, should yield same result)
		("2001:db8:85a3::8a2e:370:7334", 
		0x20010db885a3000000008a2e03707334),
		
		# IPv6 loopback
		("::1", 1),
		
		# IPv6 unspecified address
		("::", 0),
		
		# IPv4-mapped IPv6 (verified with manual calculation)
		("::ffff:192.168.1.1", 
		0x0000000000000000ffffc0a80101),
		
		# Another IPv6 example
		("2606:4700:4700::1111", 
		0x26064700470000000000000000001111),
	])
	def test_ipv6_to_integer_valid(self, ipv6_addr, expected):
		assert ipv6_to_integer(ipv6_addr) == expected

	# Test cases for invalid IPv6 addresses
	@pytest.mark.parametrize("invalid_ipv6", [
		"192.168.1.1",           # IPv4 address
		"not_an_ip_address",      # Random string
		"2001:db8::8a2e::370",   # Double colon
		"2001:db8:85a3::8a2e:0370:7334:extra",  # Too many segments
		"2001:0db8:85a3:0000:0000:8a2e:0370:7334:1234",  # Extra segment
		"",                      # Empty string
		None,                    # None value
		12345,                   # Integer
	])
	def test_ipv6_to_integer_invalid(self, invalid_ipv6):
		with pytest.raises((socket.error, ValueError, TypeError)):
			ipv6_to_integer(invalid_ipv6)


	# Test for byte representation equivalence
	def test_ipv6_byte_representation(self):
		addr1 = "2001:db8::8a2e:370:7334"
		addr2 = "2001:0db8:0000:0000:0000:8a2e:0370:7334"
		assert ipv6_to_integer(addr1) == ipv6_to_integer(addr2)
