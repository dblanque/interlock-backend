import socket
from struct import unpack


def net_port_test(ip, port, timeout=5):
	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	s.settimeout(timeout)
	try:
		s.connect((ip, int(port)))
		s.settimeout(None)
		s.shutdown(2)
		return True
	except:
		return False


# src: https://stackoverflow.com/questions/10558441/inet-aton-similar-function-for-ipv6
def ipv6_to_integer(ipv6_addr):
	ipv6_addr = socket.inet_pton(socket.AF_INET6, ipv6_addr)
	a, b = unpack(">QQ", ipv6_addr)
	return (a << 64) | b
