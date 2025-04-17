from core.utils.ipv6 import ipv6_to_integer
import socket
from rest_framework.serializers import ValidationError

def ipv4_validator(value: str):
	_exc = ValidationError("invalid_field_ipv4")
	if not isinstance(value, str):
		raise _exc
	if not value:
		raise _exc
	try:
		socket.inet_aton(str(value))
		# Check octet count, disallow incomplete addressing
		parts = str(value).split(".")
		if not len(parts) == 4 and all(part.isdigit() for part in parts):
			raise _exc
	except socket.error:
		raise _exc


def ipv6_validator(value: str):
	_exc = ValidationError("invalid_field_ipv6")
	if not isinstance(value, str):
		raise _exc
	if not value:
		raise _exc
	try:
		ipv6_to_integer(value)
	except socket.error:
		raise _exc


def port_validator(value: int):
	_exc = ValidationError("invalid_field_port")
	try:
		value = int(value)
		if 0 > value > 65535:
			raise _exc
	except:
		raise _exc
