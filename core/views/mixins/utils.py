################################################################################
#################### INTERLOCK IS LICENSED UNDER GNU AGPLv3 ####################
################## ORIGINAL PROJECT CREATED BY DYLAN BLANQUÉ ###################
########################## AND BR CONSULTING S.R.L. ############################
################################################################################
# Module: core.views.mixins.utils
# Contains extra utilities and functions

# ---------------------------------- IMPORTS -----------------------------------#
from core.ldap.defaults import LDAP_LDIF_IDENTIFIERS
import socket
import struct
from typing import Iterable


def convert_string_to_bytes(string):
	if not isinstance(string, str):
		raise ValueError("Value must be a string")
	string = string.replace("\\\\", "\\")
	string = string.lstrip("b'").rstrip("'")
	bytes = b""
	for k, i in enumerate(string):
		if i != "\\" and k > 0:
			bytes += struct.pack("B", ord(i))
		elif k - 1 > 0:
			if i == "\\" and string[k - 1] != "\\":
				bytes += struct.pack("B", ord(i))
		else:
			bytes += struct.pack("B", ord(i))
	return bytes.decode("unicode_escape").encode("raw_unicode_escape")


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


def recursiveFindInDict(obj, key):
	if key in obj:
		return obj[key]
	for k, v in obj.items():
		if isinstance(v, dict):
			item = recursiveFindInDict(v, key)
			if item is not None:
				return item


def uppercase_ldif_identifiers(v: str):
	if not isinstance(v, str):
		raise TypeError("Value must be str.")
	for ldif_ident in LDAP_LDIF_IDENTIFIERS:
		v = v.replace(f"{ldif_ident}=", f"{ldif_ident.upper()}=")
	return v


def __get_common_name__(dn):
	return str(dn).split(",")[0].split("=")[-1]


def __get_relative_dn__(dn):
	_v: list = str(dn).split(",")
	_v.remove(0)
	return ",".join(_v)


def is_non_str_iterable(v):
	if isinstance(v, str):
		return False
	return isinstance(v, Iterable)
