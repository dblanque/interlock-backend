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
from typing import Iterable, Any, overload
from ldap3 import Entry as LDAPEntry, Attribute as LDAPAttribute


@overload
def getldapattr(entry: LDAPEntry, attr: str, /) -> str | Iterable | Any: ...


@overload
def getldapattr(entry: LDAPEntry, attr: str, /, default=None) -> str | Iterable | Any: ...


def getldapattr(entry: LDAPEntry, attr: str, /, *args, **kwargs) -> str | Iterable | Any:
	"""Get LDAP Attribute with optional default

	Args:
		entry (LDAPEntry): LDAP Entry to get the attribute from.
		attr (str): Attribute key.
		default: Optional. Returned when entry getitem fails.

	Returns:
		Any: Attribute value.
	"""
	try:
		_attr: LDAPAttribute = getattr(entry, attr)
		return _attr.value
	except Exception as e:
		if "default" in kwargs:
			return kwargs["default"]
		if len(args) > 0:
			return args[0]
		raise e


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


def recursive_dict_find(obj, key):
	if key in obj:
		return obj[key]
	for k, v in obj.items():
		if isinstance(v, dict):
			item = recursive_dict_find(v, key)
			if item is not None:
				return item


def uppercase_ldif_identifiers(v: str):
	if not isinstance(v, str):
		raise TypeError("Value must be str.")
	for ldif_ident in LDAP_LDIF_IDENTIFIERS:
		v = v.replace(f"{ldif_ident}=", f"{ldif_ident.upper()}=")
	return v


def is_non_str_iterable(v):
	"""Checks if value is within types (tuple, list, set, dict)

	Args:
		v (tuple or list or set or dict): Some value to check.

	Returns:
		bool
	"""
	if isinstance(v, str):
		return False
	return isinstance(v, (tuple, list, set, dict))
