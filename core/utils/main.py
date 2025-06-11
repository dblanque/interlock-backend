################################################################################
#################### INTERLOCK IS LICENSED UNDER GNU AGPLv3 ####################
################## ORIGINAL PROJECT CREATED BY DYLAN BLANQUÉ ###################
########################## AND BR CONSULTING S.R.L. ############################
################################################################################
# Module: core.utils.main
# Contains extra utilities and functions

# ---------------------------------- IMPORTS --------------------------------- #
from core.ldap.defaults import LDAP_LDIF_IDENTIFIERS
from typing import Iterable, Any, overload
from ldap3 import Entry as LDAPEntry, Attribute as LDAPAttribute

@overload
def getlocalkeyforldapattr(v: str, default: str = None): ...


def getlocalkeyforldapattr(v: str, *args, **kwargs):
	"""Returns local alias for LDAP Attribute Key"""
	from core.config.runtime import RuntimeSettings

	for local_alias, ldap_alias in RuntimeSettings.LDAP_FIELD_MAP.items():
		if ldap_alias == v:
			return local_alias
	if args:
		return args[0]
	elif "default" in kwargs:
		return kwargs.pop("default")
	raise ValueError(f"No alias for ldap key ({v})")


@overload
def getldapattrvalue(
	entry: LDAPEntry, attr: str, /
) -> str | Iterable | Any: ...


@overload
def getldapattrvalue(
	entry: LDAPEntry, attr: str, /, default=None
) -> str | Iterable | Any: ...


def getldapattrvalue(
	entry: LDAPEntry, attr: str, /, *args, **kwargs
) -> str | Iterable | Any:
	"""Get LDAP Attribute Value with optional default

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


@overload
def getldapattr(entry: LDAPEntry, attr: str, /) -> LDAPAttribute: ...


@overload
def getldapattr(
	entry: LDAPEntry, attr: str, /, default=None
) -> LDAPAttribute: ...


def getldapattr(
	entry: LDAPEntry, attr: str, /, *args, **kwargs
) -> LDAPAttribute:
	"""Get LDAP Attribute Abstract Object

	Args:
		entry (LDAPEntry): LDAP Entry to get the attribute from.
		attr (str): Attribute key.
		default: Optional. Returned when entry getattr fails.

	Returns:
		ldap3.Attribute: LDAP3 Attribute Abstract Object.
	"""
	if len(args) > 0:
		return getattr(entry, attr, args[0])
	elif "default" in kwargs:
		return getattr(entry, attr, kwargs["default"])
	else:
		return getattr(entry, attr)


def uppercase_ldif_identifiers(v: str):
	if not isinstance(v, str):
		raise TypeError("Value must be str.")
	for ldif_ident in LDAP_LDIF_IDENTIFIERS:
		v = v.replace(f"{ldif_ident}=", f"{ldif_ident.upper()}=")
	return v
