################################################################################
#################### INTERLOCK IS LICENSED UNDER GNU AGPLv3 ####################
################## ORIGINAL PROJECT CREATED BY DYLAN BLANQUÉ ###################
########################## AND BR CONSULTING S.R.L. ############################
################################################################################
# Module: interlock_backend.ldap.adsi
# Contains:
# - LDAP Permission Dictionary
# - LDAP Manual Built-In Object Dictionary
# - Important LDAP Query Functions
###############################################################################

# ---------------------------------- IMPORTS -----------------------------------#
from core.config.runtime import RuntimeSettings
from typing import Union, Literal, TypedDict, Required
import logging

logger = logging.getLogger(__name__)

LDAP_UF_SCRIPT = "LDAP_UF_SCRIPT"
LDAP_UF_ACCOUNT_DISABLE = "LDAP_UF_ACCOUNT_DISABLE"
LDAP_UF_HOMEDIR_REQUIRED = "LDAP_UF_HOMEDIR_REQUIRED"
LDAP_UF_LOCKOUT = "LDAP_UF_LOCKOUT"
LDAP_UF_PASSWD_NOTREQD = "LDAP_UF_PASSWD_NOTREQD"
LDAP_UF_PASSWD_CANT_CHANGE = "LDAP_UF_PASSWD_CANT_CHANGE"
LDAP_UF_ENCRYPTED_TEXT_PASSWORD_ALLOWED = "LDAP_UF_ENCRYPTED_TEXT_PASSWORD_ALLOWED"
LDAP_UF_NORMAL_ACCOUNT = "LDAP_UF_NORMAL_ACCOUNT"
LDAP_UF_INTERDOMAIN_TRUST_ACCOUNT = "LDAP_UF_INTERDOMAIN_TRUST_ACCOUNT"
LDAP_UF_WORKSTATION_TRUST_ACCOUNT = "LDAP_UF_WORKSTATION_TRUST_ACCOUNT"
LDAP_UF_SERVER_TRUST_ACCOUNT = "LDAP_UF_SERVER_TRUST_ACCOUNT"
LDAP_UF_DONT_EXPIRE_PASSWD = "LDAP_UF_DONT_EXPIRE_PASSWD"
LDAP_UF_MNS_LOGON_ACCOUNT = "LDAP_UF_MNS_LOGON_ACCOUNT"
LDAP_UF_SMARTCARD_REQUIRED = "LDAP_UF_SMARTCARD_REQUIRED"
LDAP_UF_TRUSTED_FOR_DELEGATION = "LDAP_UF_TRUSTED_FOR_DELEGATION"
LDAP_UF_NOT_DELEGATED = "LDAP_UF_NOT_DELEGATED"
LDAP_UF_USE_DES_KEY_ONLY = "LDAP_UF_USE_DES_KEY_ONLY"
LDAP_UF_DONT_REQUIRE_PREAUTH = "LDAP_UF_DONT_REQUIRE_PREAUTH"
LDAP_UF_PASSWORD_EXPIRED = "LDAP_UF_PASSWORD_EXPIRED"
LDAP_UF_TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION = "LDAP_UF_TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION"
LDAP_UF_NO_AUTH_DATA_REQUIRED = "LDAP_UF_NO_AUTH_DATA_REQUIRED"
LDAP_UF_PARTIAL_SECRETS_ACCOUNT = "LDAP_UF_PARTIAL_SECRETS_ACCOUNT"


class LDAP_PERM_KEYS(TypedDict):
	value: Required[int]
	val_bin: Required[str]
	index: Required[int]


class LDAP_PERMS_DICT(TypedDict):
	LDAP_UF_SCRIPT: Required[LDAP_PERM_KEYS]
	LDAP_UF_ACCOUNT_DISABLE: Required[LDAP_PERM_KEYS]
	LDAP_UF_HOMEDIR_REQUIRED: Required[LDAP_PERM_KEYS]
	LDAP_UF_LOCKOUT: Required[LDAP_PERM_KEYS]
	LDAP_UF_PASSWD_NOTREQD: Required[LDAP_PERM_KEYS]
	LDAP_UF_PASSWD_CANT_CHANGE: Required[LDAP_PERM_KEYS]
	LDAP_UF_ENCRYPTED_TEXT_PASSWORD_ALLOWED: Required[LDAP_PERM_KEYS]
	LDAP_UF_NORMAL_ACCOUNT: Required[LDAP_PERM_KEYS]
	LDAP_UF_INTERDOMAIN_TRUST_ACCOUNT: Required[LDAP_PERM_KEYS]
	LDAP_UF_WORKSTATION_TRUST_ACCOUNT: Required[LDAP_PERM_KEYS]
	LDAP_UF_SERVER_TRUST_ACCOUNT: Required[LDAP_PERM_KEYS]
	LDAP_UF_DONT_EXPIRE_PASSWD: Required[LDAP_PERM_KEYS]
	LDAP_UF_MNS_LOGON_ACCOUNT: Required[LDAP_PERM_KEYS]
	LDAP_UF_SMARTCARD_REQUIRED: Required[LDAP_PERM_KEYS]
	LDAP_UF_TRUSTED_FOR_DELEGATION: Required[LDAP_PERM_KEYS]
	LDAP_UF_NOT_DELEGATED: Required[LDAP_PERM_KEYS]
	LDAP_UF_USE_DES_KEY_ONLY: Required[LDAP_PERM_KEYS]
	LDAP_UF_DONT_REQUIRE_PREAUTH: Required[LDAP_PERM_KEYS]
	LDAP_UF_PASSWORD_EXPIRED: Required[LDAP_PERM_KEYS]
	LDAP_UF_TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION: Required[LDAP_PERM_KEYS]
	LDAP_UF_NO_AUTH_DATA_REQUIRED: Required[LDAP_PERM_KEYS]
	LDAP_UF_PARTIAL_SECRETS_ACCOUNT: Required[LDAP_PERM_KEYS]


# LDAP Permission Dictionary - all values are converted to binary with a 32 zero padding
# Items also contain their index position in the 32bit binary string
LDAP_PERMS: LDAP_PERMS_DICT = {
	LDAP_UF_SCRIPT: {
		"value": 1,
		"val_bin": str(bin(1))[2:].zfill(32),
		"index": str(bin(1))[2:].zfill(32).find("1"),
	},
	LDAP_UF_ACCOUNT_DISABLE: {
		"value": 2,
		"val_bin": str(bin(2))[2:].zfill(32),
		"index": str(bin(2))[2:].zfill(32).find("1"),
	},
	LDAP_UF_HOMEDIR_REQUIRED: {
		"value": 8,
		"val_bin": str(bin(8))[2:].zfill(32),
		"index": str(bin(8))[2:].zfill(32).find("1"),
	},
	LDAP_UF_LOCKOUT: {
		"value": 16,
		"val_bin": str(bin(16))[2:].zfill(32),
		"index": str(bin(16))[2:].zfill(32).find("1"),
	},
	LDAP_UF_PASSWD_NOTREQD: {
		"value": 32,
		"val_bin": str(bin(32))[2:].zfill(32),
		"index": str(bin(32))[2:].zfill(32).find("1"),
	},
	LDAP_UF_PASSWD_CANT_CHANGE: {
		"value": 64,
		"val_bin": str(bin(64))[2:].zfill(32),
		"index": str(bin(64))[2:].zfill(32).find("1"),
	},
	LDAP_UF_ENCRYPTED_TEXT_PASSWORD_ALLOWED: {
		"value": 128,
		"val_bin": str(bin(128))[2:].zfill(32),
		"index": str(bin(128))[2:].zfill(32).find("1"),
	},
	LDAP_UF_NORMAL_ACCOUNT: {
		"value": 512,
		"val_bin": str(bin(512))[2:].zfill(32),
		"index": str(bin(512))[2:].zfill(32).find("1"),
	},
	LDAP_UF_INTERDOMAIN_TRUST_ACCOUNT: {
		"value": 2048,
		"val_bin": str(bin(2048))[2:].zfill(32),
		"index": str(bin(2048))[2:].zfill(32).find("1"),
	},
	LDAP_UF_WORKSTATION_TRUST_ACCOUNT: {
		"value": 4096,
		"val_bin": str(bin(4096))[2:].zfill(32),
		"index": str(bin(4096))[2:].zfill(32).find("1"),
	},
	LDAP_UF_SERVER_TRUST_ACCOUNT: {
		"value": 8192,
		"val_bin": str(bin(8192))[2:].zfill(32),
		"index": str(bin(8192))[2:].zfill(32).find("1"),
	},
	LDAP_UF_DONT_EXPIRE_PASSWD: {
		"value": 65536,
		"val_bin": str(bin(65536))[2:].zfill(32),
		"index": str(bin(65536))[2:].zfill(32).find("1"),
	},
	LDAP_UF_MNS_LOGON_ACCOUNT: {
		"value": 131072,
		"val_bin": str(bin(131072))[2:].zfill(32),
		"index": str(bin(131072))[2:].zfill(32).find("1"),
	},
	LDAP_UF_SMARTCARD_REQUIRED: {
		"value": 262144,
		"val_bin": str(bin(262144))[2:].zfill(32),
		"index": str(bin(262144))[2:].zfill(32).find("1"),
	},
	LDAP_UF_TRUSTED_FOR_DELEGATION: {
		"value": 524288,
		"val_bin": str(bin(524288))[2:].zfill(32),
		"index": str(bin(524288))[2:].zfill(32).find("1"),
	},
	LDAP_UF_NOT_DELEGATED: {
		"value": 1048576,
		"val_bin": str(bin(1048576))[2:].zfill(32),
		"index": str(bin(1048576))[2:].zfill(32).find("1"),
	},
	LDAP_UF_USE_DES_KEY_ONLY: {
		"value": 2097152,
		"val_bin": str(bin(2097152))[2:].zfill(32),
		"index": str(bin(2097152))[2:].zfill(32).find("1"),
	},
	LDAP_UF_DONT_REQUIRE_PREAUTH: {
		"value": 4194304,
		"val_bin": str(bin(4194304))[2:].zfill(32),
		"index": str(bin(4194304))[2:].zfill(32).find("1"),
	},
	LDAP_UF_PASSWORD_EXPIRED: {
		"value": 8388608,
		"val_bin": str(bin(8388608))[2:].zfill(32),
		"index": str(bin(8388608))[2:].zfill(32).find("1"),
	},
	LDAP_UF_TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION: {
		"value": 16777216,
		"val_bin": str(bin(16777216))[2:].zfill(32),
		"index": str(bin(16777216))[2:].zfill(32).find("1"),
	},
	LDAP_UF_NO_AUTH_DATA_REQUIRED: {
		"value": 33554432,
		"val_bin": str(bin(33554432))[2:].zfill(32),
		"index": str(bin(33554432))[2:].zfill(32).find("1"),
	},
	LDAP_UF_PARTIAL_SECRETS_ACCOUNT: {
		"value": 67108864,
		"val_bin": str(bin(67108864))[2:].zfill(32),
		"index": str(bin(67108864))[2:].zfill(32).find("1"),
	},
}


class LengthError(Exception):
	pass


def merge_val_bin(perm_a: str, perm_b: str):
	r = []
	if not isinstance(perm_a, str) or not isinstance(perm_b, str):
		raise TypeError("perm_a and perm_b must be binary values as string.")
	if len(perm_a) != 32 or len(perm_b) != 32:
		raise LengthError("Both permissions must be a 32bit binary string.")
	if not all(c in "01" for c in str(perm_a)):
		raise ValueError("perm_a must have a binary value as string.")
	if not all(c in "01" for c in str(perm_b)):
		raise ValueError("perm_b must have a binary value as string.")
	for c_a, c_b in zip(perm_a, perm_b):
		r.append(int(c_a) ^ int(c_b))  # XOR
	return "".join(str(v) for v in r)


LDAP_PERM_BIN_BASE = "0" * 32
LDAP_FILTER_OR = "|"
LDAP_FILTER_AND = "&"
LDAP_FILTER_NOT = "!"

LDAP_FILTER_EXPRESSION_TYPE = list[Literal["|", "&"]]
LDAP_FILTER_EXPRESSIONS: LDAP_FILTER_EXPRESSION_TYPE = ["|", "&"]
LDAP_FILTER_OPERATOR_TYPE = list[Literal["=", ">=", "<=", "~="]]
LDAP_FILTER_OPERATORS: LDAP_FILTER_OPERATOR_TYPE = ["=", ">=", "<=", "~="]
LDAP_BUILTIN_OBJECTS = [
	"Domain Controllers",
	"Computers",
	"Program Data",
	"System",
	"Builtin",
	"ForeignSecurityPrincipals",
	"Users",
	"Managed Service Accounts",
]


def is_encapsulated(v: str) -> bool:
	"""Check if a string is wrapped in parentheses."""
	if not isinstance(v, str):
		raise TypeError("is_encapsulated value must be of type str.")
	return v.startswith("(") and v.endswith(")")


def join_ldap_filter(
	filter_string: str,
	filter_to_add: str,
	expression: LDAP_FILTER_EXPRESSION_TYPE = LDAP_FILTER_AND,
	negate: bool = False,
	negate_add: bool = False,
) -> str:
	"""Combine two LDAP filters with a logical expression (AND/OR) and optionally negate the result.

	Args:
		filter_string (str): The base LDAP filter (can be empty).
		filter_to_add (str): The filter to append (required).
		expression (str, optional): LDAP expression ("&" or "|"). Defaults to "&".
		negate (bool, optional): Whether to negate the entire combined filter. Defaults to False.
		negate_add (bool, optional): Whether to negate the added filter. Defaults to False.

	Raises:
		ValueError: If `filter_to_add` is empty or expression is invalid.

	Returns:
		str: The combined LDAP filter.
	"""
	if not filter_to_add:
		raise ValueError("filter_to_add cannot be empty.")

	if isinstance(expression, str) and expression.lower() == "or":
		expression = LDAP_FILTER_OR
	if isinstance(expression, str) and expression.lower() == "and":
		expression = LDAP_FILTER_AND
	if expression not in LDAP_FILTER_EXPRESSIONS:
		raise ValueError(
			f"Invalid expression: {expression}. Must be one of {LDAP_FILTER_EXPRESSIONS}"
		)

	# Ensure both filters are properly encapsulated
	if filter_string and not is_encapsulated(filter_string):
		filter_string = f"({filter_string})"
	if not is_encapsulated(filter_to_add):
		filter_to_add = f"({filter_to_add})"
	if negate_add:
		filter_to_add = f"(!{filter_to_add})"

	# Combine filters with the expression
	if not filter_string:
		combined_filter = filter_to_add
	else:
		combined_filter = f"({expression}{filter_string}{filter_to_add})"

	# Apply negation if needed
	if negate:
		combined_filter = f"(!{combined_filter})"

	return combined_filter


# This is not used or tested yet
class LDAPFilter:  # pragma: no cover
	def __init__(self, filter_str: str = None):
		self._filter = filter_str or ""

	def _wrap(self, value: str) -> str:
		"""Ensure proper parentheses wrapping."""
		return f"({value})" if not value.startswith("(") else value

	def _validate_operator(self, operator: str):
		if not isinstance(operator, str):
			raise TypeError("LDAPFilter operator must be of type str.")
		if not operator in LDAP_FILTER_OPERATORS:
			raise ValueError(
				f"Invalid operator, must be one of [{','.join(LDAP_FILTER_OPERATORS)}]"
			)

	def _combine(self, operator: str, attribute: str, value: str, filter_op: str) -> "LDAPFilter":
		"""Core logic for combining filters."""
		self._validate_operator(operator)
		new_part = f"({attribute}{filter_op}{value})"

		if not self._filter:
			return LDAPFilter(new_part)

		combined = f"({operator}{self._wrap(self._filter)}{self._wrap(new_part)})"
		return LDAPFilter(combined)

	def c_and(self, attribute: str, value: str, operator: str = "=") -> "LDAPFilter":
		"""Add an AND condition."""
		return self._combine("&", attribute, value, operator)

	def c_or(self, attribute: str, value: str, operator: str = "=") -> "LDAPFilter":
		"""Add an OR condition."""
		return self._combine("|", attribute, value, operator)

	def negate(self) -> "LDAPFilter":
		"""Negate the entire filter."""
		if self._filter:
			return LDAPFilter(f"(!{self._filter})")
		return self

	def __str__(self) -> str:
		return self._filter


def search_filter_from_dict(
	filter_dict: dict, expression: LDAP_FILTER_EXPRESSION_TYPE = LDAP_FILTER_OR, reverse_key=False
):
	"""
	Valid Operators: | &
	"""
	search_filter = ""
	for object_key, object_type in filter_dict.items():
		_ldap_obj_key = object_key
		_ldap_obj_type = object_type
		if reverse_key:
			_ldap_obj_key = object_type
			_ldap_obj_type = object_key
		if isinstance(_ldap_obj_key, list):
			for obj in _ldap_obj_key:
				search_filter = join_ldap_filter(
					search_filter, f"{_ldap_obj_type}={obj}", expression
				)
		else:
			search_filter = join_ldap_filter(
				search_filter, f"{_ldap_obj_type}={_ldap_obj_key}", expression
			)
	return search_filter


def bin_as_str(value: str | int):
	if isinstance(value, int) and value < 0:
		raise ValueError("Integer value must be greater than 0")
	# If the input is a binary string, convert it directly to an integer with base 2
	if isinstance(value, str) and all(c in "01" for c in value):
		casted_int = int(value, 2)
	else:
		# Otherwise, treat it as a decimal integer
		casted_int = int(str(value))
	return str(bin(casted_int))[2:].zfill(32)


def bin_as_hex(value: str | int):
	if isinstance(value, str) and value == "":
		raise ValueError("Value cannot be empty string.")
	if all(c == "0" for c in value):
		return "0x0000"
	casted_bin = int(str(value).lstrip("0"), 2)
	casted_bin = hex(casted_bin)[2:].zfill(4)
	return str("0x" + casted_bin)


def list_perms():  # pragma: no cover
	"""List all the permissions in the LDAP_PERMS constant array/list

	Prints to console.
	"""
	for perm in LDAP_PERMS:
		print(perm + " = " + LDAP_PERMS[perm]["val_bin"] + ", " + str(LDAP_PERMS[perm]["index"]))


def parse_permissions_int(raw_user_permissions: int | str, user_name: str = None):
	"""
	Parses a raw LDAP Permission Integer Bitmap to a list.
	"""
	try:
		int(raw_user_permissions)
	except:
		raise ValueError("raw_user_permissions can only contain numeric characters.")
	if isinstance(raw_user_permissions, int) and not all(
		c in "01" for c in str(raw_user_permissions)
	):
		raw_user_permissions = str(bin(raw_user_permissions))[2:].zfill(32)
	else:
		raw_user_permissions = str(raw_user_permissions).zfill(32)
	permission_list = []
	i = 0

	for n in range(0, 32):  # Loop for each bit in 0-32
		i += 1
		if raw_user_permissions[n] == "1":  # If permission matches enter for loop to
			# search which one it is in the dictionary
			for perm_name in LDAP_PERMS:
				perm_binary = LDAP_PERMS[perm_name]["val_bin"]
				perm_index = LDAP_PERMS[perm_name]["index"]
				if perm_index == n:
					if user_name and isinstance(user_name, str):  # pragma: no cover
						logger.debug(f"User: {user_name}")
					logger.debug(f"Permission Name: {perm_name}")
					logger.debug(f"Permission Index: {str(perm_index)}")
					logger.debug(f"Permission Index (From User): {str(n)}")
					logger.debug(f"Permission Binary Value (From Constant): {perm_binary}")
					logger.debug(f"Permission Hex Value (From Constant): {bin_as_hex(perm_binary)}")
					permission_list.append(perm_name)
	if user_name and isinstance(user_name, str):  # pragma: no cover
		logger.debug(f"Permission List ({user_name}): ")
	else:
		logger.debug("Permission List:")
	logger.debug(permission_list)
	return permission_list


# Lists User permissions (LDAP / AD Servers save them as binary)
def list_user_perms(user, perm_search: str = None, user_is_object: bool = True) -> list | bool:
	"""
	### Creates a list of user permissions from raw LDAP Integer Bitmap
	* user: User dict or object.
	* perm_search:  Allows for directly returning a boolean when a specified
					permission is found.
	* user_is_object: Whether the user passed is an object or dict.

	Returns list.

	Returns bool if perm_search is used.
	"""
	# Cast raw integer user permissions as string
	uac_value = None
	if user_is_object is True:
		if not hasattr(user, "userAccountControl"):
			raise ValueError("User object does not contain a userAccountControl attribute.")
		uac_value = getattr(user, "userAccountControl")
		try:
			# ldap3 stores attribute values in .values field (which is a list).
			uac_value = uac_value.values[0]
		except:
			try:
				# Otherwise try a normal getattr from .value
				uac_value = uac_value.value
			except:
				pass
	else:
		if not "userAccountControl" in user:
			raise ValueError("User dictionary does not contain a userAccountControl key.")
		uac_value = user["userAccountControl"]

	if not uac_value:
		raise ValueError("Unable to process User Account Control value.")

	if uac_value != "[]":
		raw_user_permissions = bin_as_str(uac_value)
	else:
		return None

	user_permissions: list = parse_permissions_int(
		raw_user_permissions=raw_user_permissions,
		user_name=str(user[RuntimeSettings.LDAP_AUTH_USER_FIELDS["username"]]),
	)
	if isinstance(perm_search, str):
		return perm_search in user_permissions
	return user_permissions


def calc_permissions(
	permission_list: list, perm_add: Union[list, str] = None, perm_remove: Union[list, str] = None
):
	"""
	### Calculates permissions INT based on a desired array of Permission String Keys

	Args:
		permission_list (list): List of Permissions
		perm_add (list | str): Contains permission(s) to add to calculated result
		perm_remove (list | str): Contains permission(s) to remove from calculated result

	Returns:
		int
	"""
	perm_int = 0
	if not isinstance(permission_list, list) and not isinstance(permission_list, set):
		raise TypeError("permission_list must be a list or set.")
	permission_list = set(permission_list)

	# Add permissions selected in user creation
	for perm in permission_list:
		p_value = int(LDAP_PERMS[perm]["value"])
		perm_int += p_value
		logger.debug(f"Permission Value added (cast to string): {perm} = {str(p_value)}")

	# Add Permissions to list
	if perm_add and isinstance(perm_add, list):
		for perm in perm_add:
			if not perm in permission_list:
				p_value = int(LDAP_PERMS[perm]["value"])
				perm_int += p_value
				logger.debug(f"Permission Value added (cast to string): {perm} = {str(p_value)}")
	elif perm_add and not perm_add in permission_list:
		p_value = int(LDAP_PERMS[perm_add]["value"])
		perm_int += p_value
		logger.debug(f"Permission Value added (cast to string): {perm} = {str(p_value)}")

	# Remove permissions from list
	if perm_remove and isinstance(perm_remove, list):
		for perm in perm_remove:
			if perm in permission_list:
				p_value = int(LDAP_PERMS[perm]["value"])
				perm_int -= p_value
				logger.debug(f"Permission Value removed (cast to string): {perm} = {str(p_value)}")
	elif perm_remove and perm_remove in permission_list:
		p_value = int(LDAP_PERMS[perm_remove]["value"])
		perm_int -= p_value
		logger.debug(f"Permission Value removed (cast to string): {perm} = {str(p_value)}")

	# Final Result Log
	logger.debug(f"calc_permissions - Final User Permissions Value: {str(perm_int)}")

	return int(perm_int)
