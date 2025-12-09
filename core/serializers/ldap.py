################################################################################
#################### INTERLOCK IS LICENSED UNDER GNU AGPLv3 ####################
################## ORIGINAL PROJECT CREATED BY DYLAN BLANQUÉ ###################
########################## AND BR CONSULTING S.R.L. ############################
################################################################################
# Module: core.serializers.ldap
# Contains LDAP Serializer validator functions and REGEXs

# ---------------------------------- IMPORTS --------------------------------- #
from rest_framework import serializers
from rest_framework.serializers import ValidationError
import re
from ldap3.utils.dn import parse_dn
from core.ldap.adsi import LDAP_PERMS
from core.ldap.countries import LDAP_COUNTRIES
################################################################################

WEBSITE_RE = re.compile(
	r"^((?:http(?:s){0,5}(:\/\/){0,1}){0,1}(?:[a-zA-Z0-9-_.]){2,61}(?:\.[a-zA-Z]{2,})+)?/?$"
)


def validate_name_simple(name: str) -> tuple[bool, str]:
	"""
	Simple but permissive name validator using only standard library.
	Supports multi-language names by allowing any non-control character.

	Args:
	    name (str): The name to validate

	Returns:
	    tuple: (is_valid, error_message)
	"""
	SPECIAL_THRESHOLD = 5

	if not isinstance(name, str):
		return False, "value must be a string"

	# Strip whitespace for validation but keep original for checking
	stripped_name = name.strip()

	# Check for control characters or other problematic Unicode categories
	# Any control character, format character, surrogate, or private use char
	if re.search(r"[\x00-\x1F\x7F-\x9F\u200B\uFEFF\uFFF9-\uFFFF]", name):
		return False, "value contains invalid control characters"

	# Check for numbers and symbols (but allow some common name-related symbols)
	if re.search(r"[\d@#$%^*+=_|<>\[\]{}]", name):
		return False, "value contains invalid characters (numbers or symbols)"

	# Check for excessive special characters that are allowed
	allowed_special = r"'\(\)\-. "
	special_count = sum(1 for char in name if char in allowed_special)

	if special_count > SPECIAL_THRESHOLD:
		return False, "value contains too many special characters"

	# Check for consecutive special characters (except spaces)
	if re.search(r"['\-\.]{2,}", name):
		return False, "value cannot have consecutive special characters"

	# Check if name starts or ends with special characters (except spaces)
	if re.match(r"^['\-\.]", stripped_name):
		return False, "value cannot start with special character"

	if re.search(r"['\-]$", stripped_name):
		return False, "value cannot end with special character"

	# Check if the name is only special characters
	if re.fullmatch(r"['\-\. ]+", stripped_name):
		return False, "value cannot consist only of special characters"

	return True, ""


def name_validator(v: str):
	valid, reason = validate_name_simple(v)
	if not valid:
		raise ValidationError(reason.capitalize())
	return v


def ldap_user_validator(v: str):
	def has_invalid_chars(s: str):
		return (
			re.match(r'.*[\.\@\]\["\:\;\|\=\+\*\?\<\>\/\\\,\s]', s) is not None
		)

	return not has_invalid_chars(v)


def ldap_user_validator_se(v: str):
	if not ldap_user_validator(v):
		raise ValidationError("Username contains invalid characters.")
	return v


def dn_validator_se(v: str):
	try:
		parse_dn(v)
	except:
		raise ValidationError("Could not parse Distinguished Name.")
	return v


def country_validator(v: str):
	if v.strip().lower() not in [c.lower() for c in LDAP_COUNTRIES.keys()]:
		raise ValidationError("Invalid country name.")
	return v


def country_dcc_validator(v: int):
	if v is False or v is None:
		raise ValidationError("Country DCC must be a numeric value.")
	try:
		if isinstance(v, (str, int)) and int(v) == 0:
			return True
		for codes in LDAP_COUNTRIES.values():
			if int(codes.get("dccCode")) == int(v):
				return v
	except:
		raise ValidationError(f"Country DCC code ({v}) is invalid.")
	raise ValidationError(f"Country DCC code ({v}) not found.")


def country_iso_validator(v: str):
	if len(v) > 2:
		raise ValidationError("Country ISO code cannot be longer than 2 chars.")
	try:
		for codes in LDAP_COUNTRIES.values():
			if codes.get("isoCode") == v:
				return v
	except:
		raise ValidationError(f"Country DCC code ({v}) is invalid.")
	raise ValidationError(f"Country DCC code ({v}) not found.")


def ldap_permission_validator(v: str):
	if not v in LDAP_PERMS.keys():
		raise ValidationError(f"LDAP Permission is invalid ({v}).")
	return v


def website_validator(v: str):
	if not WEBSITE_RE.match(v):
		raise ValidationError("Website validation failed.")
	return v


class DistinguishedNameField(serializers.CharField):
	def __init__(self, **kwargs):
		if "validators" not in kwargs:
			kwargs["validators"] = [dn_validator_se]
		else:
			kwargs["validators"] = [dn_validator_se] + kwargs["validators"]
		super().__init__(**kwargs)
