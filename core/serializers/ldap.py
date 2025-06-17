################################################################################
#################### INTERLOCK IS LICENSED UNDER GNU AGPLv3 ####################
################## ORIGINAL PROJECT CREATED BY DYLAN BLANQUÉ ###################
########################## AND BR CONSULTING S.R.L. ############################
################################################################################
# Module: core.serializers.ldap
# Contains LDAP Serializer validator functions and REGEXs

# ---------------------------------- IMPORTS -----------------------------------#
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
	if not v.strip().lower() in [c.lower() for c in LDAP_COUNTRIES.keys()]:
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
		raise ValidationError(f"Website validation failed.")
	return v


class DistinguishedNameField(serializers.CharField):
	def __init__(self, **kwargs):
		if not "validators" in kwargs:
			kwargs["validators"] = [dn_validator_se]
		else:
			kwargs["validators"] = [dn_validator_se] + kwargs["validators"]
		super().__init__(**kwargs)
