from rest_framework import serializers
from rest_framework.serializers import ValidationError
import re
from ldap3.utils.dn import parse_dn
from core.ldap.adsi import LDAP_PERMS
from core.ldap.countries import LDAP_COUNTRIES

def ldap_user_validator(v: str):
	def has_invalid_chars(s: str):
		return re.match(r'.*[\.\@\]\["\:\;\|\=\+\*\?\<\>\/\\\,]', s) is not None
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
	try:
		for codes in LDAP_COUNTRIES.values():
			if int(codes.get("dccCode")) == v:
				return v
	except:
		pass
	raise ValidationError(f"Country DCC code ({v}) not found.")

def country_iso_validator(v: str):
	if len(v) > 2:
		raise ValidationError("Country ISO code cannot be longer than 2 chars.")
	try:
		for codes in LDAP_COUNTRIES.values():
			if codes.get("isoCode") == v:
				return v
	except:
		pass
	raise ValidationError(f"Country DCC code ({v}) not found.")

def ldap_permission_validator(v: str):
	if not v in LDAP_PERMS.keys():
		raise ValidationError(f"LDAP Permission is invalid ({v}).")
	return v

class DistinguishedNameField(serializers.CharField):
	def __init__(self, **kwargs):
		if not "required" in kwargs:
			kwargs["required"] = False
		if not "validators" in kwargs:
			kwargs["validators"] = [dn_validator_se]
		super().__init__(**kwargs)
