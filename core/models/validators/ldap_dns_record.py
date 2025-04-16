################################################################################
#################### INTERLOCK IS LICENSED UNDER GNU AGPLv3 ####################
################## ORIGINAL PROJECT CREATED BY DYLAN BLANQUÉ ###################
########################## AND BR CONSULTING S.R.L. ############################
################################################################################
# Module: core.models.validators.ldap_dns_record
# Contains the Validators for DNS Records
#
# ---------------------------------- IMPORTS -----------------------------------#
import sys
import logging
import re
import socket
from core.utils.ipv6 import ipv6_to_integer

thismodule = sys.modules[__name__]
logger = logging.getLogger(__name__)

def int32_validator(value):
	try:
		if int(value) < 4294967296 and re.match(r"^[0-9]{0,10}$", str(value)):
			return True
	except:
		pass
	return False


def port_validator(value: int):
	try:
		value = int(value)
		return 0 < value <= 65535
	except:
		return False


def natural_validator(value: str | int):
	if not isinstance(value, (str, int)):
		return False
	try:
		if re.match(r"^[0-9]+$", str(value)):
			return True
	except Exception as e:
		print(value)
		print(type(value))
		raise e
	return False


def canonical_hostname_validator(value: str, trailing_dot=True, allow_underscores=True):
	if not isinstance(value, str):
		return False
	if not value:
		return False
	# src: https://stackoverflow.com/questions/2532053/validate-a-hostname-string
	if len(value) > 253:
		return False

	labels = value.split(".")

	# the TLD must be not all-numeric
	if re.match(r"[0-9]+$", labels[-1]):
		return False

	if allow_underscores:
		re_pattern = r"(?!-)[a-z0-9-_]{1,63}(?<!-)$"
	else:
		re_pattern = r"(?!-)[a-z0-9-]{1,63}(?<!-)$"
	allowed = re.compile(re_pattern, re.IGNORECASE)

	if trailing_dot:
		if not value.endswith("."):
			return False
		return all(allowed.match(label) for label in labels[:-1])
	else:
		return all(allowed.match(label) for label in labels)

def srv_target_validator(value: str):
	return canonical_hostname_validator(value, trailing_dot=True, allow_underscores=True)


def domain_validator(value):
	return canonical_hostname_validator(value, trailing_dot=False)


def ipv4_validator(value: str):
	if not isinstance(value, str):
		return False
	if not value:
		return False
	try:
		socket.inet_aton(str(value))
		# Check octet count, disallow incomplete addressing
		parts = str(value).split(".")
		return len(parts) == 4 and all(part.isdigit() for part in parts)
	except socket.error:
		return False
	return True


def ipv6_validator(value: str):
	if not isinstance(value, str):
		return False
	if not value:
		return False
	try:
		ipv6_to_integer(value)
	except socket.error:
		return False
	return True


def ascii_validator(value):
	if not isinstance(value, str):
		return False
	if not value:
		return True
	# https://stackoverflow.com/questions/35889505/check-that-a-string-contains-only-ascii-characters
	isAscii = lambda s: re.match(r"^[\x00-\x7f]+$", s) is not None
	return isAscii(value)

def length255_validator(value: str):
	try:
		return len(value) < 255
	except:
		return False


FIELD_VALIDATORS = {
	"tstime": None,
	"serial": int32_validator,
	"address": ipv4_validator,
	"ipv6Address": ipv6_validator,
	"nameNode": canonical_hostname_validator,
	"dwSerialNo": natural_validator,
	"dwRefresh": natural_validator,
	"dwRetry": natural_validator,
	"dwExpire": natural_validator,
	"dwMinimumTtl": natural_validator,
	"namePrimaryServer": canonical_hostname_validator,
	"zoneAdminEmail": canonical_hostname_validator,
	"stringData": [
		ascii_validator,
		length255_validator,
	],
	"wPreference": natural_validator,
	"nameExchange": canonical_hostname_validator,
	"wPriority": natural_validator,
	"wWeight": natural_validator,
	"wPort": port_validator,
	"nameTarget": srv_target_validator,
}
