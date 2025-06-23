################################################################################
#################### INTERLOCK IS LICENSED UNDER GNU AGPLv3 ####################
################## ORIGINAL PROJECT CREATED BY DYLAN BLANQUÉ ###################
########################## AND BR CONSULTING S.R.L. ############################
################################################################################
# Module: core.models.validators.ldap_dns_record
# Contains the Validators for DNS Records
#
# ---------------------------------- IMPORTS --------------------------------- #
import sys
import logging
from rest_framework.serializers import ValidationError
from core.models.validators.networking import (
	ipv4_validator,
	ipv6_validator,
	port_validator,
)
from core.models.validators.dns import domain_validator
from core.models.structs.ldap_dns_record import RecordTypes

################################################################################
thismodule = sys.modules[__name__]
logger = logging.getLogger(__name__)


def record_type_validator(value: int):
	try:
		RecordTypes(value)
	except:
		raise ValidationError("dns_record_type_unsupported")


def ldap_uri_validator(uri_list: list[str]):
	for uri in uri_list:
		_exc = ValidationError("ldap_uri_invalid")
		if not uri.startswith("ldap://") and not uri.startswith("ldaps://"):
			raise _exc
		_uri_without_prefix = uri.split("//")[-1]
		_uri_split = _uri_without_prefix.split(":", 1)
		_valid_ipv4 = False
		_valid_ipv6 = False
		_valid_hostname = False
		try:
			ipv4_validator(_uri_split[0])
			_valid_ipv4 = True
		except:
			pass

		try:
			ipv6_validator(_uri_split[0])
			_valid_ipv6 = True
		except:
			pass

		try:
			domain_validator(_uri_split[0])
			_valid_hostname = True
		except:
			pass

		if not _valid_ipv4 and not _valid_ipv6 and not _valid_hostname:
			raise _exc
		port_validator(_uri_split[-1])
