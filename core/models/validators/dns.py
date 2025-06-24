################################################################################
#################### INTERLOCK IS LICENSED UNDER GNU AGPLv3 ####################
################## ORIGINAL PROJECT CREATED BY DYLAN BLANQUÉ ###################
########################## AND BR CONSULTING S.R.L. ############################
################################################################################
# Module: core.models.validators.dns
# Contains validators for DNS related fields.

# ---------------------------------- IMPORTS --------------------------------- #
import re
from rest_framework.serializers import ValidationError
################################################################################


def canonical_hostname_validator(
	value: str, trailing_dot=True, allow_underscores=True
) -> None:
	_exc = ValidationError("invalid_field_canonical_hostname")
	if not isinstance(value, str):
		raise _exc
	if not value:
		raise _exc
	# src: https://stackoverflow.com/questions/2532053/validate-a-hostname-string
	if len(value) > 253:
		raise _exc

	labels = value.split(".")

	# the TLD must be not all-numeric
	if re.match(r"[0-9]+$", labels[-1]):
		raise _exc

	if allow_underscores:
		re_pattern = r"(?!-)[a-z0-9-_]{1,63}(?<!-)$"
	else:
		re_pattern = r"(?!-)[a-z0-9-]{1,63}(?<!-)$"
	allowed = re.compile(re_pattern, re.IGNORECASE)

	if trailing_dot:
		if not value.endswith("."):
			raise _exc
		if not all(allowed.match(label) for label in labels[:-1]):
			raise _exc
	else:
		if not all(allowed.match(label) for label in labels):
			raise _exc


def srv_target_validator(value: str) -> None:
	canonical_hostname_validator(
		value, trailing_dot=True, allow_underscores=True
	)


def domain_validator(value) -> None:
	canonical_hostname_validator(value, trailing_dot=False)
