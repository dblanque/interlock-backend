################################################################################
#################### INTERLOCK IS LICENSED UNDER GNU AGPLv3 ####################
################## ORIGINAL PROJECT CREATED BY DYLAN BLANQUÉ ###################
########################## AND BR CONSULTING S.R.L. ############################
################################################################################
# Module: core.models.validators.common
# Contains commonly used validators.

# ---------------------------------- IMPORTS -----------------------------------#
import re
from rest_framework.serializers import ValidationError
################################################################################


def int32_validator(value) -> None:
	_exc = ValidationError("invalid_field_int32")
	try:
		if int(value) < 4294967296 and re.match(r"^[0-9]{0,10}$", str(value)):
			return
		else:
			raise _exc
	except:
		raise _exc


def natural_validator(value: str | int) -> None:
	_exc = ValidationError("invalid_field_natural_number")
	if not isinstance(value, (str, int)):
		raise _exc
	if not re.match(r"^[0-9]+$", str(value)):
		raise _exc


def ascii_validator(value) -> None:
	_exc = ValidationError("invalid_field_ascii")
	if not isinstance(value, str):
		raise _exc
	if not value:
		return
	# https://stackoverflow.com/questions/35889505/check-that-a-string-contains-only-ascii-characters
	isAscii = lambda s: re.match(r"^[\x00-\x7f]+$", s) is not None
	if not isAscii(value):
		raise _exc
