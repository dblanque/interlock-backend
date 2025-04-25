################################################################################
#################### INTERLOCK IS LICENSED UNDER GNU AGPLv3 ####################
################## ORIGINAL PROJECT CREATED BY DYLAN BLANQUÉ ###################
########################## AND BR CONSULTING S.R.L. ############################
################################################################################
# Module: core.views.mixins.totp
# Contains the Mixin for TOTP related operations

# ---------------------------------- IMPORTS -----------------------------------#
### Models
from core.config.runtime import RuntimeSettings
from core.models.user import User

### Exceptions
from core.exceptions import otp as exc_otp

### Others
import random
import string as mod_string
import re
import logging

from interlock_backend.settings import DEBUG as INTERLOCK_DEBUG
################################################################################

logger = logging.getLogger(__name__)
from django_otp import devices_for_user
from django_otp.plugins.otp_totp.models import TOTPDevice


def get_user_totp_device(user: User, confirmed=None) -> TOTPDevice:
	devices = devices_for_user(user, confirmed=confirmed)
	for device in devices:
		if isinstance(device, TOTPDevice):
			return device


TOTP_WITH_LABEL_RE = re.compile(r"^.*totp/.*:.*$")
TOTP_CAPTURE_RE = re.compile(r"^(.*totp/)(?!.*:)(.*)(\?.*)$")


def set_interlock_otp_label(url: str, user: User) -> str:
	# Example URL
	# otpauth://totp/dblanque?secret=AKDOIJ2509FGJ934GJ3SRG30JRG3G00G&algorithm=SHA1&digits=6&period=30
	# totp/dblanque? totp is cap group 1 | dblanque is cap group 2 | everything else cap group 3
	if TOTP_WITH_LABEL_RE.match(url):
		return url

	# For readability
	_realm = str(RuntimeSettings.LDAP_AUTH_ACTIVE_DIRECTORY_DOMAIN)
	_domain = str(RuntimeSettings.LDAP_DOMAIN)

	# If user has custom email or different domain email, use that.
	_user_ident = getattr(user, "email", None)
	if not _user_ident:
		_user_ident = rf"\2@{_domain}"
	if INTERLOCK_DEBUG:
		label = f"Interlock DEVELOPMENT {_realm}"
	else:
		label = f"Interlock {_realm}"

	return TOTP_CAPTURE_RE.sub(rf"\1{label}:{_user_ident}\3", url)


def get_random_string(length: int) -> str:
	# With combination of lower and upper case
	result_str = "".join(
		random.choice(mod_string.ascii_letters) for i in range(length)
	)
	return result_str


def generate_recovery_codes(amount: int) -> list[str]:
	codes = []
	for i in range(amount):
		codes.append(
			f"{get_random_string(4)}-{get_random_string(4)}-{get_random_string(4)}"
		)
	return codes


def create_device_totp_for_user(user: User) -> str:
	device = get_user_totp_device(user)
	if not device:
		logger.debug("TOTP Device created for user %s", user.username)
		device = user.totpdevice_set.create(confirmed=False)
		user.recovery_codes = generate_recovery_codes(5)
		user.save()
	return set_interlock_otp_label(device.config_url, user)


def fetch_device_totp_for_user(user: User) -> str:
	device = get_user_totp_device(user)
	if not device:
		return None
	return set_interlock_otp_label(device.config_url, user)


def delete_device_totp_for_user(user: User) -> tuple[int, dict[str, int]]:
	device = get_user_totp_device(user)
	if not device:
		return True
	totp_device = TOTPDevice.objects.get(user_id=user.id)
	user.recovery_codes = []
	user.save()
	logger.info("TOTP Device deleted for user %s", user.username)
	return totp_device.delete()


def validate_user_otp(
	user: User, data: dict, raise_exc=True
) -> bool | Exception:
	"""
	Returns an Exception on validation failure unless specified.
	"""
	device = get_user_totp_device(user)

	if device is None and raise_exc is True:
		logger.warning(
			"User %s attempted to validate non-existing TOTP Device.",
			user.username,
		)
		raise exc_otp.OTPNoDeviceRegistered
	elif device and device.verify_token(data["totp_code"]):
		if not device.confirmed:
			device.confirmed = True
			device.save()
			# Successfully confirmed and saved device
			logger.debug(
				"TOTP Device newly confirmed for user %s", user.username
			)
			return True
		else:
			# OTP code has been verified.
			logger.debug(
				"TOTP Device already confirmed for user %s", user.username
			)
			return True
	elif raise_exc is True:
		# Code is invalid
		logger.warning("User %s entered invalid TOTP Code.", user.username)
		raise exc_otp.OTPInvalidCode
	return False
