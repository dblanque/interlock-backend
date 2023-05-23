################################################################################
#################### INTERLOCK IS LICENSED UNDER GNU AGPLv3 ####################
################## ORIGINAL PROJECT CREATED BY DYLAN BLANQUÉ ###################
########################## AND BR CONSULTING S.R.L. ############################
################################################################################
# Module: core.views.mixins.token
# Contains the Mixin for Token related operations

#---------------------------------- IMPORTS -----------------------------------#
### Exceptions
from core.exceptions import otp as exc_otp

### Others
import random
import string as mod_string
import re
import logging

from interlock_backend.ldap.constants_cache import LDAP_AUTH_ACTIVE_DIRECTORY_DOMAIN
################################################################################

logger = logging.getLogger(__name__)
from django_otp import devices_for_user
from django_otp.plugins.otp_totp.models import TOTPDevice

def get_user_totp_device(user, confirmed=None):
	devices = devices_for_user(user, confirmed=confirmed)
	for device in devices:
		if isinstance(device, TOTPDevice):
			return device

def parse_config_url(url: str):
	# Example URL
	# otpauth://totp/dblanque?secret=AKDOIJ2509FGJ934GJ3SRG30JRG3G00G&algorithm=SHA1&digits=6&period=30
	# totp/dblanque? totp is cap group 1 | dblanque is cap group 2 | everything else cap group 3
	if re.match(r'^.*totp/.*:.*$', url):
		return url
	label = "Interlock"
	regex = r'^(.*totp/)(?!.*:)(.*)(\?.*)$'
	return re.sub(regex, rf"\1{label}:\2@{LDAP_AUTH_ACTIVE_DIRECTORY_DOMAIN}\3", url)

def get_random_string(length):
    # With combination of lower and upper case
    result_str = ''.join(random.choice(mod_string.ascii_letters) for i in range(length))
    return result_str

def generate_recovery_codes(amount):
	codes = list()
	for i in range(amount):
		codes.append(f"{get_random_string(4)}-{get_random_string(4)}-{get_random_string(4)}")
	return codes

def create_device_totp_for_user(user):
	device = get_user_totp_device(user)
	if not device:
		device = user.totpdevice_set.create(confirmed=False)
		user.recovery_codes = generate_recovery_codes(5)
		user.save()
	return parse_config_url(device.config_url)

def fetch_device_totp_for_user(user):
	device = get_user_totp_device(user)
	if not device:
		return None
	return parse_config_url(device.config_url)

def delete_device_totp_for_user(user):
	device = get_user_totp_device(user)
	if not device:
		return True
	totp_device = TOTPDevice.objects.get(user_id=user.id)
	user.recovery_codes = list()
	user.save()
	return totp_device.delete()

def validate_user_otp(user, data):
	device = get_user_totp_device(user)

	if device is None:
		raise exc_otp.OTPNoDeviceRegistered
	elif device.verify_token(data['totp_code']):
		if not device.confirmed:
			device.confirmed = True
			device.save()
			# Successfully confirmed and saved device
			return True
		else:
			# OTP code has been verified.
			return True
	else:
		# Code is invalid
		raise exc_otp.OTPInvalidCode