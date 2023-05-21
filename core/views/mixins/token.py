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
import traceback
import re
import logging
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
	# totp/dblanque?
	if re.match(r'^.*totp/.*:.*$', url):
		return url
	label = "Interlock"
	regex = r'^(.*totp/)(?!.*:)(.*)(\?.*)$'
	return re.sub(regex, rf"\1{label}:\2\3", url)

def create_device_totp_for_user(user):
	device = get_user_totp_device(user)
	if not device:
		device = user.totpdevice_set.create(confirmed=False)
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