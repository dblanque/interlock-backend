################################################################################
#################### INTERLOCK IS LICENSED UNDER GNU AGPLv3 ####################
################## ORIGINAL PROJECT CREATED BY DYLAN BLANQUÉ ###################
########################## AND BR CONSULTING S.R.L. ############################
################################################################################
# Module: interlock_backend.ldap.settings

# ---------------------------------- IMPORTS -----------------------------------#
# Core Imports
from core.models.user import User
from core.models.ldap_settings import LDAP_SETTING_MAP, LDAPSetting
from enum import Enum

# Interlock Imports
from django.core.exceptions import ObjectDoesNotExist
from interlock_backend.settings import DEFAULT_SUPERUSER_USERNAME
from core.ldap import defaults
from core.constants.attrs.local import LOCAL_ATTR_VALUE, LOCAL_ATTR_TYPE
from core.constants.settings import (
	K_LDAP_AUTH_TLS_VERSION,
	K_LDAP_AUTH_CONNECTION_PASSWORD,
)
from interlock_backend.encrypt import aes_decrypt

# Full imports
import logging
################################################################################

logger = logging.getLogger(__name__)


def get_setting_list(preset_id: int = 1) -> dict[dict]:
	"""Returns a Dictionary with the current setting values in the system"""
	data = {}
	userQuerySet = User.objects.filter(username=DEFAULT_SUPERUSER_USERNAME)
	if userQuerySet.count() > 0:
		defaultAdmin = userQuerySet.get(username=DEFAULT_SUPERUSER_USERNAME)
		data["DEFAULT_ADMIN"] = not defaultAdmin.deleted
	else:
		data["DEFAULT_ADMIN"] = False

	# Loop for each constant in the ldap_constants.py file
	for setting_key, setting_type in LDAP_SETTING_MAP.items():
		setting_instance = None
		data[setting_key] = {}
		data[setting_key][LOCAL_ATTR_TYPE] = setting_type.lower()
		try:
			setting_instance = LDAPSetting.objects.get(
				preset_id=preset_id, name=setting_key
			)

			if setting_key == K_LDAP_AUTH_CONNECTION_PASSWORD:
				try:
					data[setting_key][LOCAL_ATTR_VALUE] = aes_decrypt(
						*setting_instance.value
					)
				except:
					data[setting_key][LOCAL_ATTR_VALUE] = ""
					logger.error("Could not decrypt password")
					pass
			else:
				data[setting_key][LOCAL_ATTR_VALUE] = setting_instance.value
				if setting_key == K_LDAP_AUTH_TLS_VERSION and isinstance(
					setting_instance.value, Enum
				):
					data[setting_key][LOCAL_ATTR_VALUE] = setting_instance.value.name
		except ObjectDoesNotExist:
			data[setting_key][LOCAL_ATTR_VALUE] = getattr(defaults, setting_key)
			if setting_key == K_LDAP_AUTH_TLS_VERSION and isinstance(
				data[setting_key][LOCAL_ATTR_VALUE], Enum
			):
				data[setting_key][LOCAL_ATTR_VALUE] = data[setting_key][LOCAL_ATTR_VALUE].name
	return data
