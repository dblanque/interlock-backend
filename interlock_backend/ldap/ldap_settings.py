################################################################################
#################### INTERLOCK IS LICENSED UNDER GNU AGPLv3 ####################
################## ORIGINAL PROJECT CREATED BY DYLAN BLANQUÉ ###################
########################## AND BR CONSULTING S.R.L. ############################
################################################################################
# Module: interlock_backend.ldap.settings

#---------------------------------- IMPORTS -----------------------------------#
# Core Imports
from core.models.user import User
from core.models.ldap_settings import (
	CMAPS,
	LDAPSetting,
	LDAP_SETTING_PREFIX,
	LDAP_TYPE_PASSWORD_FIELDS,
)
from enum import Enum
# Interlock Imports
from interlock_backend.ldap import defaults
from interlock_backend.encrypt import aes_decrypt
from rest_framework import serializers

# Full imports
import traceback
import logging
################################################################################

logger = logging.getLogger(__name__)

def getSettingType(settingKey):
	# Set the Type for the Front-end based on Types in List
	settingType = CMAPS[settingKey]
	if not settingType:
		raise TypeError(f"No type set for {settingKey}")
	return settingType

def normalizeValues(settingKey, settingDict):
	"""
	Normalizes values from DB String to whatever type of object it is

	Arguments

	settingKey (STRING) - (The key for the Setting Constant or DB Override)

	settingDict (DICT) - (The dict to normalize)
	"""

	try:
		settingDict['type'] = getSettingType(settingKey)
	except Exception as e:
		print(settingKey)
		raise e

	listTypes = [ 'list', 'object', 'ldap_uri', 'array', 'tuple' ]

	try:
		# INT
		if settingDict['type'] == 'integer':
			if not serializers.IntegerField().run_validation(settingDict['value']):
				logger.error(traceback.format_exc())
				raise
			settingDict['value'] = int(settingDict['value'])
		# FLOAT
		elif settingDict['type'] == 'float':
			if not serializers.FloatField().run_validation(settingDict['value']):
				logger.error(traceback.format_exc())
				raise
			settingDict['value'] = float(settingDict['value'])
		# LIST/ARRAY OR OBJECT
		elif (settingDict['type'] in listTypes):
			settingDict['value'] = settingDict['value']
		# BOOLEAN
		elif settingDict['type'] == 'boolean':
			if settingDict['value'] == "1" or settingDict['value'] == 1 or settingDict['value'] == 'true' or settingDict['value'] == 'True':
				settingDict['value'] = True
			else:
				settingDict['value'] = False
			if not type(serializers.BooleanField().run_validation(settingDict['value'])) == bool:
				logger.error(traceback.format_exc())
				raise

		if settingKey == "LDAP_AUTH_TLS_VERSION":
			settingDict['value'] = str(settingDict['value']).split('.')[-1]
	except:
		raise ValueError(f"Invalid value for {settingKey}: {settingDict['value']} ({type(settingDict['value'])})")
	return settingDict

def getSettingsList(preset_id: int=1):
	"""Returns a Dictionary with the current setting values in the system

		Arguments:

		settingList (STRING) - Default is CMAPS

		listFormat (STRING) - frontend or backend

		BACKEND - Returns Object
		FRONTEND - Returns Dict with values and types
	"""

	data = {}
	userQuerySet = User.objects.filter(username = 'admin')
	if userQuerySet.count() > 0:
		defaultAdmin = userQuerySet.get(username = 'admin')
		data['DEFAULT_ADMIN'] = not defaultAdmin.deleted
	else:
		data['DEFAULT_ADMIN'] = False

	# Loop for each constant in the ldap_constants.py file
	relevant_parameters = LDAPSetting.objects.filter(preset_id=preset_id)
	for setting_key, setting_type in CMAPS.items():
		setting_type: str
		# Init Object/Dict
		data[setting_key] = {}
		ldap_setting = None
		if not setting_type.startswith(f"{LDAP_SETTING_PREFIX}_"):
			normalized_type = f"{LDAP_SETTING_PREFIX}_{setting_type.lower()}"
		else:
			normalized_type = setting_type

		data[setting_key]['type'] = getSettingType(setting_key).lower()
		default_value = getattr(defaults, setting_key)
		if relevant_parameters.filter(name=setting_key).exists():
			try:
				ldap_setting = relevant_parameters.get(name=setting_key)
			except:
				pass

		if setting_key == "LDAP_AUTH_CONNECTION_PASSWORD":
			try:
				data[setting_key]['value'] = aes_decrypt(
					*[getattr(ldap_setting, field) for field in LDAP_TYPE_PASSWORD_FIELDS]
				)
			except:
				data[setting_key]['value'] = ""
				print("Could not decrypt password")
				pass
		else:
			data[setting_key]['value'] = getattr(ldap_setting, normalized_type, default_value)

			if setting_key == "LDAP_AUTH_TLS_VERSION":
				_value = getattr(ldap_setting, normalized_type, default_value)
				if isinstance(_value, Enum):
					data[setting_key]['value'] = _value.name
	return data
