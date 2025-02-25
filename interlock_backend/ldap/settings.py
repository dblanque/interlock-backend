################################################################################
#################### INTERLOCK IS LICENSED UNDER GNU AGPLv3 ####################
################## ORIGINAL PROJECT CREATED BY DYLAN BLANQUÉ ###################
########################## AND BR CONSULTING S.R.L. ############################
################################################################################
# Module: interlock_backend.ldap.settings

#---------------------------------- IMPORTS -----------------------------------#
# Core Imports
from core.models.user import User
from core.models.ldap_settings import CMAPS, LDAPSetting
from enum import Enum

# Interlock Imports
from interlock_backend.ldap import defaults
from interlock_backend.ldap.encrypt import decrypt
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
	for k, value_type in CMAPS.items():
		# Init Object/Dict
		data[k] = dict()
		ldap_setting = None
		value_type = f"v_{value_type.lower()}"

		data[k]['type'] = getSettingType(k).lower()
		default_value = getattr(defaults, k)
		if relevant_parameters.filter(name=k).exists():
			try:
				ldap_setting = relevant_parameters.get(name=k)
			except:
				pass
		data[k]['value'] = getattr(ldap_setting, value_type, default_value)

		if k == "LDAP_AUTH_CONNECTION_PASSWORD" and data[k]['value'] is not None:
			try:
				data[k]['value'] = decrypt(data[k]['value'])
			except:
				data[k]['value'] = ""
				print("Could not decrypt password")
				pass
		if k == "LDAP_AUTH_TLS_VERSION":
			if isinstance(data[k]['value'], Enum):
				data[k]['value'] = data[k]['value'].name

	return data
