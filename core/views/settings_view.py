################################################################################
#################### INTERLOCK IS LICENSED UNDER GNU AGPLv3 ####################
################## ORIGINAL PROJECT CREATED BY DYLAN BLANQUÉ ###################
########################## AND BR CONSULTING S.R.L. ############################
################################################################################
# Module: core.views.settings
# Contains the ViewSet for System Setting related operations

#---------------------------------- IMPORTS -----------------------------------#
### Exceptions
from core.exceptions.ldap import ConnectionTestFailed
from core.exceptions import (
	settings_exc as exc_set,
	ldap as exc_ldap
)

### Models
from core.models.log import logToDB
from core.models.ldap_settings import (
	CMAPS,
	LDAPSetting,
	LDAPPreset,
	LDAP_SETTING_TYPES_LIST,
	LDAP_SETTINGS_CHOICES_MAP
)

### Mixins
from .mixins.settings_mixin import SettingsViewMixin

### Viewsets
from .base import BaseViewSet

### REST Framework
from rest_framework.response import Response
from rest_framework.exceptions import NotFound
from rest_framework.decorators import action

### Others
from interlock_backend.ldap import constants
from interlock_backend.ldap.connector import LDAPConnector
from interlock_backend.ldap.cacher import saveToCache, resetCacheToDefaults
from interlock_backend.ldap.encrypt import encrypt, decrypt
from core.decorators.login import auth_required
from interlock_backend.ldap.constants_cache import *
from interlock_backend.ldap.settings_func import (
	getSettingsList,
	normalizeValues
)
import logging
import ssl
################################################################################

logger = logging.getLogger(__name__)

class SettingsViewSet(BaseViewSet, SettingsViewMixin):

	@auth_required()
	def list(self, request, pk=None):
		user = request.user
		data = {}
		code = 0

		# Gets front-end parsed settings
		data = getSettingsList()
		data['DEFAULT_ADMIN_ENABLED'] = self.get_admin_status()

		if LDAP_LOG_READ == True:
			# Log this action to DB
			logToDB(
				user_id=request.user.id,
				actionType="READ",
				objectClass="SET",
				affectedObject="ALL"
			)

		return Response(
			 data={
				'code': code,
				'code_msg': 'ok',
				'settings': data
			 }
		)

	@action(detail=False, methods=['post'])
	@auth_required()
	def save(self, request, pk=None):
		user = request.user
		data: dict = request.data
		code = 0

		if "PRESET_ID" in data:
			settings_preset_id = data.pop("PRESET_ID")
			try:
				settings_preset = LDAPPreset.objects.get(id=settings_preset_id)
			except:
				raise exc_set.SettingPresetNotExists
		else:
			settings_preset = LDAPPreset.objects.get(name="default")

		adminEnabled = data.pop('DEFAULT_ADMIN_ENABLED')
		adminPassword = data.pop('DEFAULT_ADMIN_PWD')
		self.set_admin_status(status=adminEnabled, password=adminPassword)
		for param_name, param_value in data.items():
			param_value = param_value.pop("value")
			param_to_update = None
			param_to_delete = None
			if not param_name in CMAPS:
				raise exc_set.SettingTypeDoesNotMatch
			param_type = CMAPS[param_name].lower()
			is_default = (param_value == getattr(constants, param_name))
			if is_default:
				try:
					param_to_delete = LDAPSetting.objects.get(name=param_name)
					param_to_delete.delete_permanently()
				except:
					pass
			else:
				if param_type == "password":
					param_value = encrypt(param_value)
				kwargs = {
					"name": param_name,
					"type": param_type,
					f"v_{param_type}": param_value,
					"preset": settings_preset
				}
				if param_type.upper() in LDAP_SETTINGS_CHOICES_MAP:
					if param_value not in LDAP_SETTINGS_CHOICES_MAP[param_type.upper()]:
						raise exc_set.SettingTypeDoesNotMatch

				param_to_update = LDAPSetting.objects.get(name=param_name)
				if param_to_update:
					for setting_type in LDAP_SETTING_TYPES_LIST:
						setting_key = f"v_{setting_type.lower()}"
						if setting_key != f"v_{param_type}":
							print(f"{setting_key} does not belong in {param_name}")
							setattr(param_to_update, setting_key, None)
					for kw, kw_v in kwargs.items():
						setattr(param_to_update, kw, kw_v)
					param_to_update.save()
				else:
					LDAPSetting.objects.create(**kwargs)

		# if 'LDAP_LOG_MAX' in data:
		# 	if int(data['LDAP_LOG_MAX']['value']) > 10000:
		# 		raise exc_set.SettingLogMaxLimit

		# data['LDAP_AUTH_CONNECTION_USERNAME'] = dict()
		# data['LDAP_AUTH_CONNECTION_USERNAME']['value'] = data['LDAP_AUTH_CONNECTION_USER_DN']['value'].split(',')[0].split('CN=')[1].lower()
		# affectedObjects = saveToCache(newValues=data)

		# if LDAP_LOG_UPDATE == True:
		# 	# Log this action to DB
		# 	logToDB(
		# 		user_id=request.user.id,
		# 		actionType="UPDATE",
		# 		objectClass="SET",
		# 		affectedObject=affectedObjects
		# 	)

		return Response(
			 data={
				'code': code,
				'code_msg': 'ok',
				'settings': data
			 }
		)

	@action(detail=False, methods=['get'])
	@auth_required()
	def reset(self, request, pk=None):
		user = request.user
		data = request.data
		code = 0

		data = resetCacheToDefaults()

		return Response(
			 data={
				'code': code,
				'code_msg': 'ok',
				'data': data
			 }
		)

	# TODO
	@action(detail=False, methods=['post'])
	@auth_required()
	def manualcmd(self, request, pk=None):
		user = request.user
		data = request.data
		code = 0

		operation = data['operation']
		op_dn = data['dn']
		op_object = data['op_object']
		op_filter = data['op_filter']
		op_attributes = data['op_attributes']

		# Open LDAP Connection
		try:
			self.ldap_connection = LDAPConnector(user.dn, user.encryptedPassword, request.user).connection
		except Exception as e:
			print(e)
			raise exc_ldap.CouldNotOpenConnection

		# Unbind the connection
		self.ldap_connection.unbind()
		return Response(
			 data={
				'code': code,
				'code_msg': 'ok',
				'data': data
			 }
		)

	@action(detail=False, methods=['post'])
	@auth_required()
	def test(self, request, pk=None):
		user = request.user
		data = request.data
		code = 0

		data = self.test_ldap_settings(user, data)

		if not data:
			raise ConnectionTestFailed

		return Response(
			 data={
				'code': code,
				'code_msg': 'ok',
				'data': data
			 }
		)
