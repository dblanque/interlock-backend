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
from .mixins.ldap_settings import SettingsViewMixin

### Viewsets
from .base import BaseViewSet

### Serializers
from core.serializers.ldap_settings import LDAPSettingSerializer

### REST Framework
from rest_framework.response import Response
from rest_framework.decorators import action

### Others
from interlock_backend.ldap import defaults
from interlock_backend.ldap.connector import LDAPConnector
from interlock_backend.ldap.encrypt import encrypt
from core.decorators.login import auth_required
from interlock_backend.ldap.defaults import *
from core.models.ldap_settings_db import *
from interlock_backend.ldap.settings_func import getSettingsList
import logging, ssl
################################################################################

logger = logging.getLogger(__name__)

class SettingsViewSet(BaseViewSet, SettingsViewMixin):

	@auth_required()
	def list(self, request, pk=None):
		user = request.user
		data = {}
		code = 0
		active_preset = self.get_active_settings_preset()

		presets = list()
		for p in LDAPPreset.objects.all():
			presets.append({
				"name": p.name,
				"id": p.id,
				"label": p.label
			})

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
				'presets': presets,
				'active_preset': active_preset.id
			 }
		)

	@auth_required()
	@action(detail=True, methods=['get'])
	def fetch(self, request, pk):
		user = request.user
		preset_id = int(pk)
		data = {}
		code = 0

		# Gets front-end parsed settings
		data = getSettingsList(preset_id)
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
		preset_id = None
		preset_label = None
		preset_name = None

		if "PRESET_ID" in data:
			try: settings_preset = LDAPPreset.objects.get(id=data.pop("PRESET_ID"))
			except: raise exc_set.SettingPresetNotExists
		elif "PRESET_LABEL" in data:
			preset_label: str = data.pop("PRESET_LABEL")
			preset_name = preset_label.replace(" ", "_").lower()
			preset_id = data.pop("PRESET_ID")
			if LDAPPreset.objects.filter(active=True, id=preset_id).count() == 0:
				settings_preset = LDAPPreset.objects.create(label=preset_label, name=preset_name)
		else:
			settings_preset = LDAPPreset.objects.get(name="default")

		if 'LDAP_LOG_MAX' in data:
			if int(data['LDAP_LOG_MAX']['value']) > 10000:
				raise exc_set.SettingLogMaxLimit

		adminEnabled = data.pop('DEFAULT_ADMIN_ENABLED')
		adminPassword = data.pop('DEFAULT_ADMIN_PWD')
		self.set_admin_status(status=adminEnabled, password=adminPassword)
		for param_name, param_value in data.items():
			if not param_name in CMAPS:
				raise exc_set.SettingTypeDoesNotMatch
			param_to_update = None
			param_type = CMAPS[param_name].lower()
			param_value = param_value.pop("value")
			is_default = False
			if param_name == "LDAP_AUTH_TLS_VERSION":
				is_default = (getattr(ssl, param_value) == getattr(defaults, param_name, None))
			else:
				is_default = (param_value == getattr(defaults, param_name, None))
			if is_default:
				try:
					if LDAPSetting.objects.filter(name=param_name).exists():
						LDAPSetting.objects.get(name=param_name).delete_permanently()
				except:
					pass
			else:
				if param_type == "password":
					param_value = encrypt(param_value)
				kwdata = {
					"name": param_name,
					"type": param_type.upper(),
					f"v_{param_type}": param_value,
					"preset": settings_preset
				}
				for setting_type in LDAP_SETTING_TYPES_LIST:
					setting_key = f"v_{setting_type.lower()}"
					# Set other field types in row as null
					if setting_key != f"v_{param_type}":
						kwdata[setting_key] = None
				serializer = LDAPSettingSerializer(data=kwdata)
				if not serializer.is_valid():
					raise exc_set.SettingSerializerError(data={
						'key': setting_key
					})

				if param_type.upper() in LDAP_SETTINGS_CHOICES_MAP:
					if param_value not in LDAP_SETTINGS_CHOICES_MAP[param_type.upper()]:
						raise exc_set.SettingTypeDoesNotMatch

				if LDAPSetting.objects.filter(name=param_name).exists():
					param_to_update = LDAPSetting.objects.get(name=param_name)
					for kw, kw_v in kwdata.items():
						setattr(param_to_update, kw, kw_v)
					param_to_update.save()
				else:
					LDAPSetting.objects.create(**kwdata)

		if LDAP_LOG_UPDATE == True:
			# Log this action to DB
			logToDB(
				user_id=request.user.id,
				actionType="UPDATE",
				objectClass="SET",
			)

		self.restart_django()
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
		active_preset = self.get_active_settings_preset()

		try: LDAPSetting.objects.filter(preset_id=active_preset.id).delete()
		except: raise

		self.restart_django()
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
