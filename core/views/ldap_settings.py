################################################################################
#################### INTERLOCK IS LICENSED UNDER GNU AGPLv3 ####################
################## ORIGINAL PROJECT CREATED BY DYLAN BLANQUÉ ###################
########################## AND BR CONSULTING S.R.L. ############################
################################################################################
# Module: core.views.settings
# Contains the ViewSet for System Setting related operations
#
#---------------------------------- IMPORTS -----------------------------------#
### Exceptions
from core.exceptions.ldap import ConnectionTestFailed
from core.exceptions import (
	base as exc_base,
	ldap_settings as exc_set,
)

### Models
from core.views.mixins.logs import LogMixin
from core.models.ldap_settings import (
	CMAPS,
	LDAPSetting,
	LDAPPreset,
	LDAP_SETTING_TYPES_LIST,
	LDAP_SETTINGS_CHOICES_MAP,
	LDAP_SETTING_PREFIX,
)

### Mixins
from .mixins.ldap_settings import SettingsViewMixin

### Viewsets
from .base import BaseViewSet

### Serializers
from core.serializers.ldap_settings import LDAPSettingSerializer, LDAPPresetSerializer

### REST Framework
from rest_framework.response import Response
from rest_framework.decorators import action

### Others
from interlock_backend.ldap import defaults
from interlock_backend.encrypt import aes_encrypt
from core.decorators.login import auth_required
from core.models.ldap_settings_db import RunningSettings
from interlock_backend.ldap.settings import getSettingsList
import logging, ssl
################################################################################

DBLogMixin = LogMixin()
logger = logging.getLogger(__name__)

class SettingsViewSet(BaseViewSet, SettingsViewMixin):

	@auth_required()
	def list(self, request, pk=None):
		code = 0
		active_preset = self.get_active_settings_preset()

		presets = list()
		for p in LDAPPreset.objects.all():
			presets.append({
				"name": p.name,
				"id": p.id,
				"label": p.label,
				"active": p.active or False
			})

		if RunningSettings.LDAP_LOG_READ == True:
			# Log this action to DB
			DBLogMixin.log(
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
		preset_id = int(pk)
		data = {}
		code = 0

		# Gets front-end parsed settings
		data = getSettingsList(preset_id)
		data['DEFAULT_ADMIN_ENABLED'] = self.get_admin_status()

		if RunningSettings.LDAP_LOG_READ == True:
			# Log this action to DB
			DBLogMixin.log(
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
	def preset_create(self, request, pk=None):
		code = 0
		if not "label" in request.data:
			raise exc_base.MissingDataKey(data={"detail":"label"})
		preset_label = str(request.data["label"])
		preset_name = self.normalize_preset_name(preset_label)
		if LDAPPreset.objects.filter(name=preset_name).exists():
			raise exc_set.SettingPresetExists
		preset = {
			"name": preset_name,
			"label": preset_label
		}
		serializer = LDAPPresetSerializer(data=preset)
		if not serializer.is_valid():
			raise exc_set.SettingPresetSerializerError(data={
				"errors": serializer.errors
			})
		LDAPPreset.objects.create(**preset)

		return Response(
			data={
				'code': code,
				'code_msg': 'ok'
			}
		)

	@action(detail=False, methods=['post'])
	@auth_required()
	def preset_delete(self, request, pk=None):
		data: dict = request.data
		code = 0
		if not "id" in data:
			raise exc_base.MissingDataKey(data={"key":"id"})
		preset_id = data["id"]
		if not LDAPPreset.objects.filter(id=preset_id).exists():
			raise exc_set.SettingPresetNotExists
		active_preset = self.get_active_settings_preset()
		if active_preset.id == preset_id:
			raise exc_set.SettingPresetMustBeDisabled
		LDAPPreset.objects.get(id=preset_id).delete_permanently()
		return Response(
			data={
				'code': code,
				'code_msg': 'ok'
			}
		)

	@action(detail=False, methods=['post'])
	@auth_required()
	def preset_enable(self, request, pk=None):
		data: dict = request.data
		code = 0
		if not "id" in data:
			raise exc_base.MissingDataKey(data={"key":"id"})
		preset_id = data["id"]
		if not LDAPPreset.objects.filter(id=preset_id).exists():
			raise exc_set.SettingPresetNotExists
		active_preset = self.get_active_settings_preset()
		active_preset.active = None # Don't set this to False, DB Constraints
		active_preset.save()
		inactive_preset = LDAPPreset.objects.get(id=preset_id)
		inactive_preset.active = True
		inactive_preset.save()

		self.resync_settings()
		return Response(
			data={
				'code': code,
				'code_msg': 'ok'
			}
		)

	@action(detail=False, methods=['post'])
	@auth_required()
	def preset_rename(self, request, pk=None):
		data: dict = request.data
		code = 0
		for k in ["id","label"]:
			if not k in data:
				raise exc_base.MissingDataKey(data={"key": k})
		preset_id = data["id"]
		preset_label = data["label"]
		if not LDAPPreset.objects.filter(id=preset_id).exists():
			raise exc_set.SettingPresetNotExists
		preset = LDAPPreset.objects.get(id=preset_id)

		serializer = LDAPPresetSerializer(data={
			"label": preset_label,
			"name": self.normalize_preset_name(preset_label),
		})
		if not serializer.is_valid():
			raise exc_set.SettingPresetSerializerError(data={
				"errors": serializer.errors
			})
		preset.label = serializer.data["label"]
		preset.name = serializer.data["name"]
		preset.save()

		return Response(
			data={
				'code': code,
				'code_msg': 'ok'
			}
		)

	@action(detail=False, methods=['post'])
	@auth_required()
	def save(self, request, pk=None):
		data_preset: dict = request.data["preset"]
		data_settings: dict = request.data["settings"]
		code = 0
		settings_preset = None
		active_preset = None

		if "id" in data_preset:
			try: settings_preset = LDAPPreset.objects.get(id=data_preset["id"])
			except: raise exc_set.SettingPresetNotExists
		else:
			raise exc_base.MissingDataKey(data={"key":"data.preset.id"})

		try: active_preset = self.get_active_settings_preset()
		except: raise

		if 'LDAP_LOG_MAX' in data_settings:
			if int(data_settings['LDAP_LOG_MAX']['value']) > 10000:
				raise exc_set.SettingLogMaxLimit

		adminEnabled = data_settings.pop('DEFAULT_ADMIN_ENABLED')
		adminPassword = data_settings.pop('DEFAULT_ADMIN_PWD')
		self.set_admin_status(status=adminEnabled, password=adminPassword)
		for param_name, param_value in data_settings.items():
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
					if LDAPSetting.objects.filter(name=param_name, preset_id=settings_preset).exists():
						LDAPSetting.objects.get(name=param_name, preset_id=settings_preset).delete_permanently()
				except:
					pass
			else:
				kwdata = {
					"name": param_name,
					"type": param_type.upper(),
					"preset": settings_preset,
				}

				if param_type == "password":
					encrypted_data = aes_encrypt(param_value)
					kwdata = kwdata | {
						f"{LDAP_SETTING_PREFIX}_password_aes": encrypted_data[0],
						f"{LDAP_SETTING_PREFIX}_password_ct": encrypted_data[1],
						f"{LDAP_SETTING_PREFIX}_password_nonce": encrypted_data[2],
						f"{LDAP_SETTING_PREFIX}_password_tag": encrypted_data[3],
					}
				else:
					kwdata[f"{LDAP_SETTING_PREFIX}_{param_type}"] = param_value

				for setting_type in LDAP_SETTING_TYPES_LIST:
					setting_key = f"{LDAP_SETTING_PREFIX}_{setting_type.lower()}"
					# Set other field types in row as null
					if setting_key != f"{LDAP_SETTING_PREFIX}_{param_type}":
						kwdata[setting_key] = None
				serializer = LDAPSettingSerializer(data=kwdata)
				if not serializer.is_valid():
					raise exc_set.SettingSerializerError(data={
						'key': setting_key
					})

				if param_type.upper() in LDAP_SETTINGS_CHOICES_MAP:
					if param_value not in LDAP_SETTINGS_CHOICES_MAP[param_type.upper()]:
						raise exc_set.SettingTypeDoesNotMatch

				if LDAPSetting.objects.filter(name=param_name, preset_id=settings_preset).exists():
					param_to_update = LDAPSetting.objects.get(name=param_name, preset_id=settings_preset)
					for kw, kw_v in kwdata.items():
						setattr(param_to_update, kw, kw_v)
					param_to_update.save()
				else:
					LDAPSetting.objects.create(**kwdata)

		if RunningSettings.LDAP_LOG_UPDATE == True:
			# Log this action to DB
			DBLogMixin.log(
				user_id=request.user.id,
				actionType="UPDATE",
				objectClass="SET",
			)

		self.resync_settings()
		return Response(
			 data={
				'code': code,
				'code_msg': 'ok',
				'settings': data_settings,
				'restart': True
			 }
		)

	@action(detail=False, methods=['get'])
	@auth_required()
	def reset(self, request, pk=None):
		data: dict = request.data
		code = 0
		active_preset = self.get_active_settings_preset()

		try: LDAPSetting.objects.filter(preset_id=active_preset.id).delete()
		except: raise

		self.resync_settings()
		return Response(
			 data={
				'code': code,
				'code_msg': 'ok',
				'data': data
			 }
		)

	# TODO
	# @action(detail=False, methods=['post'])
	# @auth_required()
	# def manualcmd(self, request, pk=None):
	# 	user = request.user
	# 	data = request.data
	# 	code = 0

	# 	operation = data['operation']
	# 	op_dn = data['dn']
	# 	op_object = data['op_object']
	# 	op_filter = data['op_filter']
	# 	op_attributes = data['op_attributes']

	# 	# Open LDAP Connection
	# 	try:
	# 		self.ldap_connection = LDAPConnector(user.dn, user.encryptedPassword, request.user).connection
	# 	except Exception as e:
	# 		print(e)
	# 		raise exc_ldap.CouldNotOpenConnection

	# 	# Unbind the connection
	# 	self.ldap_connection.unbind()
	# 	return Response(
	# 		 data={
	# 			'code': code,
	# 			'code_msg': 'ok',
	# 			'data': data
	# 		 }
	# 	)

	@action(detail=False, methods=['post'])
	@auth_required()
	def test(self, request, pk=None):
		data: dict = request.data
		code = 0

		for param_name, param_data in data.items():
			param_type = CMAPS[param_name].lower()
			if param_type.upper() in LDAP_SETTINGS_CHOICES_MAP:
				if param_data["value"] not in LDAP_SETTINGS_CHOICES_MAP[param_type.upper()]:
					raise exc_set.SettingTypeDoesNotMatch({"field": param_type})

		data = self.test_ldap_settings(data)
		if not data:
			raise ConnectionTestFailed

		return Response(
			 data={
				'code': code,
				'code_msg': 'ok',
				'data': data
			 }
		)
