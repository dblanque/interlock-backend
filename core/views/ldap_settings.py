################################################################################
#################### INTERLOCK IS LICENSED UNDER GNU AGPLv3 ####################
################## ORIGINAL PROJECT CREATED BY DYLAN BLANQUÉ ###################
########################## AND BR CONSULTING S.R.L. ############################
################################################################################
# Module: core.views.settings
# Contains the ViewSet for System Setting related operations
#
# ---------------------------------- IMPORTS -----------------------------------#
### Exceptions
from core.exceptions.ldap import ConnectionTestFailed
from core.exceptions import (
	base as exc_base,
	ldap_settings as exc_set,
)
from django.core.exceptions import ObjectDoesNotExist

### Models
from core.views.mixins.logs import LogMixin
from core.models.types.settings import TYPE_AES_ENCRYPT
from core.models.choices.log import LOG_ACTION_READ, LOG_ACTION_UPDATE, LOG_CLASS_SET, LOG_TARGET_ALL
from core.models.interlock_settings import (
	InterlockSetting,
	INTERLOCK_SETTING_PUBLIC,
	INTERLOCK_SETTING_MAP,
)
from core.models.ldap_settings import (
	LDAP_SETTING_MAP,
	LDAPSetting,
	LDAPPreset,
	LDAP_SETTINGS_CHOICES_MAP,
)

### Mixins
from core.views.mixins.ldap_settings import SettingsViewMixin

### Viewsets
from core.views.base import BaseViewSet

### Serializers
from core.serializers.ldap_settings import LDAPSettingSerializer, LDAPPresetSerializer
from core.serializers.interlock_settings import InterlockSettingSerializer

### REST Framework
from rest_framework.response import Response
from rest_framework.decorators import action

### Others
from core.ldap import defaults
from interlock_backend.encrypt import aes_encrypt
from core.decorators.login import auth_required, admin_required
from core.config.runtime import RuntimeSettings
from core.ldap.ldap_settings import get_setting_list
from django.db import transaction
import logging, ssl
################################################################################

DBLogMixin = LogMixin()
logger = logging.getLogger(__name__)


class SettingsViewSet(BaseViewSet, SettingsViewMixin):
	ldap_setting_class = LDAPSetting

	@auth_required
	@admin_required
	def list(self, request, pk=None):
		code = 0
		active_preset = self.get_active_settings_preset()

		presets = []
		for p in LDAPPreset.objects.all():
			presets.append(
				{"name": p.name, "id": p.id, "label": p.label, "active": p.active or False}
			)

		DBLogMixin.log(
			user=request.user.id,
			operation_type=LOG_ACTION_READ,
			log_target_class=LOG_CLASS_SET,
			log_target=LOG_TARGET_ALL
		)

		return Response(
			data={
				"code": code,
				"code_msg": "ok",
				"presets": presets,
				"active_preset": active_preset.id,
			}
		)

	@auth_required()
	@action(detail=True, methods=["get"])
	def fetch(self, request, pk):
		preset_id = int(pk)
		code = 0

		# Gets Front-End Parsed LDAP Settings
		ldap_settings = {}
		ldap_settings = get_setting_list(preset_id)
		ldap_settings["DEFAULT_ADMIN_ENABLED"] = self.get_admin_status()

		DBLogMixin.log(
			user=request.user.id,
			operation_type=LOG_ACTION_READ,
			log_target_class=LOG_CLASS_SET,
			log_target=LOG_TARGET_ALL
		)

		interlock_settings = {}
		for setting_key in INTERLOCK_SETTING_PUBLIC:
			setting_instance = InterlockSetting.objects.get(name=setting_key)
			interlock_settings[setting_key] = {
				"value": setting_instance.value,
				"type": setting_instance.type,
			}
		return Response(
			data={
				"code": code,
				"code_msg": "ok",
				"settings": {
					"local": interlock_settings,
					"ldap": ldap_settings,
				},
			}
		)

	@action(detail=False, methods=["post"])
	@auth_required
	@admin_required
	def preset_create(self, request, pk=None):
		code = 0
		if not "label" in request.data:
			raise exc_base.MissingDataKey(data={"detail": "label"})
		preset_label = str(request.data["label"])
		preset_name = self.normalize_preset_name(preset_label)
		if LDAPPreset.objects.filter(name=preset_name).exists():
			raise exc_set.SettingPresetExists
		preset = {"name": preset_name, "label": preset_label}
		serializer = LDAPPresetSerializer(data=preset)
		if not serializer.is_valid():
			raise exc_set.SettingPresetSerializerError(data={"errors": serializer.errors})
		LDAPPreset.objects.create(**preset)

		return Response(data={"code": code, "code_msg": "ok"})

	@action(detail=False, methods=["post"])
	@auth_required
	@admin_required
	def preset_delete(self, request, pk=None):
		data: dict = request.data
		code = 0
		if not "id" in data:
			raise exc_base.MissingDataKey(data={"key": "id"})
		preset_id = data["id"]
		if not LDAPPreset.objects.filter(id=preset_id).exists():
			raise exc_set.SettingPresetNotExists
		active_preset = self.get_active_settings_preset()
		if active_preset.id == preset_id:
			raise exc_set.SettingPresetMustBeDisabled
		LDAPPreset.objects.get(id=preset_id).delete_permanently()
		return Response(data={"code": code, "code_msg": "ok"})

	@action(detail=False, methods=["post"])
	@auth_required
	@admin_required
	def preset_enable(self, request, pk=None):
		data: dict = request.data
		code = 0
		if not "id" in data:
			raise exc_base.MissingDataKey(data={"key": "id"})
		preset_id = data["id"]
		if not LDAPPreset.objects.filter(id=preset_id).exists():
			raise exc_set.SettingPresetNotExists
		with transaction.atomic():
			active_preset = self.get_active_settings_preset()
			active_preset.active = None  # Don't set this to False, DB Constraints
			active_preset.save()
			inactive_preset = LDAPPreset.objects.get(id=preset_id)
			inactive_preset.active = True
			inactive_preset.save()

		self.resync_settings()
		return Response(data={"code": code, "code_msg": "ok"})

	@action(detail=False, methods=["post"])
	@auth_required
	@admin_required
	def preset_rename(self, request, pk=None):
		data: dict = request.data
		code = 0
		for k in ["id", "label"]:
			if not k in data:
				raise exc_base.MissingDataKey(data={"key": k})
		preset_id = data["id"]
		preset_label = data["label"]
		if not LDAPPreset.objects.filter(id=preset_id).exists():
			raise exc_set.SettingPresetNotExists
		preset = LDAPPreset.objects.get(id=preset_id)

		serializer = LDAPPresetSerializer(
			data={
				"label": preset_label,
				"name": self.normalize_preset_name(preset_label),
			}
		)
		if not serializer.is_valid():
			raise exc_set.SettingPresetSerializerError(data={"errors": serializer.errors})
		preset.label = serializer.data["label"]
		preset.name = serializer.data["name"]
		preset.save()

		return Response(data={"code": code, "code_msg": "ok"})

	@action(detail=False, methods=["post"])
	@auth_required
	@admin_required
	def save(self, request, pk=None):
		data_preset: dict = request.data["preset"]
		data_settings: dict = request.data["settings"]
		code = 0
		settings_preset = None
		active_preset = None

		if "id" in data_preset:
			try:
				settings_preset = LDAPPreset.objects.get(id=data_preset["id"])
			except:
				raise exc_set.SettingPresetNotExists
		else:
			raise exc_base.MissingDataKey(data={"key": "data.preset.id"})

		# active_preset = self.get_active_settings_preset()
		# current_settings = get_setting_list(active_preset)
		if "LDAP_LOG_MAX" in data_settings:
			if int(data_settings["LDAP_LOG_MAX"]["value"]) > 10000:
				raise exc_set.SettingLogMaxLimit

		adminEnabled = data_settings.pop("DEFAULT_ADMIN_ENABLED")
		adminPassword = data_settings.pop("DEFAULT_ADMIN_PWD")
		local_settings: dict = data_settings.pop("local")
		ldap_settings: dict = data_settings.pop("ldap")
		self.set_admin_status(status=adminEnabled, password=adminPassword)

		with transaction.atomic():
			param_name: str
			param_value: dict
			for param_name, param_value in local_settings.items():
				if not param_name in INTERLOCK_SETTING_MAP:
					raise exc_set.SettingTypeDoesNotMatch(data={"field": param_name})
				param_type = INTERLOCK_SETTING_MAP[param_name]
				param_value = param_value.pop("value")
				kwdata = {"name": param_name, "type": param_type.lower(), "value": param_value}

				serializer = InterlockSettingSerializer(data=kwdata)
				if not serializer.is_valid():
					raise exc_set.SettingSerializerError(
						data={"key": param_name, "errors": serializer.errors}
					)

				try:
					setting_instance = InterlockSetting.objects.get(name=param_name)
					for attr in kwdata:
						setattr(setting_instance, attr, kwdata[attr])
					setting_instance.save()
				except ObjectDoesNotExist:
					InterlockSetting.objects.create(**kwdata)

			for param_name, param_value in ldap_settings.items():
				if not param_name in LDAP_SETTING_MAP:
					raise exc_set.SettingTypeDoesNotMatch(data={"field": param_name})
				param_type = LDAP_SETTING_MAP[param_name]
				param_value = param_value.pop("value")

				is_default = False
				if param_name == "LDAP_AUTH_TLS_VERSION":
					is_default = getattr(ssl, param_value) == getattr(defaults, param_name, None)
				else:
					is_default = param_value == getattr(defaults, param_name, None)

				if is_default:
					try:
						if LDAPSetting.objects.filter(
							name=param_name, preset_id=settings_preset
						).exists():
							LDAPSetting.objects.get(
								name=param_name, preset_id=settings_preset
							).delete_permanently()
					except:
						pass
				else:
					kwdata = {
						"name": param_name,
						"type": param_type.lower(),
						"preset": settings_preset,
					}

					if param_type == TYPE_AES_ENCRYPT.lower():
						kwdata["value"] = aes_encrypt(param_value)
					else:
						kwdata["value"] = param_value

					serializer = LDAPSettingSerializer(data=kwdata)
					if not serializer.is_valid():
						raise exc_set.SettingSerializerError(
							data={"key": param_name, "errors": serializer.errors}
						)

					try:
						setting_instance = LDAPSetting.objects.get(
							name=param_name, preset_id=settings_preset
						)
						for attr in kwdata:
							setattr(setting_instance, attr, kwdata[attr])
						setting_instance.save()
					except ObjectDoesNotExist:
						LDAPSetting.objects.create(**kwdata)

		DBLogMixin.log(
			user=request.user.id,
			operation_type=LOG_ACTION_UPDATE,
			log_target_class=LOG_CLASS_SET,
		)

		self.resync_settings()
		return Response(
			data={
				"code": code,
				"code_msg": "ok",
			}
		)

	@action(detail=False, methods=["get"])
	@auth_required
	@admin_required
	def reset(self, request, pk=None):
		data: dict = request.data
		code = 0
		active_preset = self.get_active_settings_preset()

		LDAPSetting.objects.filter(preset_id=active_preset.id).delete()

		self.resync_settings()
		return Response(data={"code": code, "code_msg": "ok", "data": data})

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

	@action(detail=False, methods=["post"])
	@auth_required
	@admin_required
	def test(self, request, pk=None):
		data: dict = request.data
		code = 0

		for param_name, param_data in data.items():
			param_type = LDAP_SETTING_MAP[param_name].lower()
			if param_type.upper() in LDAP_SETTINGS_CHOICES_MAP:
				if param_data["value"] not in LDAP_SETTINGS_CHOICES_MAP[param_type.upper()]:
					raise exc_set.SettingTypeDoesNotMatch({"field": param_type})

		data = self.test_ldap_settings(data)
		if not data:
			raise ConnectionTestFailed

		return Response(data={"code": code, "code_msg": "ok", "data": data})
