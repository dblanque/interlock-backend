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

### Models
from core.views.mixins.logs import LogMixin
from core.models.choices.log import (
	LOG_ACTION_READ,
	LOG_ACTION_UPDATE,
	LOG_CLASS_SET,
	LOG_TARGET_ALL,
)
from core.models.ldap_settings import (
	LDAP_SETTING_MAP,
	LDAPSetting,
	LDAPPreset,
	LDAP_SETTINGS_CHOICES_MAP,
)

### Mixins
from core.views.mixins.ldap_settings import SettingsViewMixin
from core.views.mixins.ldap.user import LDAPUserBaseMixin

### Viewsets
from core.views.base import BaseViewSet

### Serializers
from core.serializers.ldap_settings import LDAPPresetSerializer

### REST Framework
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.decorators import action

### Others
from core.constants.attrs import (
	LOCAL_ATTR_ID,
	LOCAL_ATTR_NAME,
	LOCAL_ATTR_VALUE,
	LOCAL_ATTR_LABEL,
	LOCAL_ATTR_ACTIVE,
)
from core.constants.settings import K_LDAP_LOG_MAX
from core.decorators.login import auth_required, admin_required
from django.db import transaction
import logging
################################################################################

DBLogMixin = LogMixin()
logger = logging.getLogger(__name__)


class SettingsViewSet(BaseViewSet, SettingsViewMixin):
	ldap_setting_class = LDAPSetting

	@auth_required
	@admin_required
	def list(self, request: Request, pk=None):
		code = 0
		active_preset = self.get_active_settings_preset()

		presets = []
		for p in LDAPPreset.objects.all():
			presets.append(
				{
					LOCAL_ATTR_NAME: p.name,
					LOCAL_ATTR_ID: p.id,
					LOCAL_ATTR_LABEL: p.label,
					LOCAL_ATTR_ACTIVE: p.active or False,
				}
			)

		DBLogMixin.log(
			user=request.user.id,
			operation_type=LOG_ACTION_READ,
			log_target_class=LOG_CLASS_SET,
			log_target=LOG_TARGET_ALL,
		)

		return Response(
			data={
				"code": code,
				"code_msg": "ok",
				"presets": presets,
				"active_preset": active_preset.id,
			}
		)

	@action(detail=True, methods=["get"])
	@auth_required
	@admin_required
	def fetch(self, request: Request, pk):
		preset_id = int(pk)
		code = 0

		# Gets Front-End Parsed LDAP Settings
		ldap_settings = {}
		ldap_settings = self.get_ldap_settings(preset_id)
		local_settings = self.get_local_settings(preset_id)

		DBLogMixin.log(
			user=request.user.id,
			operation_type=LOG_ACTION_READ,
			log_target_class=LOG_CLASS_SET,
			log_target=LOG_TARGET_ALL,
		)

		return Response(
			data={
				"code": code,
				"code_msg": "ok",
				"settings": {
					"local": local_settings,
					"ldap": ldap_settings,
				},
			}
		)

	@action(detail=False, methods=["post"])
	@auth_required
	@admin_required
	def preset_create(self, request: Request, pk=None):
		code = 0
		if not LOCAL_ATTR_LABEL in request.data:
			raise exc_base.MissingDataKey(data={"detail": LOCAL_ATTR_LABEL})
		preset_label = request.data[LOCAL_ATTR_LABEL]
		if not isinstance(preset_label, str):
			raise exc_base.BadRequest(
				data={"detail": "Preset Label must be of type str."}
			)
		preset_name = self.normalize_preset_name(preset_label)
		if LDAPPreset.objects.filter(name=preset_name).exists():
			raise exc_set.SettingPresetExists
		preset = {LOCAL_ATTR_NAME: preset_name, LOCAL_ATTR_LABEL: preset_label}
		serializer = LDAPPresetSerializer(data=preset)
		if not serializer.is_valid():
			raise exc_set.SettingPresetSerializerError(
				data={"errors": serializer.errors}
			)

		preset_instance = LDAPPreset(**preset)
		preset_instance.save()

		return Response(data={"code": code, "code_msg": "ok"})

	@action(detail=False, methods=["post"])
	@auth_required
	@admin_required
	def preset_delete(self, request: Request, pk=None):
		data: dict = request.data
		code = 0
		if not LOCAL_ATTR_ID in data:
			raise exc_base.MissingDataKey(data={"key": LOCAL_ATTR_ID})
		preset_id = data[LOCAL_ATTR_ID]
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
	def preset_enable(self, request: Request, pk=None):
		data: dict = request.data
		code = 0
		if not LOCAL_ATTR_ID in data:
			raise exc_base.MissingDataKey(data={"key": LOCAL_ATTR_ID})
		preset_id = data[LOCAL_ATTR_ID]
		if not LDAPPreset.objects.filter(id=preset_id).exists():
			raise exc_set.SettingPresetNotExists
		with transaction.atomic():
			active_preset = self.get_active_settings_preset()
			active_preset.active = (
				None  # Don't set this to False, DB Constraints
			)
			active_preset.save()
			inactive_preset = LDAPPreset.objects.get(id=preset_id)
			inactive_preset.active = True
			inactive_preset.save()

		self.resync_settings()
		return Response(data={"code": code, "code_msg": "ok"})

	@action(detail=False, methods=["post"])
	@auth_required
	@admin_required
	def preset_rename(self, request: Request, pk=None):
		data: dict = request.data
		code = 0
		for k in [LOCAL_ATTR_ID, LOCAL_ATTR_LABEL]:
			if not k in data:
				raise exc_base.MissingDataKey(data={"key": k})
		preset_id = data[LOCAL_ATTR_ID]
		preset_label = data[LOCAL_ATTR_LABEL]
		if not LDAPPreset.objects.filter(id=preset_id).exists():
			raise exc_set.SettingPresetNotExists
		preset = LDAPPreset.objects.get(id=preset_id)

		serializer = LDAPPresetSerializer(
			data={
				LOCAL_ATTR_LABEL: preset_label,
				LOCAL_ATTR_NAME: self.normalize_preset_name(preset_label),
			}
		)
		if not serializer.is_valid():
			raise exc_set.SettingPresetSerializerError(
				data={"errors": serializer.errors}
			)
		preset.label = serializer.data[LOCAL_ATTR_LABEL]
		preset.name = serializer.data[LOCAL_ATTR_NAME]
		preset.save()

		return Response(data={"code": code, "code_msg": "ok"})

	@action(detail=False, methods=["post"])
	@auth_required
	@admin_required
	def save(self, request: Request, pk=None):
		data_preset: dict = request.data["preset"]
		data_settings: dict = request.data["settings"]
		code = 0
		settings_preset = None
		active_preset = None

		if data_preset and LOCAL_ATTR_ID in data_preset:
			try:
				settings_preset = LDAPPreset.objects.get(
					id=data_preset[LOCAL_ATTR_ID]
				)
			except:
				raise exc_set.SettingPresetNotExists
		else:
			raise exc_base.MissingDataKey(data={"key": "data.preset.id"})

		if K_LDAP_LOG_MAX in data_settings:
			if int(data_settings[K_LDAP_LOG_MAX][LOCAL_ATTR_VALUE]) > 10000:
				raise exc_set.SettingLogMaxLimit

		admin_enabled = data_settings.pop("DEFAULT_ADMIN_ENABLED", None)
		admin_password = data_settings.pop("DEFAULT_ADMIN_PWD", None)
		local_settings: dict = data_settings.pop("local")
		ldap_settings: dict = data_settings.pop("ldap")

		with transaction.atomic():
			self.set_admin_status(status=admin_enabled, password=admin_password)
			self.save_local_settings(local_settings)
			self.save_ldap_settings(ldap_settings, settings_preset)

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
	def reset(self, request: Request, pk=None):
		data: dict = request.data
		code = 0
		active_preset = self.get_active_settings_preset()

		LDAPSetting.objects.filter(preset_id=active_preset.id).delete()

		self.resync_settings()
		return Response(data={"code": code, "code_msg": "ok", "data": data})

	@action(detail=False, methods=["post"])
	@auth_required
	@admin_required
	def test(self, request: Request, pk=None):
		data: dict = request.data
		code = 0

		for param_name, param_data in data.items():
			param_type = LDAP_SETTING_MAP[param_name].lower()
			if param_type.upper() in LDAP_SETTINGS_CHOICES_MAP:
				if (
					param_data["value"]
					not in LDAP_SETTINGS_CHOICES_MAP[param_type.upper()]
				):
					raise exc_set.SettingTypeDoesNotMatch({"field": param_type})

		data = self.test_ldap_settings(data)
		if not data:
			raise ConnectionTestFailed

		return Response(data={"code": code, "code_msg": "ok", "data": data})

	@action(detail=False, methods=["get"])
	@auth_required
	@admin_required
	def sync_users(self, request: Request, pk=None):
		"""Synchronizes LDAP Users to Local Database"""
		synced_users, updated_users = LDAPUserBaseMixin().ldap_users_sync(
			responsible_user=request.user
		)

		return Response(
			data={
				"code": 0,
				"code_msg": "ok",
				"synced_users": synced_users,
				"updated_users": updated_users,
			}
		)

	@action(detail=False, methods=["get"])
	@auth_required
	@admin_required
	def prune_users(self, request: Request, pk=None):
		"""Prunes LDAP Users from Local Database"""
		pruned_users = LDAPUserBaseMixin().ldap_users_prune(
			responsible_user=request.user
		)
		return Response(
			data={"code": 0, "code_msg": "ok", "count": pruned_users}
		)

	@action(detail=False, methods=["get"])
	@auth_required
	@admin_required
	def purge_users(self, request: Request, pk=None):
		"""Synchronizes LDAP Users to Local Database"""
		logger.warning(f"LDAP User Purge requested by {request.user.username}")
		purged_users = LDAPUserBaseMixin().ldap_users_purge(
			responsible_user=request.user
		)

		return Response(
			data={"code": 0, "code_msg": "ok", "count": purged_users}
		)
