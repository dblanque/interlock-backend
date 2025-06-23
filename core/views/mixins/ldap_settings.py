################################################################################
#################### INTERLOCK IS LICENSED UNDER GNU AGPLv3 ####################
################## ORIGINAL PROJECT CREATED BY DYLAN BLANQUÉ ###################
########################## AND BR CONSULTING S.R.L. ############################
################################################################################
# Module: core.views.mixins.ldap_settings
# Contains the Mixin for Setting related operations

# ---------------------------------- IMPORTS --------------------------------- #
### Django
from django.db import transaction

### ViewSets
from rest_framework import viewsets

### Core
from interlock_backend.settings import DEFAULT_SUPERUSER_USERNAME
from interlock_backend.encrypt import aes_decrypt, aes_encrypt
from core.config.runtime import RuntimeSettings
from core.ldap.connector import (
	test_ldap_connection,
	LDAPConnector,
	LDAPConnectionOptions,
)
from core.utils.db import db_table_exists

#### Models
from core.models.interlock_settings import (
	InterlockSetting,
	INTERLOCK_SETTING_PUBLIC,
	INTERLOCK_SETTING_MAP,
	INTERLOCK_SETTING_ENABLE_LDAP,
)
from core.models.user import User
from core.models.ldap_settings import (
	LDAPPreset,
	LDAPSetting,
	LDAP_PRESET_TABLE,
	LDAP_SETTING_MAP,
)

#### Serializers
from core.serializers.ldap_settings import LDAPSettingSerializer
from core.serializers.interlock_settings import InterlockSettingSerializer

#### Constants
from core.ldap import defaults
from core.constants.attrs.local import (
	LOCAL_ATTR_NAME,
	LOCAL_ATTR_TYPE,
	LOCAL_ATTR_VALUE,
	LOCAL_ATTR_PRESET,
	LOCAL_ATTR_DN,
)
from core.models.types.settings import (
	make_field_db_name,
	TYPE_AES_ENCRYPT,
	TYPE_BOOL,
)
from core.constants.settings import (
	K_LDAP_AUTH_TLS_VERSION,
	K_LDAP_AUTH_CONNECTION_PASSWORD,
	K_LDAP_FIELD_MAP,
)

#### Exceptions
from core.exceptions import (
	ldap as exc_ldap,
	ldap_settings as exc_set,
)
from rest_framework.serializers import ValidationError
from django.core.exceptions import ObjectDoesNotExist

### Others
from core.utils.network import net_port_test
from enum import Enum
import logging
import ssl
################################################################################


logger = logging.getLogger(__name__)

DEFAULT_PRESET_NAME = "default_preset"


class SettingsViewMixin(viewsets.ViewSetMixin):
	def create_default_preset(self) -> LDAPPreset | None:
		if db_table_exists(LDAP_PRESET_TABLE):
			if not LDAPPreset.objects.filter(name=DEFAULT_PRESET_NAME).exists():
				return LDAPPreset.objects.create(
					name=DEFAULT_PRESET_NAME,
					label="Default Preset",
					active=True,
				)

	def remove_default_preset(self):
		qs = LDAPPreset.objects.filter(name=DEFAULT_PRESET_NAME)
		if qs.exists():
			qs[0].delete_permanently()

	def resync_users(self) -> None:
		# If LDAP is not enable, do not resync users.
		try:
			ldap_enabled = InterlockSetting.objects.get(
				name=INTERLOCK_SETTING_ENABLE_LDAP
			)
			if not ldap_enabled.value:
				return None
		except:
			logger.warning(
				f"Could not fetch {INTERLOCK_SETTING_ENABLE_LDAP} from Database."
			)
			return None

		ldc_opts = LDAPConnectionOptions()
		ldc_opts["force_admin"] = True
		# Open LDAP Connection
		with LDAPConnector(**ldc_opts) as ldc:
			for local_user in User.objects.all():
				try:
					user: User = ldc.get_user(username=local_user.username)
					if user:
						user.save()
				except Exception as e:
					logger.warning(
						f"Could not re-sync user {local_user.username} on settings change."
					)
					logger.exception(e)
					pass
		return None

	def normalize_preset_name(self, name: str) -> str:
		replace_chars = (
			" ",
			"-",
		)
		for c in replace_chars:
			name = name.replace(c, "_")
		return name.lower()

	def get_active_settings_preset(self):
		try:
			return LDAPPreset.objects.get(active=True)
		except ObjectDoesNotExist:
			self.create_default_preset()
		return LDAPPreset.objects.get(active=True)

	def resync_settings(self):
		RuntimeSettings.resync()
		self.resync_users()

	def get_admin_status(self):
		try:
			admin_user: User = User.objects.get(
				username=DEFAULT_SUPERUSER_USERNAME
			)
			return not admin_user.deleted
		except ObjectDoesNotExist:
			return False

	@transaction.atomic
	def set_admin_status(self, status: bool = None, password: str = None):
		default_admin = None
		full_query_set = User.objects.get_full_queryset()
		user_modified = False

		try:
			default_admin: User = full_query_set.get(
				username=DEFAULT_SUPERUSER_USERNAME
			)
		except ObjectDoesNotExist:
			default_admin: User = User.objects.create_default_superuser()

		if status is not None:
			if not isinstance(status, bool):
				raise TypeError("status must be of type bool.")
			default_admin.deleted = not status
			user_modified = True

		if password:
			default_admin.set_password(password)
			user_modified = True

		if user_modified:
			default_admin.save()

	def get_ldap_settings(self, preset_id: int = 1) -> dict[dict]:
		"""Returns a Dictionary with the current setting values in the system"""
		data = {}

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
						data[setting_key][LOCAL_ATTR_VALUE] = (
							setting_instance.value.name
						)
			except ObjectDoesNotExist:
				data[setting_key][LOCAL_ATTR_VALUE] = getattr(
					defaults, setting_key
				)
				if setting_key == K_LDAP_AUTH_TLS_VERSION and isinstance(
					data[setting_key][LOCAL_ATTR_VALUE], Enum
				):
					data[setting_key][LOCAL_ATTR_VALUE] = data[setting_key][
						LOCAL_ATTR_VALUE
					].name
		return data

	def get_local_settings(
		self, preset_id=1, public_fields_only=True
	) -> dict[dict]:
		fields_to_retrieve = None
		if public_fields_only:
			fields_to_retrieve = INTERLOCK_SETTING_PUBLIC
		else:
			fields_to_retrieve = INTERLOCK_SETTING_MAP.keys()

		interlock_settings = {}
		interlock_settings["DEFAULT_ADMIN_ENABLED"] = {
			"value": self.get_admin_status(),
			"type": TYPE_BOOL,
		}
		if public_fields_only:
			for setting_key in fields_to_retrieve:
				setting_instance = InterlockSetting.objects.get(
					name=setting_key
				)
				interlock_settings[setting_key] = {
					"value": setting_instance.value,
					"type": setting_instance.type,
				}
		return interlock_settings

	def test_ldap_settings(self, data):
		ldapAuthConnectionUser = data["LDAP_AUTH_CONNECTION_USER_DN"]["value"]
		ldapAuthConnectionPassword = data["LDAP_AUTH_CONNECTION_PASSWORD"][
			"value"
		]
		ldapAuthURL = data["LDAP_AUTH_URL"]["value"]
		ldapAuthConnectTimeout = int(data["LDAP_AUTH_CONNECT_TIMEOUT"]["value"])
		ldapAuthReceiveTimeout = int(data["LDAP_AUTH_RECEIVE_TIMEOUT"]["value"])
		ldapAuthUseSSL = data["LDAP_AUTH_USE_SSL"]["value"]
		ldapAuthUseTLS = data["LDAP_AUTH_USE_TLS"]["value"]
		ldapAuthTLSVersion = data["LDAP_AUTH_TLS_VERSION"]["value"]

		logger.info("LDAP Socket Testing")
		for server in ldapAuthURL:
			ip = server.split(":")[1][2:]
			port = server.split(":")[2]
			logger.info("IP to Test: " + ip)
			logger.info("Port to Test: " + port)
			if not net_port_test(ip, port, ldapAuthConnectTimeout):
				exception = exc_ldap.PortUnreachable
				data = {
					"code": "ldap_port_err",
					"ipAddress": ip,
					"port": port,
				}
				exception.set_detail(exception, data)
				raise exception
			logger.info("Port test successful")

		username = DEFAULT_SUPERUSER_USERNAME
		user_dn = ldapAuthConnectionUser

		logger.info("Test Connection Endpoint Parameters: ")
		logger.info(f"User: {username}")
		logger.info(f"User DN: {user_dn}")
		logger.info(f"LDAP Connection User: {ldapAuthConnectionUser}")
		# logger.info(ldapAuthConnectionPassword)
		logger.info(f"LDAP URL: {ldapAuthURL}")
		logger.info(f"LDAP Connect Timeout: {ldapAuthConnectTimeout}")
		logger.info(f"LDAP Receive Timeout: {ldapAuthReceiveTimeout}")
		logger.info(f"Force SSL: {ldapAuthUseSSL}")
		logger.info(f"Use TLS: {ldapAuthUseTLS}")
		logger.info(f"TLS Version: {ldapAuthTLSVersion}")

		# Open LDAP Connection
		try:
			c = test_ldap_connection(
				username=username,
				user_dn=user_dn,
				password=ldapAuthConnectionPassword,
				ldapAuthConnectionUser=ldapAuthConnectionUser,
				ldapAuthConnectionPassword=ldapAuthConnectionPassword,
				ldapAuthURL=ldapAuthURL,
				ldapAuthConnectTimeout=ldapAuthConnectTimeout,
				ldapAuthReceiveTimeout=ldapAuthReceiveTimeout,
				ldapAuthUseSSL=ldapAuthUseSSL,
				ldapAuthUseTLS=ldapAuthUseTLS,
				ldapAuthTLSVersion=ldapAuthTLSVersion,
			)
		except Exception as e:
			try:
				c.unbind()
			except:
				pass
			print(e)
			raise exc_ldap.CouldNotOpenConnection

		result = c.result
		c.unbind()

		result["user_used"] = username
		result["user_dn_used"] = user_dn
		result["server_pool"] = ldapAuthURL
		result["ssl"] = ldapAuthUseSSL
		result["tls"] = ldapAuthUseTLS
		result["tls_version"] = ldapAuthTLSVersion
		logger.info("Test Connection Endpoint Result: ")
		logger.info(result)
		return result

	def set_value_fields(self, value, value_fields, data):
		if len(value_fields) == 1:
			fld = value_fields[0]
			data[make_field_db_name(fld)] = value
		else:
			if not isinstance(value, (list, set, tuple)):
				raise ValidationError(
					"Cannot use sequence value fields if parsed value"
					" is not a sequence."
				)
			for idx, fld in enumerate(value_fields):
				data[make_field_db_name(fld)] = value[idx]
		return data

	def parse_local_setting_data(
		self,
		param_name: str,
		param_type: str,
		param_value,
	):
		setting_data = {
			LOCAL_ATTR_NAME: param_name,
			LOCAL_ATTR_TYPE: param_type,
		}
		value_fields = InterlockSetting.get_type_value_fields(param_type)
		return self.set_value_fields(
			param_value,
			value_fields,
			setting_data,
		)

	def save_local_settings(self, local_settings: dict):
		"""
		Validates and Serializes data for Interlock Settings, then saves it.
		"""
		param_name: str
		param_value: dict | str | bool | int | list[str]
		# Interlock Settings
		for param_name, param_value in local_settings.items():
			if not param_name in INTERLOCK_SETTING_PUBLIC:
				continue
			if not param_name in INTERLOCK_SETTING_MAP:
				raise exc_set.SettingTypeDoesNotMatch(
					data={"field": param_name}
				)
			param_type = INTERLOCK_SETTING_MAP[param_name]
			param_value = param_value.pop(LOCAL_ATTR_VALUE)

			serializer = InterlockSettingSerializer(
				data=self.parse_local_setting_data(
					param_name=param_name,
					param_type=param_type,
					param_value=param_value,
				)
			)
			serializer.is_valid(raise_exception=True)
			validated_data = serializer.validated_data

			try:
				setting_instance = InterlockSetting.objects.get(name=param_name)
				for attr in validated_data:
					setattr(setting_instance, attr, validated_data[attr])
			except ObjectDoesNotExist:
				setting_instance = InterlockSetting(**validated_data)
			setting_instance.save()

	def parse_ldap_setting_value(self, name: str, t: str, v):
		"""Parses an LDAP Setting Value for Serialization / Validation

		Args:
			name (str): LDAP Setting Key Name
			t (str): LDAP Setting Type
			v (Any): LDAP Setting Value

		Returns:
			Parsed Value.
		"""
		if t == TYPE_AES_ENCRYPT.lower():
			if not isinstance(v, str):
				raise ValidationError(
					f"{TYPE_AES_ENCRYPT} type setting value must be of type str"
				)
			return aes_encrypt(v)
		elif name == K_LDAP_FIELD_MAP:
			v: dict
			if not isinstance(v, dict):
				raise ValidationError(
					f"{K_LDAP_FIELD_MAP} must be of type dict"
				)
			_non_nullables = list(defaults.LDAP_AUTH_USER_LOOKUP_FIELDS)
			_non_nullables.append(LOCAL_ATTR_DN)
			for fld in _non_nullables:
				if not v.get(fld, None):
					raise ValidationError(
						f"{fld} is required in dict for {K_LDAP_FIELD_MAP}"
					)
			for _sub_k, _sub_v in v.items():
				_sub_v: str
				if _sub_v.lower() in (
					"none",
					"null",
				):
					if _sub_k in set(_non_nullables):
						raise ValidationError(
							{_sub_k: "Field is not nullable."}
						)
					v[_sub_k] = None
			return v
		return v

	def parse_ldap_setting_data(
		self,
		param_name: str,
		param_type: str,
		param_value,
		settings_preset: LDAPPreset,
	):
		setting_data = {
			LOCAL_ATTR_NAME: param_name,
			LOCAL_ATTR_TYPE: param_type,
			LOCAL_ATTR_PRESET: settings_preset,
		}
		value = self.parse_ldap_setting_value(
			name=param_name,
			t=param_type,
			v=param_value,
		)
		value_fields = LDAPSetting.get_type_value_fields(param_type)
		return self.set_value_fields(value, value_fields, setting_data)

	def save_ldap_settings(
		self,
		ldap_settings: dict,
		settings_preset: LDAPPreset,
	):
		"""Validates and Serializes data for LDAP Settings, then saves it."""
		param_name: str
		param_value: dict | str | bool | int | list[str]
		# LDAP Settings
		for param_name, param_value in ldap_settings.items():
			if not param_name in LDAP_SETTING_MAP:
				raise exc_set.SettingTypeDoesNotMatch(
					data={"field": param_name}
				)
			param_type = LDAP_SETTING_MAP[param_name].lower()
			param_value = param_value.pop("value")

			is_default = False
			if param_name == K_LDAP_AUTH_TLS_VERSION:
				is_default = getattr(ssl, param_value) == getattr(
					defaults, param_name, None
				)
			elif param_name == K_LDAP_AUTH_CONNECTION_PASSWORD:
				if not param_value:
					is_default = True
			else:
				is_default = param_value == getattr(defaults, param_name, None)

			# If value is same as default
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
			# If value is an override
			else:
				parsed_data = self.parse_ldap_setting_data(
					param_name=param_name,
					param_type=param_type,
					param_value=param_value,
					settings_preset=settings_preset,
				)

				serializer = LDAPSettingSerializer(data=parsed_data)
				serializer.is_valid(raise_exception=True)
				validated_data = serializer.validated_data

				try:
					setting_instance = LDAPSetting.objects.get(
						name=param_name,
						preset=settings_preset,
					)
					for attr in validated_data:
						setattr(setting_instance, attr, validated_data[attr])
				except ObjectDoesNotExist:
					setting_instance = LDAPSetting(
						**validated_data,
						preset=settings_preset,
					)
				setting_instance.save()
