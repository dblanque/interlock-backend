################################################################################
#################### INTERLOCK IS LICENSED UNDER GNU AGPLv3 ####################
################## ORIGINAL PROJECT CREATED BY DYLAN BLANQUÉ ###################
########################## AND BR CONSULTING S.R.L. ############################
################################################################################
# Module: core.models.ldap_settings_runtime
# Description:	Contains required functions to import LDAP Connection constants
# from file defaults and database entries.
#
# Contributors:
# - Dylan Blanque
# - Brian Blanque
# ---------------------------------- IMPORTS --------------------------------- #
from core.ldap import defaults
from core.models.ldap_settings import (
	LDAP_SETTING_MAP,
	LDAPSetting,
	LDAPPreset,
	TYPE_AES_ENCRYPT,
	LDAP_SETTING_TABLE,
	LDAP_PRESET_TABLE,
)
from django.core.exceptions import ObjectDoesNotExist, AppRegistryNotReady
from django.apps import apps
from interlock_backend.encrypt import aes_decrypt
from core.utils.db import db_table_exists
from core.utils.migrations import is_in_migration
import sys
import logging
from uuid import uuid1, getnode as uuid_getnode
from random import getrandbits
################################################################################

logger = logging.getLogger(__name__)
this_module = sys.modules[__name__]


# ! You also have to add the settings to the following files:
# core.models.ldap_settings
# core.models.ldap_settings_runtime <--- You're Here
# core.ldap.defaults
class RuntimeSettingsSingleton:
	_instance = None
	_initialized = False
	PLAIN_TEXT_BIND_PASSWORD = defaults.PLAIN_TEXT_BIND_PASSWORD
	LDAP_AUTH_URL = defaults.LDAP_AUTH_URL
	LDAP_DOMAIN = defaults.LDAP_DOMAIN
	LDAP_AUTH_USE_SSL = defaults.LDAP_AUTH_USE_SSL
	LDAP_AUTH_USE_TLS = defaults.LDAP_AUTH_USE_TLS
	LDAP_AUTH_TLS_VERSION = defaults.LDAP_AUTH_TLS_VERSION
	LDAP_AUTH_SEARCH_BASE = defaults.LDAP_AUTH_SEARCH_BASE
	LDAP_SCHEMA_NAMING_CONTEXT = defaults.LDAP_SCHEMA_NAMING_CONTEXT
	LDAP_AUTH_OBJECT_CLASS = defaults.LDAP_AUTH_OBJECT_CLASS
	LDAP_DNS_LEGACY = defaults.LDAP_DNS_LEGACY
	EXCLUDE_COMPUTER_ACCOUNTS = defaults.EXCLUDE_COMPUTER_ACCOUNTS
	DISABLE_SETTING_OVERRIDES = defaults.DISABLE_SETTING_OVERRIDES
	LDAP_OU_FIELD = defaults.LDAP_OU_FIELD
	LDAP_GROUP_FIELD = defaults.LDAP_GROUP_FIELD
	LDAP_FIELD_MAP = defaults.LDAP_FIELD_MAP
	LDAP_AUTH_USERNAME_IDENTIFIER = defaults.LDAP_AUTH_USERNAME_IDENTIFIER
	LDAP_AUTH_USER_LOOKUP_FIELDS = defaults.LDAP_AUTH_USER_LOOKUP_FIELDS
	LDAP_AUTH_CLEAN_USER_DATA = defaults.LDAP_AUTH_CLEAN_USER_DATA
	LDAP_AUTH_SYNC_USER_RELATIONS = defaults.LDAP_AUTH_SYNC_USER_RELATIONS
	LDAP_AUTH_FORMAT_SEARCH_FILTERS = defaults.LDAP_AUTH_FORMAT_SEARCH_FILTERS
	LDAP_AUTH_FORMAT_USERNAME = defaults.LDAP_AUTH_FORMAT_USERNAME
	LDAP_AUTH_ACTIVE_DIRECTORY_DOMAIN = (
		defaults.LDAP_AUTH_ACTIVE_DIRECTORY_DOMAIN
	)
	LDAP_AUTH_CONNECTION_USER_DN = defaults.LDAP_AUTH_CONNECTION_USER_DN
	LDAP_AUTH_CONNECTION_USERNAME = defaults.LDAP_AUTH_CONNECTION_USERNAME
	LDAP_AUTH_CONNECTION_PASSWORD = defaults.LDAP_AUTH_CONNECTION_PASSWORD
	LDAP_AUTH_CONNECT_TIMEOUT = defaults.LDAP_AUTH_CONNECT_TIMEOUT
	LDAP_AUTH_RECEIVE_TIMEOUT = defaults.LDAP_AUTH_RECEIVE_TIMEOUT
	ADMIN_GROUP_TO_SEARCH = defaults.ADMIN_GROUP_TO_SEARCH
	LDAP_LDIF_IDENTIFIERS = defaults.LDAP_LDIF_IDENTIFIERS
	LDAP_OPERATIONS = defaults.LDAP_OPERATIONS

	# Singleton def
	def __new__(cls, *args, **kwargs):
		if cls._instance is None:
			cls._instance = super().__new__(cls, *args, **kwargs)
		return cls._instance

	def __new_uuid__(self):
		self.uuid = uuid1(node=uuid_getnode(), clock_seq=getrandbits(14))

	def __init__(self):
		if self._initialized or not apps.ready:
			if is_in_migration():
				logger.error(
					"%s in migration mode (must be initialized manually "
					"within migration)."
					% (self.__class__.__name__)
				)
			elif not apps.ready:
				logger.error(
					"%s may not be initialized before all apps are ready."
					% (self.__class__.__name__)
				)
			return
		self.__new_uuid__()

		# Set defaults / constants
		for k in LDAP_SETTING_MAP.keys():
			setattr(self, k, getattr(defaults, k))
		self.resync(raise_exc=True)
		self._initialized = True

	def postsync(self) -> None:
		pass

	def resync(self, raise_exc=False) -> bool:
		self.__new_uuid__()
		try:
			_current_settings: dict = self.get_settings(self.uuid)
			for k, v in _current_settings.items():
				setattr(self, k, v)
		except AppRegistryNotReady:
			raise
		except Exception as e:
			if raise_exc:
				raise e
			else:
				logger.exception(e)
				return False
		self.postsync()
		return True

	def get_settings(self, uuid, quiet=False) -> dict:
		if not quiet:
			add_newline = "\n  " if is_in_migration() else ""
			logger.info(
				"%sRe-synchronizing settings for %s (Configuration Instance %s)"
				% (add_newline, this_module, uuid)
			)
		active_preset = None
		r = {}

		for t in [LDAP_PRESET_TABLE, LDAP_SETTING_TABLE]:
			if not db_table_exists(t):
				logger.warning(
					"Table %s does not exist, please check migrations.", t
				)

		if db_table_exists(LDAP_PRESET_TABLE):
			try:
				active_preset = LDAPPreset.objects.get(active=True)
			except ObjectDoesNotExist:
				pass

		# For constant, value_type in...
		for setting_key, setting_type in LDAP_SETTING_MAP.items():
			setting_instance = None
			if db_table_exists(LDAP_SETTING_TABLE):
				# Get Setting Override if it exists
				try:
					setting_instance = LDAPSetting.objects.get(
						name=setting_key,
						preset=active_preset,
						type=setting_type,
					)
				except ObjectDoesNotExist:
					pass
			# Default
			value_default = getattr(defaults, setting_key)

			if not setting_instance:
				r[setting_key] = value_default
			else:
				if setting_type == TYPE_AES_ENCRYPT and setting_instance:
					setting_value = aes_decrypt(*setting_instance.value)
				else:
					setting_value = setting_instance.value
				r[setting_key] = setting_value
		return r
