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
# ---------------------------------- IMPORTS -----------------------------------#
from core.ldap import defaults
from core.models.ldap_settings import (
	LDAP_SETTING_MAP,
	LDAPSetting,
	LDAPPreset,
	TYPE_AES_ENCRYPT,
	LDAP_SETTING_TABLE,
	LDAP_PRESET_TABLE,
)
from interlock_backend.encrypt import aes_decrypt
from core.utils.db import db_table_exists
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
	LDAP_AUTH_USER_FIELDS = defaults.LDAP_AUTH_USER_FIELDS
	LDAP_AUTH_USERNAME_IDENTIFIER = defaults.LDAP_AUTH_USERNAME_IDENTIFIER
	LDAP_AUTH_USER_LOOKUP_FIELDS = defaults.LDAP_AUTH_USER_LOOKUP_FIELDS
	LDAP_AUTH_CLEAN_USER_DATA = defaults.LDAP_AUTH_CLEAN_USER_DATA
	LDAP_AUTH_SYNC_USER_RELATIONS = defaults.LDAP_AUTH_SYNC_USER_RELATIONS
	LDAP_AUTH_FORMAT_SEARCH_FILTERS = defaults.LDAP_AUTH_FORMAT_SEARCH_FILTERS
	LDAP_AUTH_FORMAT_USERNAME = defaults.LDAP_AUTH_FORMAT_USERNAME
	LDAP_AUTH_ACTIVE_DIRECTORY_DOMAIN = defaults.LDAP_AUTH_ACTIVE_DIRECTORY_DOMAIN
	LDAP_AUTH_CONNECTION_USER_DN = defaults.LDAP_AUTH_CONNECTION_USER_DN
	LDAP_AUTH_CONNECTION_USERNAME = defaults.LDAP_AUTH_CONNECTION_USERNAME
	LDAP_AUTH_CONNECTION_PASSWORD = defaults.LDAP_AUTH_CONNECTION_PASSWORD
	LDAP_AUTH_CONNECT_TIMEOUT = defaults.LDAP_AUTH_CONNECT_TIMEOUT
	LDAP_AUTH_RECEIVE_TIMEOUT = defaults.LDAP_AUTH_RECEIVE_TIMEOUT
	ADMIN_GROUP_TO_SEARCH = defaults.ADMIN_GROUP_TO_SEARCH
	LDAP_DIRTREE_OU_FILTER = defaults.LDAP_DIRTREE_OU_FILTER
	LDAP_DIRTREE_CN_FILTER = defaults.LDAP_DIRTREE_CN_FILTER
	LDAP_DIRTREE_ATTRIBUTES = defaults.LDAP_DIRTREE_ATTRIBUTES
	LDAP_LDIF_IDENTIFIERS = defaults.LDAP_LDIF_IDENTIFIERS
	LDAP_OPERATIONS = defaults.LDAP_OPERATIONS
	LDAP_LOG_READ = defaults.LDAP_LOG_READ
	LDAP_LOG_CREATE = defaults.LDAP_LOG_CREATE
	LDAP_LOG_UPDATE = defaults.LDAP_LOG_UPDATE
	LDAP_LOG_DELETE = defaults.LDAP_LOG_DELETE
	LDAP_LOG_OPEN_CONNECTION = defaults.LDAP_LOG_OPEN_CONNECTION
	LDAP_LOG_CLOSE_CONNECTION = defaults.LDAP_LOG_CLOSE_CONNECTION
	LDAP_LOG_LOGIN = defaults.LDAP_LOG_LOGIN
	LDAP_LOG_LOGOUT = defaults.LDAP_LOG_LOGOUT
	LDAP_LOG_MAX = defaults.LDAP_LOG_MAX

	# Singleton def
	def __new__(cls, *args, **kwargs):
		if cls._instance is None:
			cls._instance = super().__new__(cls, *args, **kwargs)
		return cls._instance

	def __newUuid__(self):
		self.uuid = uuid1(node=uuid_getnode(), clock_seq=getrandbits(14))

	def __init__(self):
		if self._initialized:
			return
		self.__newUuid__()

		# Set defaults / constants
		for k, v in defaults.__dict__.items():
			setattr(self, k, v)
		self.resync()
		self._initialized = True

	def postsync(self) -> None:
		for f in [
			self.LDAP_AUTH_USER_FIELDS["username"],
			"username",
		]:
			if not f in self.LDAP_DIRTREE_ATTRIBUTES:
				self.LDAP_DIRTREE_ATTRIBUTES.append(f)
		self.LDAP_DIRTREE_ATTRIBUTES = list(set(self.LDAP_DIRTREE_ATTRIBUTES))

	def resync(self, raise_exc=False) -> bool:
		self.__newUuid__()
		try:
			_current_settings: dict = get_settings(self.uuid)
			for k, v in _current_settings.items():
				setattr(self, k, v)
		except:
			if raise_exc:
				raise
			else:
				return False
		self.postsync()
		return True


def get_settings(uuid, quiet=False) -> dict:
	if not quiet:
		logger.info(f"Re-synchronizing settings for {this_module} (Configuration Instance {uuid})")
	active_preset = None
	r = {}

	for t in [LDAP_PRESET_TABLE, LDAP_SETTING_TABLE]:
		if not db_table_exists(t):
			logger.warning("Table %s does not exist, please check migrations.", t)

	if db_table_exists(LDAP_PRESET_TABLE):
		active_preset = LDAPPreset.objects.get(active=True)

	# For constant, value_type in...
	for setting_key, setting_type in LDAP_SETTING_MAP.items():
		setting_instance = None
		if db_table_exists(LDAP_SETTING_TABLE):
			# Setting
			setting_instance = LDAPSetting.objects.filter(name=setting_key, preset_id=active_preset)
			if setting_instance.exists():
				setting_instance = setting_instance[0]
		# Default
		value_default = getattr(defaults, setting_key)

		# Value
		if setting_type == TYPE_AES_ENCRYPT and setting_instance:
			setting_value = aes_decrypt(*setting_instance.value)
		else:
			setting_value = getattr(setting_instance, "value", value_default)
		r[setting_key] = setting_value
	return r
