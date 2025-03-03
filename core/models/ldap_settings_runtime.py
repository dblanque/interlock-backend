################################################################################
#################### INTERLOCK IS LICENSED UNDER GNU AGPLv3 ####################
################## ORIGINAL PROJECT CREATED BY DYLAN BLANQUÉ ###################
########################## AND BR CONSULTING S.R.L. ############################
################################################################################
# Module: core.models.ldap_settings_db
# Description:	Contains required functions to import LDAP Connection constants
#				from file defaults and database entries.
#
#---------------------------------- IMPORTS -----------------------------------#
from interlock_backend.ldap import defaults
from .ldap_settings import (
	CMAPS,
	LDAPSetting,
	LDAPPreset,
	LDAP_TYPE_PASSWORD,
	LDAP_SETTING_PREFIX,
	LDAP_TYPE_PASSWORD_FIELDS,
)
from interlock_backend.encrypt import aes_decrypt
from django.db import connection
import sys
import logging
from uuid import (
	uuid1,
	getnode as uuid_getnode
)
from random import getrandbits
################################################################################

logger = logging.getLogger(__name__)
this_module = sys.modules[__name__]

# ! You also have to add the settings to the following files:
# core.models.ldap_settings
# core.models.ldap_settings_db		<------------ You're Here
# interlock_backend.ldap.defaults
class RunningSettingsClass():
	def __newUuid__(self):
		self.uuid = uuid1(node=uuid_getnode(), clock_seq=getrandbits(14))

	def __init__(self):
		self.__newUuid__()
		# ! For typing hints
		self.PLAIN_TEXT_BIND_PASSWORD = None
		self.LDAP_AUTH_URL = None
		self.LDAP_DOMAIN = None
		self.LDAP_AUTH_USE_SSL = None
		self.LDAP_AUTH_USE_TLS = None
		self.LDAP_AUTH_TLS_VERSION = None
		self.LDAP_AUTH_SEARCH_BASE = None
		self.LDAP_SCHEMA_NAMING_CONTEXT = None
		self.LDAP_AUTH_OBJECT_CLASS = None
		self.LDAP_DNS_LEGACY = None
		self.LDAP_GROUP_TYPE_MAPPING = None
		self.LDAP_GROUP_SCOPE_MAPPING = None
		self.EXCLUDE_COMPUTER_ACCOUNTS = None
		self.DISABLE_SETTING_OVERRIDES = None
		self.LDAP_OU_FIELD = None
		self.LDAP_GROUP_FIELD = None
		self.LDAP_AUTH_USER_FIELDS = None
		self.LDAP_AUTH_USERNAME_IDENTIFIER = None
		self.LDAP_AUTH_USER_LOOKUP_FIELDS = None
		self.LDAP_AUTH_CLEAN_USER_DATA = None
		self.LDAP_AUTH_SYNC_USER_RELATIONS = None
		self.LDAP_AUTH_FORMAT_SEARCH_FILTERS = None
		self.LDAP_AUTH_FORMAT_USERNAME = None
		self.LDAP_AUTH_ACTIVE_DIRECTORY_DOMAIN = None
		self.LDAP_AUTH_CONNECTION_USER_DN = None
		self.LDAP_AUTH_CONNECTION_USERNAME = None
		self.LDAP_AUTH_CONNECTION_PASSWORD = None
		self.LDAP_AUTH_CONNECT_TIMEOUT = None
		self.LDAP_AUTH_RECEIVE_TIMEOUT = None
		self.ADMIN_GROUP_TO_SEARCH = None
		self.LDAP_DIRTREE_OU_FILTER = None
		self.LDAP_DIRTREE_CN_FILTER = None
		self.LDAP_DIRTREE_ATTRIBUTES = None
		self.LDAP_LDIF_IDENTIFIERS = None
		self.LDAP_OPERATIONS = None
		self.LDAP_LOG_READ = None
		self.LDAP_LOG_CREATE = None
		self.LDAP_LOG_UPDATE = None
		self.LDAP_LOG_DELETE = None
		self.LDAP_LOG_OPEN_CONNECTION = None
		self.LDAP_LOG_CLOSE_CONNECTION = None
		self.LDAP_LOG_LOGIN = None
		self.LDAP_LOG_LOGOUT = None
		self.LDAP_LOG_MAX = None

		# Set defaults / constants
		for k,v in defaults.__dict__.items():
			setattr(self, k, v)
		self.resync()

	def __getattribute__(self, name: str):
		return super().__getattribute__(name)

	def resync(self) -> bool:
		self.__newUuid__()
		try:
			_current_settings: dict = get_settings(self.uuid)
			for k, v in _current_settings.items():
				setattr(self, k, v)
		except: return False
		return True

def get_settings(uuid) -> dict:
	logger.info(f"Re-synchronizing settings for {this_module} (Configuration Instance {uuid})")
	all_tables = connection.introspection.table_names()
	active_preset = None
	r = {}

	if "core_ldappreset" in all_tables:
		active_preset = LDAPPreset.objects.get(active=True)

	# For constant, value_type in...
	for setting_key, setting_type in CMAPS.items():
		s = None
		if "core_ldapsetting" in all_tables:
			# Setting
			s = LDAPSetting.objects.filter(name=setting_key, preset_id=active_preset)
			if s.exists():
				s = s[0]
		# Default
		d = getattr(defaults, setting_key)
		# Value

		if setting_type == LDAP_TYPE_PASSWORD:
			decrypt_args = []
			for field in LDAP_TYPE_PASSWORD_FIELDS:
				try:
					decrypt_args.append(getattr(s, field))
				except:
					raise ValueError(f"Missing crypt object for {setting_key}")
			v = aes_decrypt(*decrypt_args)
		else:
			v = getattr(s, f"{LDAP_SETTING_PREFIX}_{setting_type.lower()}", d)
		r[setting_key] = v
	return r

RunningSettings = RunningSettingsClass()