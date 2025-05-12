################################################################################
#################### INTERLOCK IS LICENSED UNDER GNU AGPLv3 ####################
################## ORIGINAL PROJECT CREATED BY DYLAN BLANQUÉ ###################
########################## AND BR CONSULTING S.R.L. ############################
################################################################################
# Module: core.models.ldap_settings
# Description:	Contains default LDAP Setting definitions
#
# ---------------------------------- IMPORTS -----------------------------------#
from django.db import models
from core.models.validators.ldap import ldap_uri_validator
from django.utils.translation import gettext_lazy as _
from core.models.setting.base import (
	BaseSetting,
	BaseSettingsPreset,
	add_fields_from_dict,
)
from core.models.types.settings import (
	LDAP_SETTING_FIELDS,
	TYPE_STRING,
	TYPE_BOOL,
	TYPE_JSON,
	TYPE_AES_ENCRYPT,
	TYPE_INTEGER,
	TYPE_LDAP_URI,
	TYPE_LDAP_TLS_VERSION,
)
################################################################################

LDAP_SETTING_TABLE = "core_ldap_setting"
LDAP_PRESET_TABLE = "core_ldap_preset"
LDAP_TLS_TYPES = (
	# Identifier, Pretty Name
	("PROTOCOL_TLSv1", "TLSv1"),
	("PROTOCOL_TLSv1_1", "TLSv1_1"),
	("PROTOCOL_TLSv1_2", "TLSv1_2"),
	("PROTOCOL_TLSv1_3", "TLSv1_3"),
	("PROTOCOL_TLS", "TLS"),
	("PROTOCOL_TLS_CLIENT", "TLS_CLIENT"),
)

# ! Only add non-constant values with DB Save-able overrides here.
# ! You also have to add the settings to the following files:
# core.models.ldap_settings			<------------ You're Here
# core.models.ldap_settings_runtime
# interlock_backend.ldap.defaults
LDAP_SETTING_MAP = {
	"LDAP_AUTH_URL": TYPE_LDAP_URI,
	"LDAP_DOMAIN": TYPE_STRING,
	"LDAP_LOG_MAX": TYPE_INTEGER,
	"LDAP_LOG_READ": TYPE_BOOL,
	"LDAP_LOG_CREATE": TYPE_BOOL,
	"LDAP_LOG_UPDATE": TYPE_BOOL,
	"LDAP_LOG_DELETE": TYPE_BOOL,
	"LDAP_LOG_OPEN_CONNECTION": TYPE_BOOL,
	"LDAP_LOG_CLOSE_CONNECTION": TYPE_BOOL,
	"LDAP_LOG_LOGIN": TYPE_BOOL,
	"LDAP_LOG_LOGOUT": TYPE_BOOL,
	"LDAP_AUTH_USE_SSL": TYPE_BOOL,
	"LDAP_AUTH_USE_TLS": TYPE_BOOL,
	"LDAP_AUTH_TLS_VERSION": TYPE_LDAP_TLS_VERSION,
	"LDAP_AUTH_SEARCH_BASE": TYPE_STRING,
	"LDAP_DNS_LEGACY": TYPE_BOOL,
	"LDAP_AUTH_OBJECT_CLASS": TYPE_STRING,
	"EXCLUDE_COMPUTER_ACCOUNTS": TYPE_BOOL,
	"LDAP_FIELD_MAP": TYPE_JSON,
	"LDAP_AUTH_ACTIVE_DIRECTORY_DOMAIN": TYPE_STRING,
	"LDAP_AUTH_CONNECTION_USER_DN": TYPE_STRING,
	"LDAP_AUTH_CONNECTION_USERNAME": TYPE_STRING,
	"LDAP_AUTH_CONNECTION_PASSWORD": TYPE_AES_ENCRYPT,
	"LDAP_AUTH_CONNECT_TIMEOUT": TYPE_INTEGER,
	"LDAP_AUTH_RECEIVE_TIMEOUT": TYPE_INTEGER,
	"ADMIN_GROUP_TO_SEARCH": TYPE_STRING,
}
VALIDATORS = {TYPE_LDAP_URI: [ldap_uri_validator]}
FIELD_ARGS = {TYPE_LDAP_URI: [models.CharField(max_length=255)]}

LDAP_SETTINGS_CHOICES_MAP = {
	TYPE_LDAP_TLS_VERSION: [
		"PROTOCOL_TLSv1",
		"PROTOCOL_TLSv1_1",
		"PROTOCOL_TLSv1_2",
		"PROTOCOL_TLSv1_3",
		"PROTOCOL_TLS",
		"PROTOCOL_TLS_CLIENT",
	]
}
LDAP_SETTING_NAME_CHOICES = tuple([(k, k) for k, t in LDAP_SETTING_MAP.items()])
LDAP_SETTING_TYPE_CHOICES = []
for key in LDAP_SETTING_FIELDS.keys():
	LDAP_SETTING_TYPE_CHOICES.append(
		(
			key,
			key.upper(),
		)
	)
LDAP_SETTING_TYPE_CHOICES = tuple(LDAP_SETTING_TYPE_CHOICES)


class LDAPPreset(BaseSettingsPreset):
	id = models.BigAutoField(verbose_name=_("id"), primary_key=True)
	name = models.CharField(
		verbose_name=_("name"),
		unique=True,
		null=False,
		blank=False,
		max_length=128,
	)
	label = models.CharField(
		verbose_name=_("label"), blank=False, null=False, max_length=64
	)
	active = models.BooleanField(
		verbose_name=_("active"), unique=True, null=True
	)

	class Meta:
		db_table = LDAP_PRESET_TABLE


@add_fields_from_dict(
	LDAP_SETTING_FIELDS, validators_dict=VALIDATORS, args_pass=FIELD_ARGS
)
class LDAPSetting(BaseSetting):
	setting_fields = LDAP_SETTING_FIELDS
	name = models.CharField(
		verbose_name=_("name"),
		choices=LDAP_SETTING_NAME_CHOICES,
		unique=False,
		null=False,
		blank=False,
		max_length=128,
	)
	preset = models.ForeignKey(
		LDAPPreset, verbose_name=_("settings_preset"), on_delete=models.CASCADE
	)
	type = models.CharField(
		verbose_name=_("type"), choices=LDAP_SETTING_TYPE_CHOICES, null=False
	)

	class Meta:
		db_table = LDAP_SETTING_TABLE
