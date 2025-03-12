################################################################################
#################### INTERLOCK IS LICENSED UNDER GNU AGPLv3 ####################
################## ORIGINAL PROJECT CREATED BY DYLAN BLANQUÉ ###################
########################## AND BR CONSULTING S.R.L. ############################
################################################################################
# Module: core.models.ldap_settings
# Description:	Contains default LDAP Setting definitions
#
#---------------------------------- IMPORTS -----------------------------------#
from .base import BaseModel
from django.db import models
from .validators.ldap_uri import validate_ldap_uri
from django.utils.translation import gettext_lazy as _
from django.contrib.postgres.fields import ArrayField
from typing import Iterable
from .types.settings import (
	TYPE_STRING as LDAP_TYPE_STRING,
	TYPE_BOOL as LDAP_TYPE_BOOL,
	TYPE_JSON as LDAP_TYPE_JSON,
	TYPE_PASSWORD as LDAP_TYPE_PASSWORD,
	TYPE_INTEGER as LDAP_TYPE_INTEGER,
	TYPE_LDAP_URI as LDAP_TYPE_LDAP_URI,
	TYPE_LDAP_TLS_VERSION as LDAP_AUTH_TLS_VERSION
)
################################################################################

LDAP_SETTING_TYPES = (
	# Identifier, Pretty Name
	(LDAP_TYPE_STRING, "String"),
	(LDAP_TYPE_BOOL, "Boolean"),
	(LDAP_TYPE_JSON, "JSON Object"),
	(LDAP_TYPE_PASSWORD, "Password"),
	(LDAP_TYPE_INTEGER, "Integer"),
	(LDAP_TYPE_LDAP_URI, "LDAP URI"),
	(LDAP_AUTH_TLS_VERSION, "LDAP TLS Version")
)
LDAP_SETTING_TYPES_LIST = [x[0] for x in LDAP_SETTING_TYPES]
LDAP_TLS_TYPES = (
	# Identifier, Pretty Name
	("PROTOCOL_TLSv1", "TLSv1"),
	("PROTOCOL_TLSv1_1", "TLSv1_1"),
	("PROTOCOL_TLSv1_2", "TLSv1_2"),
	("PROTOCOL_TLSv1_3", "TLSv1_3"),
	("PROTOCOL_TLS", "TLS"),
	("PROTOCOL_TLS_CLIENT", "TLS_CLIENT"),
)
LDAP_SETTING_PREFIX = "v"
LDAP_TYPE_PASSWORD_FIELDS = (
	f"{LDAP_SETTING_PREFIX}_password_aes",
	f"{LDAP_SETTING_PREFIX}_password_ct",
	f"{LDAP_SETTING_PREFIX}_password_nonce",
	f"{LDAP_SETTING_PREFIX}_password_tag",
)

# ! Only add non-constant values with DB Save-able overrides here.
# ! You also have to add the settings to the following files:
# core.models.ldap_settings			<------------ You're Here
# core.models.ldap_settings_runtime
# interlock_backend.ldap.defaults
CMAPS = {
	"LDAP_AUTH_URL": LDAP_TYPE_LDAP_URI,
	"LDAP_DOMAIN": LDAP_TYPE_STRING,
	"LDAP_LOG_MAX": LDAP_TYPE_INTEGER,
	"LDAP_LOG_READ": LDAP_TYPE_BOOL,
	"LDAP_LOG_CREATE": LDAP_TYPE_BOOL,
	"LDAP_LOG_UPDATE": LDAP_TYPE_BOOL,
	"LDAP_LOG_DELETE": LDAP_TYPE_BOOL,
	"LDAP_LOG_OPEN_CONNECTION": LDAP_TYPE_BOOL,
	"LDAP_LOG_CLOSE_CONNECTION": LDAP_TYPE_BOOL,
	"LDAP_LOG_LOGIN": LDAP_TYPE_BOOL,
	"LDAP_LOG_LOGOUT": LDAP_TYPE_BOOL,
	"LDAP_AUTH_USE_SSL": LDAP_TYPE_BOOL, 
	"LDAP_AUTH_USE_TLS": LDAP_TYPE_BOOL, 
	"LDAP_AUTH_TLS_VERSION": LDAP_AUTH_TLS_VERSION,
	"LDAP_AUTH_SEARCH_BASE":LDAP_TYPE_STRING,
	"LDAP_DNS_LEGACY": LDAP_TYPE_BOOL,
	"LDAP_AUTH_OBJECT_CLASS":LDAP_TYPE_STRING,
	"EXCLUDE_COMPUTER_ACCOUNTS": LDAP_TYPE_BOOL,
	"LDAP_AUTH_USER_FIELDS": LDAP_TYPE_JSON,
	"LDAP_DIRTREE_OU_FILTER": LDAP_TYPE_JSON,
	"LDAP_DIRTREE_CN_FILTER": LDAP_TYPE_JSON,
	"LDAP_AUTH_ACTIVE_DIRECTORY_DOMAIN": LDAP_TYPE_STRING,
	"LDAP_AUTH_CONNECTION_USER_DN":LDAP_TYPE_STRING,
	"LDAP_AUTH_CONNECTION_USERNAME":LDAP_TYPE_STRING,
	"LDAP_AUTH_CONNECTION_PASSWORD": LDAP_TYPE_PASSWORD,
	"LDAP_AUTH_CONNECT_TIMEOUT": LDAP_TYPE_INTEGER,
	"LDAP_AUTH_RECEIVE_TIMEOUT": LDAP_TYPE_INTEGER,
	"ADMIN_GROUP_TO_SEARCH": LDAP_TYPE_STRING
}

LDAP_SETTINGS_CHOICES_MAP = {
	LDAP_AUTH_TLS_VERSION:[
		"PROTOCOL_TLSv1",
		"PROTOCOL_TLSv1_1",
		"PROTOCOL_TLSv1_2",
		"PROTOCOL_TLSv1_3",
		"PROTOCOL_TLS",
		"PROTOCOL_TLS_CLIENT",
	]
}

class LDAPPreset(BaseModel):
	id = models.BigAutoField(verbose_name=_("id"), primary_key=True)
	name = models.CharField(
		verbose_name=_("name"),
		unique=True,
		null=False,
		blank=False,
		max_length=128
	)
	label = models.CharField(
		verbose_name=_("label"),
		blank=False,
		null=False,
		max_length=64
	)
	active = models.BooleanField(verbose_name=_("active"), unique=True, null=True)

class BaseLDAPSetting(BaseModel):
	id = models.BigAutoField(verbose_name=_("id"), primary_key=True)
	name = models.CharField(
		verbose_name=_("name"),
		choices=[(k, f"{LDAP_SETTING_PREFIX}_{k.lower()}") for k in CMAPS.keys()],
		unique=False,
		null=False,
		blank=False,
		max_length=128
	)
	type = models.CharField(
		verbose_name=_("type"),
		choices=LDAP_SETTING_TYPES,
		null=False
	)
	preset = models.ForeignKey(
		LDAPPreset,
		verbose_name=_("ldap_preset"),
		on_delete=models.CASCADE
	)

	class Meta:
		abstract = True

class LDAPSetting(BaseLDAPSetting):
	v_string = models.CharField(
		verbose_name=_(f"param_{LDAP_SETTING_PREFIX}_string"),
		null=True,
		blank=True,
		max_length=256
	)
	v_password_aes = models.BinaryField(
		verbose_name=_(f"param_{LDAP_SETTING_PREFIX}_aes"),
		null=True,
		blank=True
	)
	v_password_ct = models.BinaryField(
		verbose_name=_(f"param_{LDAP_SETTING_PREFIX}_ct"),
		null=True,
		blank=True
	)
	v_password_nonce = models.BinaryField(
		verbose_name=_(f"param_{LDAP_SETTING_PREFIX}_nonce"),
		null=True,
		blank=True
	)
	v_password_tag = models.BinaryField(
		verbose_name=_(f"param_{LDAP_SETTING_PREFIX}_tag"),
		null=True,
		blank=True
	)
	v_bool = models.BooleanField(
		verbose_name=_(f"param_{LDAP_SETTING_PREFIX}_bool"),
		null=True,
		blank=True
	)
	v_json = models.JSONField(
		verbose_name=_(f"param_{LDAP_SETTING_PREFIX}_json"),
		null=True,
		blank=True
	)
	v_integer = models.IntegerField(
		verbose_name=_(f"param_{LDAP_SETTING_PREFIX}_integer"),
		null=True,
		blank=True
	)
	v_tls = models.CharField(
		verbose_name=_(f"param_{LDAP_SETTING_PREFIX}_tls"),
		null=True,
		blank=True,
		choices=LDAP_TLS_TYPES
	)
	v_ldap_uri = ArrayField(
		models.CharField(_(f"param_{LDAP_SETTING_PREFIX}_ldap_uri"), max_length=255),
		verbose_name=_(f"param_{LDAP_SETTING_PREFIX}_ldap_uri_list"),
		null=True,
		blank=True,
		validators=[validate_ldap_uri]
	)

	class Meta:
		constraints = [
			models.CheckConstraint(
				check=models.Q(
						v_password_aes=None,
						v_password_ct=None,
						v_password_nonce=None,
						v_password_tag=None
						) |
					  models.Q(
						v_password_aes__isnull=False,
						v_password_ct__isnull=False,
						v_password_nonce__isnull=False,
						v_password_tag__isnull=False
					  ),
				name=f'{LDAP_SETTING_PREFIX}_password_crypt_data_all_or_none'
			)
		]

	@staticmethod
	def value_field(t: str=None) -> str | Iterable:
		if t == LDAP_TYPE_PASSWORD:
			return LDAP_TYPE_PASSWORD_FIELDS
		return f"{LDAP_SETTING_PREFIX}_{t.lower()}"

	def __str__(self):
		return getattr(self, f"{LDAP_SETTING_PREFIX}_{self.type.lower()}", None)
