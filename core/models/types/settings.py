################################################################################
#################### INTERLOCK IS LICENSED UNDER GNU AGPLv3 ####################
################## ORIGINAL PROJECT CREATED BY DYLAN BLANQUÉ ###################
########################## AND BR CONSULTING S.R.L. ############################
################################################################################
# Module: core.models.types.settings
# Contains the types for settings

# ---------------------------------- IMPORTS --------------------------------- #
from django.db import models
from django.contrib.postgres.fields import ArrayField
################################################################################

TYPE_FLOAT = "float"
TYPE_STRING = "str"
TYPE_BYTES = "bytes"
TYPE_BOOL = "bool"
TYPE_JSON = "json"
TYPE_INTEGER = "integer"
TYPE_LDAP_TLS_VERSION = "ldap_tls"
TYPE_LDAP_URI = "ldap_uri"
TYPE_AES_ENCRYPT_FIELDS = (
	"crypt_aes",
	"crypt_ct",
	"crypt_nonce",
	"crypt_tag",
)
TYPE_AES_ENCRYPT = "crypt"

DEFAULT_FIELD_ARGS = {"null": True, "blank": True}
MAP_FIELD_VALUE_MODEL = {
	TYPE_FLOAT: models.FloatField,
	TYPE_STRING: models.CharField,
	TYPE_BYTES: models.BinaryField,
	TYPE_BOOL: models.BooleanField,
	TYPE_JSON: models.JSONField,
	TYPE_INTEGER: models.IntegerField,
	TYPE_LDAP_TLS_VERSION: models.CharField,
	TYPE_LDAP_URI: ArrayField,
}
for key in TYPE_AES_ENCRYPT_FIELDS:
	MAP_FIELD_VALUE_MODEL[key] = models.BinaryField

MAP_FIELD_TYPE_MODEL = {
	TYPE_FLOAT: float,
	TYPE_STRING: str,
	TYPE_BYTES: bytes,
	TYPE_BOOL: bool,
	TYPE_JSON: dict,
	TYPE_INTEGER: int,
	TYPE_LDAP_TLS_VERSION: str,
	TYPE_LDAP_URI: list,
}
for key in TYPE_AES_ENCRYPT_FIELDS:
	MAP_FIELD_TYPE_MODEL[key] = bytes


def make_field_db_name(v: str) -> str | tuple:
	if isinstance(v, str):
		return "_" + v
	elif isinstance(v, tuple):
		return "_" + v[0]


BASE_SETTING_FIELDS = {
	TYPE_AES_ENCRYPT: TYPE_AES_ENCRYPT_FIELDS,
	TYPE_FLOAT: TYPE_FLOAT,
	TYPE_STRING: TYPE_STRING,
	TYPE_BYTES: TYPE_BYTES,
	TYPE_BOOL: TYPE_BOOL,
	TYPE_JSON: TYPE_JSON,
	TYPE_INTEGER: TYPE_INTEGER,
}

INTERLOCK_SETTING_FIELDS = BASE_SETTING_FIELDS
LDAP_SETTING_FIELDS = BASE_SETTING_FIELDS | {
	TYPE_LDAP_URI: TYPE_LDAP_URI,
	TYPE_LDAP_TLS_VERSION: TYPE_LDAP_TLS_VERSION,
}
