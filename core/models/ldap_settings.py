from .base import BaseModel
from django.db import models
from .validators.ldap_uri import validate_ldap_uri
from django.core.exceptions import ValidationError
from django.utils.translation import gettext_lazy as _
from django.contrib.postgres.fields import ArrayField

LDAP_TYPE_STRING = "STRING"
LDAP_TYPE_BOOL = "BOOL"
LDAP_TYPE_JSON = "JSON"
LDAP_TYPE_INTEGER = "INTEGER"
LDAP_TYPE_PASSWORD = "PASSWORD"
LDAP_TYPE_TLS_VER = "TLS"
LDAP_TYPE_LDAP_URI = "LDAP_URI"
LDAP_SETTING_TYPES = (
	(LDAP_TYPE_STRING, "String"),
	(LDAP_TYPE_BOOL, "Boolean"),
	(LDAP_TYPE_JSON, "JSON Object"),
	(LDAP_TYPE_PASSWORD, "Password"),
	(LDAP_TYPE_INTEGER, "Integer"),
	(LDAP_TYPE_LDAP_URI, "LDAP URI"),
    (LDAP_TYPE_TLS_VER, "LDAP TLS Version")
)
LDAP_SETTING_TYPES_LIST = [x[0] for x in LDAP_SETTING_TYPES]

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
    "LDAP_AUTH_TLS_VERSION": LDAP_TYPE_TLS_VER,
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
    "LDAP_AUTH_RECEIVE_TIMEOUT": LDAP_TYPE_INTEGER,
    "ADMIN_GROUP_TO_SEARCH": LDAP_TYPE_STRING
}

LDAP_SETTINGS_CHOICES_MAP = {
    LDAP_TYPE_TLS_VER:[
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
    name = models.CharField(verbose_name=_("name"), unique=True, null=False, blank=False, max_length=128)

class BaseLDAPSetting(BaseModel):
    id = models.BigAutoField(verbose_name=_("id"), primary_key=True)
    name = models.CharField(verbose_name=_("name"), unique=True, null=False, blank=False, max_length=128)
    type = models.CharField(verbose_name=_("type"), choices=LDAP_SETTING_TYPES, null=False)
    preset = models.ForeignKey(LDAPPreset, verbose_name=_("ldap_preset"), on_delete=models.CASCADE)

    class Meta:
        abstract = True

class LDAPSetting(BaseLDAPSetting):
    v_string = models.CharField(verbose_name=_("param_v_string"), null=True, blank=True, max_length=128)
    v_password = models.CharField(verbose_name=_("param_v_password"), null=True, blank=True)
    v_bool = models.BooleanField(verbose_name=_("param_v_bool"), null=True, blank=True)
    v_json = models.JSONField(verbose_name=_("param_v_json"), null=True, blank=True)
    v_integer = models.IntegerField(verbose_name=_("param_v_integer"), null=True, blank=True)
    v_tls = models.CharField(verbose_name=_("param_v_tls"), null=True, blank=True)
    v_ldap_uri = ArrayField(
        models.CharField(_("param_v_ldap_uri"), max_length=255),
        verbose_name=_("param_v_ldap_uri_list"),
        null=True,
        blank=True,
        validators=[validate_ldap_uri]
    )

    def __str__(self):
        return getattr(self, f"v_{self.type.lower()}", None)
