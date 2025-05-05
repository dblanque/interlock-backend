from core.models.ldap_settings_runtime import RuntimeSettingsSingleton
from core.ldap.constants import *

PUBLIC_FIELDS_SHORT = (
	"id",
	"username",
	"email",
	"dn",
	"user_type",
	"is_enabled",
)

PUBLIC_FIELDS = (
	*PUBLIC_FIELDS_SHORT,
	"first_name",
	"last_name",
	"last_login",
	"created_at",
	"modified_at",
)


class UserViewsetFilterAttributeBuilder:
	def __init__(self, settings: RuntimeSettingsSingleton):
		if not isinstance(settings, RuntimeSettingsSingleton):
			raise TypeError("Initialization for cls requires RuntimeSettingsSingleton instance.")
		self.RuntimeSettings = settings

	def get_list_attrs(self):
		return [
			LDAP_ATTR_FIRST_NAME,
			LDAP_ATTR_LAST_NAME,
			LDAP_ATTR_FULL_NAME,
			self.RuntimeSettings.LDAP_AUTH_USER_FIELDS["username"],
			LDAP_ATTR_EMAIL,
			LDAP_ATTR_DN,
			LDAP_ATTR_UAC,
		]

	def get_fetch_attrs(self):
		return [
			LDAP_ATTR_FIRST_NAME,
			LDAP_ATTR_LAST_NAME,
			LDAP_ATTR_FULL_NAME,
			self.RuntimeSettings.LDAP_AUTH_USER_FIELDS["username"],
			"mail",
			LDAP_ATTR_PHONE,
			LDAP_ATTR_ADDRESS,
			LDAP_ATTR_POSTAL_CODE,
			LDAP_ATTR_CITY,  # Local / City
			LDAP_ATTR_STATE,  # State/Province
			LDAP_ATTR_COUNTRY,  # 2 Letter Code for Country
			LDAP_ATTR_COUNTRY_DCC,  # INT
			LDAP_ATTR_COUNTRY_ISO,  # Full Country Name
			LDAP_ATTR_WEBSITE,
			LDAP_ATTR_DN,
			LDAP_ATTR_UPN,
			LDAP_ATTR_UAC,  # Permission ACLs
			LDAP_ATTR_CREATED,
			LDAP_ATTR_MODIFIED,
			LDAP_ATTR_LAST_LOGIN,
			LDAP_ATTR_BAD_PWD_COUNT,
			LDAP_ATTR_PWD_SET_AT,
			LDAP_ATTR_PRIMARY_GROUP_ID,
			LDAP_ATTR_OBJECT_CLASS,
			LDAP_ATTR_OBJECT_CATEGORY,
			LDAP_ATTR_SECURITY_ID,
			LDAP_ATTR_ACCOUNT_TYPE,
			LDAP_ATTR_USER_GROUPS,
		]

	def get_update_attrs(self):
		return [
			self.RuntimeSettings.LDAP_AUTH_USER_FIELDS["username"],
			LDAP_ATTR_DN,
			LDAP_ATTR_UPN,
			LDAP_ATTR_UAC,
		]

	def get_bulk_insert_attrs(self):
		return [
			self.RuntimeSettings.LDAP_AUTH_USER_FIELDS["username"],
			LDAP_ATTR_DN,
			LDAP_ATTR_UPN,
		]

	def get_update_exclude_keys(self):
		return [
			# Added keys for front-end normalization
			"name",
			"type",
			# Samba keys to intentionally exclude
			"password",
			"passwordConfirm",
			"path",
			"permission_list",  # This array is parsed and calculated later
			LDAP_ATTR_DN,  # We don't want the front-end generated DN
			"username",  # LDAP Uses sAMAccountName
			LDAP_ATTR_CREATED,
			LDAP_ATTR_MODIFIED,
			LDAP_ATTR_LAST_LOGIN,
			LDAP_ATTR_BAD_PWD_COUNT,
			LDAP_ATTR_PWD_SET_AT,
			"is_enabled",
			LDAP_ATTR_ACCOUNT_TYPE,
			LDAP_ATTR_OBJECT_CATEGORY,
			LDAP_ATTR_SECURITY_ID,
			LDAP_ATTR_RELATIVE_ID,
		]

	def get_update_self_exclude_keys(self):
		return [
			"can_change_pwd",
			"password",
			"passwordConfirm",
			"path",
			"permission_list",  # This array is parsed and calculated later
			LDAP_ATTR_DN,  # We don't want the front-end generated DN
			"username",  # LDAP Uses sAMAccountName
			LDAP_ATTR_CREATED,
			LDAP_ATTR_MODIFIED,
			LDAP_ATTR_LAST_LOGIN,
			LDAP_ATTR_BAD_PWD_COUNT,
			LDAP_ATTR_PWD_SET_AT,
			"is_enabled",
			LDAP_ATTR_ACCOUNT_TYPE,
			LDAP_ATTR_OBJECT_CATEGORY,
			LDAP_ATTR_UAC,
			LDAP_ATTR_OBJECT_CLASS,
			LDAP_ATTR_PRIMARY_GROUP_ID,
		]

	def get_fetch_me_attrs(self):
		_REMOVE = [
			LDAP_ATTR_PRIMARY_GROUP_ID,
			LDAP_ATTR_OBJECT_CLASS,
			LDAP_ATTR_OBJECT_CATEGORY,
			LDAP_ATTR_SECURITY_ID,
			LDAP_ATTR_ACCOUNT_TYPE,
			LDAP_ATTR_USER_GROUPS,
		]
		_RESULT = self.get_fetch_attrs()
		for value in _REMOVE:
			_RESULT.remove(value)
		return _RESULT
