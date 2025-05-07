from core.models.ldap_settings_runtime import RuntimeSettingsSingleton
from core.constants.attrs import *

class GroupViewsetFilterAttributeBuilder:
	def __init__(self, settings: RuntimeSettingsSingleton):
		self.RunningSettings = settings

	def get_list_filter(self):
		return [
			LDAP_ATTR_COMMON_NAME,
			LDAP_ATTR_DN,
			LDAP_ATTR_GROUP_TYPE,
			LDAP_ATTR_GROUP_MEMBERS,
		]

	def get_fetch_filter(self):
		return [
			LDAP_ATTR_COMMON_NAME,
			LDAP_ATTR_EMAIL,
			LDAP_ATTR_GROUP_MEMBERS,
			LDAP_ATTR_DN,
			LDAP_ATTR_GROUP_TYPE,
			LDAP_ATTR_SECURITY_ID,
			LDAP_ATTR_OBJECT_CLASS,
		]

	def get_insert_filter(self):
		return [
			LDAP_ATTR_COMMON_NAME,
			LDAP_ATTR_DN,
			LDAP_ATTR_UPN,
		]
