from core.constants.attrs import *
from .search_attr_builder import SearchAttrBuilder


class LDAPGroupSearchAttrBuilder(SearchAttrBuilder):
	def get_list_filter(self):
		return [
			self._to_ldap(LOCAL_ATTR_COMMON_NAME),
			self._to_ldap(LOCAL_ATTR_DN),
			self._to_ldap(LOCAL_ATTR_GROUP_TYPE),
			self._to_ldap(LOCAL_ATTR_GROUP_MEMBERS),
		]

	def get_fetch_filter(self):
		return [
			self._to_ldap(LOCAL_ATTR_COMMON_NAME),
			self._to_ldap(LOCAL_ATTR_EMAIL),
			self._to_ldap(LOCAL_ATTR_GROUP_MEMBERS),
			self._to_ldap(LOCAL_ATTR_DN),
			self._to_ldap(LOCAL_ATTR_GROUP_TYPE),
			self._to_ldap(LOCAL_ATTR_SECURITY_ID),
			self._to_ldap(LOCAL_ATTR_OBJECT_CLASS),
		]

	def get_insert_filter(self):
		return [
			self._to_ldap(LOCAL_ATTR_COMMON_NAME),
			self._to_ldap(LOCAL_ATTR_DN),
			self._to_ldap(LOCAL_ATTR_UPN),
		]
