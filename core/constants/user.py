################################################################################
#################### INTERLOCK IS LICENSED UNDER GNU AGPLv3 ####################
################## ORIGINAL PROJECT CREATED BY DYLAN BLANQUÉ ###################
########################## AND BR CONSULTING S.R.L. ############################
################################################################################
# Module: core.constants.user
# Contains constants for User classes

# ---------------------------------- IMPORTS -----------------------------------#
from .search_attr_builder import SearchAttrBuilder
from core.constants.attrs.local import *
from core.utils.main import getlocalkeyforldapattr
################################################################################

LOCAL_PUBLIC_FIELDS_BASIC = (
	LOCAL_ATTR_ID,
	LOCAL_ATTR_USERNAME,
	LOCAL_ATTR_EMAIL,
	LOCAL_ATTR_DN,
	LOCAL_ATTR_USERTYPE,
	LOCAL_ATTR_IS_ENABLED,
)

LOCAL_PUBLIC_FIELDS = (
	*LOCAL_PUBLIC_FIELDS_BASIC,
	LOCAL_ATTR_FIRST_NAME,
	LOCAL_ATTR_LAST_NAME,
	LOCAL_ATTR_LAST_LOGIN,
	LOCAL_ATTR_CREATED,
	LOCAL_ATTR_MODIFIED,
)

# Lower-cased username, well-known Relative ID
BUILTIN_ADMIN = ("administrator", 500)
BUILTIN_USERS = (
	BUILTIN_ADMIN,
	("guest", 501),
	("krbtgt", 502),
)


class LDAPUserSearchAttrBuilder(SearchAttrBuilder):
	def get_list_attrs(self):
		return [
			self._to_ldap(LOCAL_ATTR_FIRST_NAME),
			self._to_ldap(LOCAL_ATTR_LAST_NAME),
			self._to_ldap(LOCAL_ATTR_FULL_NAME),
			self._to_ldap(LOCAL_ATTR_USERNAME),
			self._to_ldap(LOCAL_ATTR_EMAIL),
			self._to_ldap(LOCAL_ATTR_DN),
			self._to_ldap(LOCAL_ATTR_UAC),
		]

	def get_fetch_attrs(self):
		return [
			self._to_ldap(LOCAL_ATTR_FIRST_NAME),
			self._to_ldap(LOCAL_ATTR_LAST_NAME),
			self._to_ldap(LOCAL_ATTR_FULL_NAME),
			self._to_ldap(LOCAL_ATTR_USERNAME),
			self._to_ldap(LOCAL_ATTR_EMAIL),
			self._to_ldap(LOCAL_ATTR_PHONE),
			self._to_ldap(LOCAL_ATTR_ADDRESS),
			self._to_ldap(LOCAL_ATTR_POSTAL_CODE),
			self._to_ldap(LOCAL_ATTR_CITY),  # Local / City
			self._to_ldap(LOCAL_ATTR_STATE),  # State/Province
			self._to_ldap(LOCAL_ATTR_COUNTRY),  # 2 Letter Code for Country
			self._to_ldap(LOCAL_ATTR_COUNTRY_DCC),  # INT
			self._to_ldap(LOCAL_ATTR_COUNTRY_ISO),  # Full Country Name
			self._to_ldap(LOCAL_ATTR_WEBSITE),
			self._to_ldap(LOCAL_ATTR_DN),
			self._to_ldap(LOCAL_ATTR_UPN),
			self._to_ldap(LOCAL_ATTR_UAC),  # Permission ACLs
			self._to_ldap(LOCAL_ATTR_CREATED),
			self._to_ldap(LOCAL_ATTR_MODIFIED),
			self._to_ldap(LOCAL_ATTR_LAST_LOGIN_WIN32),
			self._to_ldap(LOCAL_ATTR_BAD_PWD_COUNT),
			self._to_ldap(LOCAL_ATTR_PWD_SET_AT),
			self._to_ldap(LOCAL_ATTR_PRIMARY_GROUP_ID),
			self._to_ldap(LOCAL_ATTR_OBJECT_CLASS),
			self._to_ldap(LOCAL_ATTR_OBJECT_CATEGORY),
			self._to_ldap(LOCAL_ATTR_SECURITY_ID),
			self._to_ldap(LOCAL_ATTR_ACCOUNT_TYPE),
			self._to_ldap(LOCAL_ATTR_USER_GROUPS),
		]

	def get_update_attrs(self):
		return [
			self._to_ldap(LOCAL_ATTR_USERNAME),
			self._to_ldap(LOCAL_ATTR_DN),
			self._to_ldap(LOCAL_ATTR_UPN),
			self._to_ldap(LOCAL_ATTR_UAC),
		]

	def get_bulk_insert_attrs(self):
		return [
			self._to_ldap(LOCAL_ATTR_USERNAME),
			self._to_ldap(LOCAL_ATTR_DN),
			self._to_ldap(LOCAL_ATTR_UPN),
		]

	def get_update_self_exclude_keys(self):
		"""Return local keys to exclude"""
		return [
			"can_change_pwd",
			LOCAL_ATTR_PASSWORD,
			LOCAL_ATTR_PASSWORD_CONFIRM,
			LOCAL_ATTR_PATH,
			LOCAL_ATTR_DN,
			LOCAL_ATTR_USERNAME,
			LOCAL_ATTR_CREATED,
			LOCAL_ATTR_MODIFIED,
			LOCAL_ATTR_LAST_LOGIN_WIN32,
			LOCAL_ATTR_BAD_PWD_COUNT,
			LOCAL_ATTR_PWD_SET_AT,
			LOCAL_ATTR_IS_ENABLED,
			LOCAL_ATTR_ACCOUNT_TYPE,
			LOCAL_ATTR_PERMISSIONS,
			LOCAL_ATTR_UAC,
			LOCAL_ATTR_OBJECT_CATEGORY,
			LOCAL_ATTR_OBJECT_CLASS,
			LOCAL_ATTR_PRIMARY_GROUP_ID,
		]

	def get_fetch_me_attrs(self) -> list[str]:
		"""Returns local keys"""
		_REMOVE = [
			self._to_ldap(LOCAL_ATTR_PRIMARY_GROUP_ID),
			self._to_ldap(LOCAL_ATTR_OBJECT_CLASS),
			self._to_ldap(LOCAL_ATTR_OBJECT_CATEGORY),
			self._to_ldap(LOCAL_ATTR_SECURITY_ID),
			self._to_ldap(LOCAL_ATTR_ACCOUNT_TYPE),
			self._to_ldap(LOCAL_ATTR_USER_GROUPS),
		]
		_RESULT = self.get_fetch_attrs()
		for value in _REMOVE:
			_RESULT.remove(value)
		return [getlocalkeyforldapattr(v) for v in _RESULT]
