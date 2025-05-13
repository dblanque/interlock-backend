################################################################################
#################### INTERLOCK IS LICENSED UNDER GNU AGPLv3 ####################
################## ORIGINAL PROJECT CREATED BY DYLAN BLANQUÉ ###################
########################## AND BR CONSULTING S.R.L. ############################
################################################################################
# Module: core.models.ldap_user
# Contains the Models for generic LDAP Objects
#
# ---------------------------------- IMPORTS -----------------------------------#
### Django
from django.utils.translation import gettext_lazy as _

### Interlock
from core.exceptions import users as exc_user
from core.constants.attrs import *
from core.ldap.countries import LDAP_COUNTRIES
from core.config.runtime import RuntimeSettings
from core.ldap.adsi import (
	calc_permissions,
	list_user_perms,
	LDAP_UF_ACCOUNT_DISABLE,
	LDAP_UF_NORMAL_ACCOUNT,
)

### Others
from core.type_hints.connector import LDAPConnectionProtocol
from core.ldap.filter import LDAPFilter
from ldap3 import Entry as LDAPEntry
from typing import overload
from logging import getLogger
from core.models.ldap_object import LDAPObject, LDAPObjectTypes

################################################################################
logger = getLogger()


class LDAPUser(LDAPObject):
	type = LDAPObjectTypes.USER
	search_attrs = (
		LDAP_ATTR_DN,
		LDAP_ATTR_USERNAME_SAMBA_ADDS,
		LDAP_ATTR_EMAIL,
		LDAP_ATTR_FIRST_NAME,
		LDAP_ATTR_LAST_NAME,
		LDAP_ATTR_FULL_NAME,
		LDAP_ATTR_PHONE,
		LDAP_ATTR_ADDRESS,
		LDAP_ATTR_POSTAL_CODE,
		LDAP_ATTR_CITY,
		LDAP_ATTR_STATE,
		LDAP_ATTR_COUNTRY,
		LDAP_ATTR_COUNTRY_DCC,
		LDAP_ATTR_COUNTRY_ISO,
		LDAP_ATTR_WEBSITE,
		LDAP_ATTR_UPN,
		LDAP_ATTR_UAC,
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
		LDAP_ATTR_INITIALS,
	)

	def __validate_init__(self, **kwargs):
		kw_samaccountname = kwargs.pop(LDAP_ATTR_USERNAME_SAMBA_ADDS, None)
		self.username = kwargs.pop(LOCAL_ATTR_USERNAME, kw_samaccountname)

		# Type check Entry
		if self.entry and not isinstance(self.entry, LDAPEntry):
			raise TypeError(
				"LDAPUser entry must attr must be of type ldap3.Entry"
			)

		if not self.connection and not self.entry:
			raise Exception(
				"LDAPUser requires an LDAP Connection or an Entry to Initialize"
			)
		elif self.connection:
			if not self.distinguished_name and not self.username:
				raise Exception(
					"LDAPUser requires a distinguished_name or username to search for the object"
				)

		if self.entry:
			self.__set_dn_and_filter_from_entry__()
		elif self.distinguished_name and isinstance(
			self.distinguished_name, str
		):
			self.search_filter = LDAPFilter.eq(
				LDAP_ATTR_DN, self.distinguished_name
			).to_string()
		elif self.username and isinstance(self.username, str):
			_USER_CLASSES = {
				RuntimeSettings.LDAP_AUTH_OBJECT_CLASS,
				"user",
				"person",
				"organizationalPerson",
			}
			self.search_filter = LDAPFilter.and_(
				LDAPFilter.or_(
					*[
						LDAPFilter.eq(LDAP_ATTR_OBJECT_CLASS, auth_class)
						for auth_class in _USER_CLASSES
					]
				),
				LDAPFilter.eq(LDAP_ATTR_USERNAME_SAMBA_ADDS, self.username),
			).to_string()

	@overload
	def __init__(
		self,
		entry: LDAPEntry = None,
		connection: LDAPConnectionProtocol = None,
		distinguished_name: str = None,
		username: str = None,
		search_base: str = None,
		excluded_attributes: list[str] = None,
		required_attributes: list[str] = None,
		attributes: dict = None,
	) -> None: ...

	def __init__(self, **kwargs):
		super().__init__(**kwargs)

	def parse_special_attributes(self):
		self.parse_country(self.attributes.get(LOCAL_ATTR_COUNTRY, None))
		self.parse_permissions(
			self.attributes.get(LOCAL_ATTR_PERMISSIONS, None)
		)

	def post_create(self):
		self.parse_group_operations(
			groups_to_add=self.attributes.get(LOCAL_ATTR_USER_ADD_GROUPS, []),
			groups_to_remove=self.attributes.get(LOCAL_ATTR_USER_RM_GROUPS, []),
		)

	def post_update(self):
		self.post_create()

	def parse_country(self, value: str = None):
		_COUNTRY_ATTRS = (
			LOCAL_ATTR_COUNTRY,
			LOCAL_ATTR_COUNTRY_DCC,
			LOCAL_ATTR_COUNTRY_ISO,
		)
		if value is None:
			return
		if value == "":
			self.attributes[LOCAL_ATTR_COUNTRY_DCC] = ""
			self.attributes[LOCAL_ATTR_COUNTRY_ISO] = ""
		else:
			self.attributes[LOCAL_ATTR_COUNTRY_DCC] = LDAP_COUNTRIES[value][
				"dccCode"
			]
			self.attributes[LOCAL_ATTR_COUNTRY_ISO] = LDAP_COUNTRIES[value][
				"isoCode"
			]

		for attr in _COUNTRY_ATTRS:
			if not attr in self.parsed_specials:
				self.parsed_specials.append(attr)

	def parse_permissions(self, value: list[str]):
		if value is None:
			return
		if value and isinstance(value, list):
			self.attributes[LOCAL_ATTR_UAC] = calc_permissions(
				permission_list=value
			)
		else:
			self.attributes[LOCAL_ATTR_UAC] = calc_permissions(
				[LDAP_UF_NORMAL_ACCOUNT]
			)
		if not LOCAL_ATTR_UAC in self.parsed_specials:
			self.parsed_specials.append(LOCAL_ATTR_UAC)

	def parse_group_operations(self, groups_to_add=None, groups_to_remove=None):
		# De-duplicate group ops
		if groups_to_add:
			groups_to_add = set(groups_to_add)
		if groups_to_remove:
			groups_to_remove = set(groups_to_remove)

		if groups_to_add and groups_to_remove:
			if groups_to_add == groups_to_remove:
				raise exc_user.BadGroupSelection
			if any(a == b for a, b in zip(groups_to_add, groups_to_remove)):
				raise exc_user.BadGroupSelection

		# Group Add
		if groups_to_add:
			self.connection.extend.microsoft.add_members_to_groups(
				self.distinguished_name, groups_to_add
			)

		# Group Remove
		if groups_to_remove:
			self.connection.extend.microsoft.remove_members_from_groups(
				self.distinguished_name, groups_to_remove
			)

	@property
	def is_enabled(self):
		if not self.entry:
			raise ValueError("No LDAP Entry for LDAPObjectUser")
		if not LDAP_ATTR_UAC in self.entry.entry_attributes:
			raise ValueError(
				"%s attribute is required in entry search" % (LDAP_ATTR_UAC)
			)

		return not list_user_perms(
			user=self.entry,
			perm_search=LDAP_UF_ACCOUNT_DISABLE,
		)
