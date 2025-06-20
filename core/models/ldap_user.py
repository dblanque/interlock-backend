################################################################################
#################### INTERLOCK IS LICENSED UNDER GNU AGPLv3 ####################
################## ORIGINAL PROJECT CREATED BY DYLAN BLANQUÉ ###################
########################## AND BR CONSULTING S.R.L. ############################
################################################################################
# Module: core.models.ldap_user
# Contains the Models for generic LDAP Objects
#
# ---------------------------------- IMPORTS ----------------------------------#

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
	LDAP_UF_PASSWD_CANT_CHANGE,
)

### Others
from core.type_hints.connector import LDAPConnectionProtocol
from core.ldap.filter import LDAPFilter
from ldap3 import Entry as LDAPEntry
from typing import overload, get_args, Literal
from logging import getLogger
from core.models.ldap_object import LDAPObject, LDAPObjectTypes
from core.utils.main import getldapattrvalue
################################################################################

logger = getLogger()

GroupsCleanupOperation = Literal["add", "remove"]

DEFAULT_LOCAL_ATTRS = (
	LOCAL_ATTR_DN,
	LOCAL_ATTR_USERNAME,
	LOCAL_ATTR_EMAIL,
	LOCAL_ATTR_FIRST_NAME,
	LOCAL_ATTR_LAST_NAME,
	LOCAL_ATTR_FULL_NAME,
	LOCAL_ATTR_PHONE,
	LOCAL_ATTR_ADDRESS,
	LOCAL_ATTR_POSTAL_CODE,
	LOCAL_ATTR_CITY,
	LOCAL_ATTR_STATE,
	LOCAL_ATTR_COUNTRY,
	LOCAL_ATTR_COUNTRY_DCC,
	LOCAL_ATTR_COUNTRY_ISO,
	LOCAL_ATTR_WEBSITE,
	LOCAL_ATTR_UPN,
	LOCAL_ATTR_UAC,
	LOCAL_ATTR_CREATED,
	LOCAL_ATTR_MODIFIED,
	LOCAL_ATTR_LAST_LOGIN,
	LOCAL_ATTR_BAD_PWD_COUNT,
	LOCAL_ATTR_PWD_SET_AT,
	LOCAL_ATTR_PRIMARY_GROUP_ID,
	LOCAL_ATTR_OBJECT_CLASS,
	LOCAL_ATTR_OBJECT_CATEGORY,
	LOCAL_ATTR_SECURITY_ID,
	LOCAL_ATTR_ACCOUNT_TYPE,
	LOCAL_ATTR_USER_GROUPS,
	LOCAL_ATTR_INITIALS,
)


class LDAPUser(LDAPObject):
	type = LDAPObjectTypes.USER
	search_attrs = None

	@overload
	def __init__(
		self,
		entry: LDAPEntry = None,
		connection: LDAPConnectionProtocol = None,
		distinguished_name: str = None,
		search_base: str = None,
		search_attrs: list[str] = None,
		excluded_ldap_attributes: list[str] = None,
		attributes: dict = None,
		skip_fetch: bool = False,
		context: dict = None,
		username: str = None,
	) -> None: ...

	# Only defined explicitly for overload definition
	def __init__(self, **kwargs):
		self.search_attrs = {
			RuntimeSettings.LDAP_FIELD_MAP.get(attr)
			for attr in DEFAULT_LOCAL_ATTRS
			if RuntimeSettings.LDAP_FIELD_MAP.get(attr, None)
		}
		self.default_attrs = self.search_attrs
		super().__init__(**kwargs)

	def __validate_init__(self, **kwargs):
		kw_samaccountname = kwargs.pop(LDAP_ATTR_USERNAME_SAMBA_ADDS, None)
		self.username = kwargs.pop(LOCAL_ATTR_USERNAME, kw_samaccountname)

		if self.username:
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
		else:
			super().__validate_init__(**kwargs)

	def parse_write_special_attributes(self):
		# Cleanup Groups to ADD
		self.cleanup_groups_operation(
			group_dns=self.attributes.get(LOCAL_ATTR_USER_ADD_GROUPS, None),
			operation="add",
		)
		# Cleanup Groups to REMOVE
		self.cleanup_groups_operation(
			group_dns=self.attributes.get(LOCAL_ATTR_USER_RM_GROUPS, None),
			operation="remove",
		)
		self.parse_write_country(self.attributes.get(LOCAL_ATTR_COUNTRY, None))
		self.parse_write_permissions(
			self.attributes.get(LOCAL_ATTR_PERMISSIONS, None)
		)

	def post_create(self):
		self.perform_group_operations(
			groups_to_add=self.attributes.get(LOCAL_ATTR_USER_ADD_GROUPS, []),
			groups_to_remove=self.attributes.get(LOCAL_ATTR_USER_RM_GROUPS, []),
		)

	def post_update(self):
		self.post_create()

	def save(self):
		has_groups_to_modify = bool(
			self.attributes.get(LOCAL_ATTR_USER_ADD_GROUPS, [])
			or self.attributes.get(LOCAL_ATTR_USER_RM_GROUPS, [])
		)
		return super().save(
			update_kwargs={
				"force_post_update": has_groups_to_modify,
			}
		)

	def remove_primary_group(
		self, group_dns: list[str]
	) -> tuple[list[str], bool]:
		"""
		Finds Primary Group by Relative ID and removes its Distinguished Name
		from list of strings.
		"""
		found_id = False
		if not group_dns:
			return
		if not isinstance(group_dns, list | set):
			raise TypeError("group_dns must be of types list, set")
		if not isinstance(group_dns, set):
			group_dns = set(group_dns)
		user_primary_group_id = int(
			getldapattrvalue(
				self.entry,
				LDAP_ATTR_PRIMARY_GROUP_ID,
				None,
			)
		)

		if not "LDAPGroup" in globals().keys():
			from core.models.ldap_group import LDAPGroup
		group_objects = [
			LDAPGroup(
				distinguished_name=distinguished_name,
				connection=self.connection,
			)
			for distinguished_name in group_dns
		]
		for group in group_objects:
			# Fetch Primary Group ID from Server-side Entry
			group_relative_id = group.attributes.get(LOCAL_ATTR_RELATIVE_ID)
			if group_relative_id == user_primary_group_id:
				found_id = True
				group_dns.remove(group.distinguished_name)
		return group_dns, found_id

	def cleanup_groups_operation(
		self,
		group_dns: list[str] | set[str] | str = None,
		operation: GroupsCleanupOperation = None,
	):
		"""Cleans up Group DN List in self.attributes before saving."""
		if not group_dns:
			return
		if not operation in get_args(GroupsCleanupOperation):
			raise ValueError("operation must be add or remove.")
		if not isinstance(group_dns, (list, set, tuple, str)):
			raise TypeError(
				"add_group_dns must be of types list, set, tuple, str"
			)

		if operation == "add":
			_attr = LOCAL_ATTR_USER_ADD_GROUPS
		else:
			_attr = LOCAL_ATTR_USER_RM_GROUPS

		if isinstance(group_dns, str):
			group_dns = {group_dns}
		elif isinstance(group_dns, (list, tuple)):
			group_dns = set(group_dns)

		# Remove groups that the user is already a member of
		previous_groups = getldapattrvalue(
			self.entry, LDAP_ATTR_USER_GROUPS, []
		)
		if previous_groups:
			if not isinstance(previous_groups, (list, set, tuple)):
				previous_groups = [previous_groups]
			ignore_dns = set()
			for distinguished_name in group_dns:
				_cond = (
					distinguished_name in previous_groups
					if operation == "add" else
					distinguished_name not in previous_groups
				)
				if _cond:
					ignore_dns.add(distinguished_name)
			for distinguished_name in ignore_dns:
				group_dns.remove(distinguished_name)
			self.attributes[_attr] = group_dns

		group_dns, was_removed = self.remove_primary_group(
			group_dns=group_dns
		)
		if not _attr in self.parsed_specials:
			self.parsed_specials.append(_attr)

	def parse_write_country(self, value: str = None):
		"""Parses Country data before saving to LDAP Server."""
		_COUNTRY_ATTRS = (
			LOCAL_ATTR_COUNTRY,
			LOCAL_ATTR_COUNTRY_DCC,
			LOCAL_ATTR_COUNTRY_ISO,
		)
		if value:
			self.attributes[LOCAL_ATTR_COUNTRY_DCC] = int(
				LDAP_COUNTRIES[value]["dccCode"]
			)
			self.attributes[LOCAL_ATTR_COUNTRY_ISO] = LDAP_COUNTRIES[value][
				"isoCode"
			]
		elif not value:
			self.attributes[LOCAL_ATTR_COUNTRY] = None
			self.attributes[LOCAL_ATTR_COUNTRY_DCC] = 0
			self.attributes[LOCAL_ATTR_COUNTRY_ISO] = None

		for attr in _COUNTRY_ATTRS:
			if not attr in self.parsed_specials:
				self.parsed_specials.append(attr)

	def parse_write_permissions(self, value: list[str]):
		"""Parses Permission data before saving to LDAP Server."""
		# If value is None then no changes were received for this field
		if value is None:
			return

		if isinstance(value, (list, tuple)):
			value = set(value)
		if not value or not isinstance(value, (list, set)):
			value = [
				LDAP_UF_NORMAL_ACCOUNT,
				LDAP_UF_ACCOUNT_DISABLE,
			]
		self.attributes[LOCAL_ATTR_UAC] = calc_permissions(value)
		self.attributes[LOCAL_ATTR_PERMISSIONS] = value
		if not LOCAL_ATTR_UAC in self.parsed_specials:
			self.parsed_specials.append(LOCAL_ATTR_UAC)

	def perform_group_operations(
		self, groups_to_add=None, groups_to_remove=None
	):
		"""Executes parsed group membership changes."""
		# De-duplicate group ops
		if groups_to_add:
			if not LOCAL_ATTR_USER_ADD_GROUPS in self.parsed_specials:
				raise exc_user.CoreException
			groups_to_add = set(groups_to_add)
		if groups_to_remove:
			if not LOCAL_ATTR_USER_RM_GROUPS in self.parsed_specials:
				raise exc_user.CoreException
			groups_to_remove = set(groups_to_remove)

		if groups_to_add and groups_to_remove:
			if groups_to_add == groups_to_remove:
				raise exc_user.BadGroupSelection
			for a in groups_to_add:
				if a in groups_to_remove:
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
			raise ValueError(
				"An LDAP Entry is required to check if the User is enabled on the server."
			)
		_UAC_FIELD = RuntimeSettings.LDAP_FIELD_MAP[LOCAL_ATTR_UAC]
		if not _UAC_FIELD in self.entry.entry_attributes:
			raise ValueError(
				"%s attribute is required in entry search" % (_UAC_FIELD)
			)

		return not list_user_perms(
			user=self.entry,
			perm_search=LDAP_UF_ACCOUNT_DISABLE,
		)

	@property
	def can_change_password(self):
		if not self.entry:
			raise ValueError(
				"An LDAP Entry is required to check if the User is enabled on the server."
			)
		_UAC_FIELD = RuntimeSettings.LDAP_FIELD_MAP[LOCAL_ATTR_UAC]
		if not _UAC_FIELD in self.entry.entry_attributes:
			raise ValueError(
				"%s attribute is required in entry search" % (_UAC_FIELD)
			)

		return not list_user_perms(
			user=self.entry,
			perm_search=LDAP_UF_PASSWD_CANT_CHANGE,
		)
