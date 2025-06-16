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
from core.exceptions import base as exc_base, users as exc_user
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
from typing import overload
from logging import getLogger
from core.models.ldap_object import LDAPObject, LDAPObjectTypes
from core.utils.main import getldapattrvalue
################################################################################

logger = getLogger()

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
		self.parse_add_groups()
		self.parse_remove_groups(
			groups=self.attributes.get(LOCAL_ATTR_USER_GROUPS, None),
			remove_group_dns=self.attributes.get(
				LOCAL_ATTR_USER_RM_GROUPS, None
			),
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

	def parse_add_groups(self):
		if not LOCAL_ATTR_USER_ADD_GROUPS in self.parsed_specials:
			self.parsed_specials.append(LOCAL_ATTR_USER_ADD_GROUPS)

	def parse_remove_groups(
		self,
		groups: list[dict] = None,
		remove_group_dns: list[str] = None,
	) -> None:
		if not remove_group_dns or not groups:
			return

		# Fetch Primary Group ID from Server-side Entry
		primary_group_id = getldapattrvalue(
			self.entry,
			LDAP_ATTR_PRIMARY_GROUP_ID,
			None,
		)
		if primary_group_id is not None:
			primary_group_id = int(primary_group_id)

		if remove_group_dns and not primary_group_id:
			logger.warning(
				"Cannot parse group removal without providing"
				"the user's Primary Group ID"
			)
			raise exc_user.PrimaryGroupIDRequired

		for g in groups:
			distinguished_name: str = g.get(LOCAL_ATTR_DN, None)
			relative_id: int = g.get(LOCAL_ATTR_RELATIVE_ID, None)
			# Validate RID
			if not isinstance(relative_id, int):
				try:
					relative_id = int(relative_id)
				except:
					raise exc_base.BadRequest(
						data={
							"detail": "Group Relative ID is not a valid integer."
						}
					)
			# Validate both DN and RID exist
			if not distinguished_name or not relative_id:
				raise exc_base.BadRequest(
					data={
						"detail": "Full parsed groups must be sent along with removal operations."
					}
				)

			if primary_group_id == relative_id and (
				distinguished_name in remove_group_dns
				or distinguished_name.lower() in remove_group_dns
			):
				remove_group_dns.remove(distinguished_name)

		if not LOCAL_ATTR_USER_RM_GROUPS in self.parsed_specials:
			self.parsed_specials.append(LOCAL_ATTR_USER_RM_GROUPS)

	def parse_write_country(self, value: str = None):
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
		# If value is None then no changes were received for this field
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

	def perform_group_operations(
		self, groups_to_add=None, groups_to_remove=None
	):
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
