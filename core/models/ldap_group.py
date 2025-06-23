################################################################################
#################### INTERLOCK IS LICENSED UNDER GNU AGPLv3 ####################
################## ORIGINAL PROJECT CREATED BY DYLAN BLANQUÉ ###################
########################## AND BR CONSULTING S.R.L. ############################
################################################################################
# Module: core.models.ldap_group
# Contains the Models for generic LDAP Objects
#
# ---------------------------------- IMPORTS ----------------------------------#
### Interlock
from core.exceptions import (
	groups as exc_group,
	ldap as exc_ldap,
)
from core.constants.attrs import *

### Others
from core.type_hints.connector import LDAPConnectionProtocol
from core.ldap.filter import LDAPFilter
from ldap3 import Entry as LDAPEntry
from ldap3.utils.dn import safe_rdn
from core.views.mixins.ldap.organizational_unit import OrganizationalUnitMixin
from typing import overload
from logging import getLogger
from core.utils.main import getldapattrvalue
from core.models.ldap_object import (
	LDAPObject,
	LDAPObjectTypes,
	ATTRS_SPECIAL_LDAP,
)
from core.config.runtime import RuntimeSettings
from core.ldap.types.group import LDAPGroupTypes
from rest_framework.request import Request

################################################################################
logger = getLogger()

DEFAULT_LOCAL_ATTRS = (
	LOCAL_ATTR_DN,
	LOCAL_ATTR_COMMON_NAME,
	LOCAL_ATTR_GROUP_MEMBERS,
	LOCAL_ATTR_GROUP_TYPE,
	LOCAL_ATTR_SECURITY_ID,
	LOCAL_ATTR_EMAIL,
	LOCAL_ATTR_OBJECT_CLASS,
	LOCAL_ATTR_OBJECT_CATEGORY,
	LOCAL_ATTR_CREATED,
	LOCAL_ATTR_MODIFIED,
)


class LDAPGroup(LDAPObject):
	type = LDAPObjectTypes.GROUP
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
		groupname: str = None,
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
		kw_common_name = kwargs.pop(
			"common_name", kwargs.pop(LOCAL_ATTR_NAME, None)
		)
		self.groupname = kwargs.pop(
			RuntimeSettings.LDAP_FIELD_MAP[LOCAL_ATTR_NAME], kw_common_name
		)

		if self.groupname and isinstance(self.groupname, str):
			self.search_filter = LDAPFilter.and_(
				LDAPFilter.eq(
					RuntimeSettings.LDAP_FIELD_MAP[LOCAL_ATTR_OBJECT_CLASS],
					"group",
				),
				LDAPFilter.eq(
					RuntimeSettings.LDAP_FIELD_MAP[LOCAL_ATTR_NAME],
					self.groupname,
				),
			).to_string()
		else:
			super().__validate_init__(**kwargs)

	def parse_read_group_type_scope(
		self, group_type: int = None
	) -> tuple[list[str], list[str]]:
		"""Get group types and scopes from integer value"""
		sum = 0
		_scopes = []
		_types = []
		if not isinstance(group_type, (int, str)) or isinstance(
			group_type, bool
		):
			raise TypeError("group_type must be of type int or str")

		if isinstance(group_type, str):
			try:
				group_type = int(group_type)
			except:
				raise ValueError("group_type could not be cast to int.")
		group_type_last_int = int(str(group_type)[-1])
		if group_type < -1:
			sum -= LDAPGroupTypes.TYPE_SECURITY.value
			_types.append(LDAPGroupTypes.TYPE_SECURITY.name)
		else:
			_types.append(LDAPGroupTypes.TYPE_DISTRIBUTION.name)

		if (group_type_last_int % 2) != 0:
			sum += LDAPGroupTypes.TYPE_SYSTEM.value
			_types.append(LDAPGroupTypes.TYPE_SYSTEM.name)
		if group_type == (sum + 2):
			sum += LDAPGroupTypes.SCOPE_GLOBAL.value
			_scopes.append(LDAPGroupTypes.SCOPE_GLOBAL.name)
		if group_type == (sum + 4):
			sum += LDAPGroupTypes.SCOPE_DOMAIN_LOCAL.value
			_scopes.append(LDAPGroupTypes.SCOPE_DOMAIN_LOCAL.name)
		if group_type == (sum + 8):
			sum += LDAPGroupTypes.SCOPE_UNIVERSAL.value
			_scopes.append(LDAPGroupTypes.SCOPE_UNIVERSAL.name)

		if sum != group_type:
			raise ValueError("Invalid group type integer calculation")

		return _types, _scopes

	def parse_write_group_type_scope(self) -> int:
		"""Convert front-end generated type and scope to LDAP acceptable int."""
		group_types = self.attributes.pop(LOCAL_ATTR_GROUP_TYPE, [])
		group_scopes = self.attributes.pop(LOCAL_ATTR_GROUP_SCOPE, [])
		if not group_types or not group_scopes:
			return

		_type = 0
		for t in set(group_types):
			t: str
			if t.lower() == LDAPGroupTypes.TYPE_SECURITY.name.lower():
				_type -= LDAPGroupTypes[t].value
			else:
				_type += LDAPGroupTypes[t].value

		_scope = 0
		_scope += LDAPGroupTypes[group_scopes[0]].value
		_sum = _type + _scope

		# Validate
		_parsed_types, _parsed_scopes = self.parse_read_group_type_scope(_sum)
		if set(_parsed_types) != set(group_types):
			raise ValueError("Could not properly parse group type")
		if set(_parsed_scopes) != set(group_scopes):
			raise ValueError("Could not properly parse group scope")

		self.attributes[LOCAL_ATTR_GROUP_TYPE] = _sum

		if not LOCAL_ATTR_GROUP_TYPE in self.parsed_specials:
			self.parsed_specials.append(LOCAL_ATTR_GROUP_TYPE)
		return _sum

	def parse_write_common_name(self):
		"""Renames Group Object as per LDAP Requirements for Common Name
		modifications in Group Object types.
		"""
		# Set Common Name
		original_cn: str = safe_rdn(self.distinguished_name)[0]
		original_cn = original_cn.split("=")[-1]
		group_cn: str = self.attributes.get(LOCAL_ATTR_NAME, None)
		# If Group CN is present and has changed
		if group_cn and group_cn.lower() != original_cn.lower():
			# Validate CN Identifier
			if group_cn.lower().startswith("cn="):
				split_cn = group_cn.split("=")
				if len(split_cn) != 2:
					raise exc_ldap.DistinguishedNameValidationError
				group_cn = f"CN={split_cn[-1]}"
			# Rename Group
			context_request: Request = self.context.get("request", None)
			context_user = context_request.user if context_request else None
			self.distinguished_name = (
				OrganizationalUnitMixin.move_or_rename_object(
					self,
					distinguished_name=self.distinguished_name,
					target_rdn=group_cn,
					responsible_user=context_user,
				)
			)

	def perform_member_operations(
		self,
		members_to_add: list | set = None,
		members_to_remove: list | set = None,
	):
		# Set members to check
		members = getldapattrvalue(self.entry, LDAP_ATTR_GROUP_MEMBERS, [])

		# Clean-up DNs to add
		ignore_add = set()
		if members_to_add:
			members_to_add = set(members_to_add)
			for m in members_to_add:
				if m in members:
					ignore_add.add(m)
		for dn in ignore_add:
			members_to_add.remove(dn)

		# Clean-up DNs to remove
		ignore_rm = set()
		if members_to_remove:
			members_to_remove = set(members_to_remove)
			for m in members_to_remove:
				if m not in members:
					ignore_rm.add(m)
		for dn in ignore_rm:
			members_to_remove.remove(dn)

		# Execute operations
		try:
			self.connection.extend.microsoft.add_members_to_groups(
				members=members_to_add,
				groups=self.distinguished_name,
			)
			if not LOCAL_ATTR_GROUP_ADD_MEMBERS in self.parsed_specials:
				self.parsed_specials.append(LOCAL_ATTR_GROUP_ADD_MEMBERS)
		except Exception as e:
			logger.exception(e)
			raise exc_group.GroupMembersAdd(
				data={"ldap_response": self.connection.result}
			)

		try:
			self.connection.extend.microsoft.remove_members_from_groups(
				members=members_to_remove,
				groups=self.distinguished_name,
			)
			if not LOCAL_ATTR_GROUP_RM_MEMBERS in self.parsed_specials:
				self.parsed_specials.append(LOCAL_ATTR_GROUP_RM_MEMBERS)
		except Exception as e:
			logger.exception(e)
			raise exc_group.GroupMembersRemove(
				data={"ldap_response": self.connection.result}
			)

	def parse_write_special_attributes(self):
		self.parse_write_group_type_scope()

	def parse_read_special_attributes(self):
		for attr_key in ATTRS_SPECIAL_LDAP:
			if not attr_key in self.entry.entry_attributes:
				continue

			attr_value = getldapattrvalue(self.entry, attr_key)
			if (
				attr_key
				== RuntimeSettings.LDAP_FIELD_MAP[LOCAL_ATTR_GROUP_TYPE]
			):
				group_types, group_scopes = self.parse_read_group_type_scope(
					attr_value
				)
				self.attributes[LOCAL_ATTR_GROUP_TYPE] = group_types
				self.attributes[LOCAL_ATTR_GROUP_SCOPE] = group_scopes

	def post_create(self):
		self.perform_member_operations(
			members_to_add=self.attributes.get(
				LOCAL_ATTR_GROUP_ADD_MEMBERS, []
			),
			members_to_remove=self.attributes.get(
				LOCAL_ATTR_GROUP_RM_MEMBERS, []
			),
		)

	def post_update(self):
		self.post_create()
		self.parse_write_common_name()

	def save(self):
		has_members_to_modify = bool(
			self.attributes.get(LOCAL_ATTR_GROUP_ADD_MEMBERS, [])
			or self.attributes.get(LOCAL_ATTR_GROUP_RM_MEMBERS, [])
		)
		return super().save(
			update_kwargs={
				"force_post_update": has_members_to_modify,
			}
		)
