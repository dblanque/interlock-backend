################################################################################
#################### INTERLOCK IS LICENSED UNDER GNU AGPLv3 ####################
################## ORIGINAL PROJECT CREATED BY DYLAN BLANQUÉ ###################
########################## AND BR CONSULTING S.R.L. ############################
################################################################################
# Module: core.models.ldap_group
# Contains the Models for generic LDAP Objects
#
# ---------------------------------- IMPORTS -----------------------------------#
### Django
from django.utils.translation import gettext_lazy as _

### Interlock
from core.exceptions import (
	groups as exc_group,
	dirtree as exc_dirtree,
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
from core.views.mixins.utils import getldapattrvalue
from core.models.ldap_object import (
	LDAPObject,
	LDAPObjectTypes,
	ATTRS_SPECIAL_LDAP,
)
from core.ldap.types.group import LDAPGroupTypes

################################################################################
logger = getLogger()


class LDAPGroup(LDAPObject):
	type = LDAPObjectTypes.GROUP
	search_attrs = (
		LDAP_ATTR_DN,
		LDAP_ATTR_COMMON_NAME,
		LDAP_ATTR_GROUP_MEMBERS,
		LDAP_ATTR_GROUP_TYPE,
		LDAP_ATTR_SECURITY_ID,
		LDAP_ATTR_EMAIL,
		LDAP_ATTR_OBJECT_CLASS,
		LDAP_ATTR_OBJECT_CATEGORY,
		LDAP_ATTR_CREATED,
		LDAP_ATTR_MODIFIED,
	)

	@overload
	def __init__(
		self,
		entry: LDAPEntry = None,
		connection: LDAPConnectionProtocol = None,
		distinguished_name: str = None,
		groupname: str = None,
		search_base: str = None,
		excluded_attributes: list[str] = None,
		required_attributes: list[str] = None,
		attributes: dict = None,
	) -> None: ...

	def __init__(self, **kwargs):
		super().__init__(**kwargs)

	def parse_read_group_type_scope(self, group_type: int = None) -> tuple[list[str], list[str]]:
		"""Get group types and scopes from integer value"""
		sum = 0
		_scopes = []
		_types = []
		if not isinstance(group_type, (int, str)) or group_type is False:
			raise TypeError("group_type must be of type int.")

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
			raise ValueError("Invalid group type integer")

		return _types, _scopes

	def parse_write_group_type_scope(self) -> int:
		"""Convert front-end generated type and scope to LDAP acceptable int."""
		group_types = self.attributes.get(LOCAL_ATTR_GROUP_TYPE, [])
		group_scopes = self.attributes.get(LOCAL_ATTR_GROUP_SCOPE, [])
		if not group_types or not group_scopes:
			return

		_type = 0
		for t in set(self.attributes[LOCAL_ATTR_GROUP_TYPE]):
			t: str
			if t.lower() == LDAPGroupTypes.TYPE_SECURITY.name.lower():
				_type -= LDAPGroupTypes[t].value
			else:
				_type += LDAPGroupTypes[t].value

		_scope = 0
		_scope += LDAPGroupTypes[
			self.attributes[LOCAL_ATTR_GROUP_SCOPE][0]
		].value
		_sum = _type + _scope

		# Validate
		_parsed_types, _parsed_scopes = self.parse_read_group_type_scope(_sum)
		if set(_parsed_types) != set(self.attributes[LOCAL_ATTR_GROUP_TYPE]):
			raise ValueError("Could not properly parse group type")
		if set(_parsed_scopes) != set(self.attributes[LOCAL_ATTR_GROUP_SCOPE]):
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
		if group_cn.lower() != original_cn.lower():
			# Validate CN Identifier
			if group_cn.lower().startswith("cn="):
				split_cn = group_cn.split("=")
				if len(split_cn) != 2:
					raise exc_ldap.DistinguishedNameValidationError
				group_cn = f"CN={split_cn[-1]}"
			# Rename Group
			self.distinguished_name = (
				OrganizationalUnitMixin.move_or_rename_object(
					self,
					distinguished_name=self.distinguished_name,
					target_rdn=group_cn,
				)
			)

	def perform_member_operations(
		self, members_to_add=None, members_to_remove=None
	):
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
			if attr_key == LDAP_ATTR_GROUP_TYPE:
				group_types, group_scopes = self.parse_read_group_type_scope(attr_value)
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

	def __validate_init__(self, **kwargs):
		kw_common_name = kwargs.pop("common_name", None)
		self.groupname = kwargs.pop(LDAP_ATTR_COMMON_NAME, kw_common_name)

		if self.entry and not isinstance(self.entry, LDAPEntry):
			raise TypeError(
				f"LDAPGroup entry must attr must be of type ldap3.Entry"
			)

		if not self.connection and not self.entry:
			raise Exception(
				f"LDAPGroup requires an LDAP Connection or an Entry to Initialize"
			)
		elif self.connection:
			if not self.distinguished_name and not self.groupname:
				raise Exception(
					f"LDAPGroup requires a distinguished_name or groupname to search for the object"
				)

		if self.entry:
			self.__set_dn_and_filter_from_entry__()
		elif self.distinguished_name and isinstance(
			self.distinguished_name, str
		):
			self.search_filter = LDAPFilter.eq(
				LDAP_ATTR_DN, self.distinguished_name
			).to_string()
		elif self.groupname and isinstance(self.groupname, str):
			self.search_filter = LDAPFilter.and_(
				LDAPFilter.eq(LDAP_ATTR_OBJECT_CLASS, "group"),
				LDAPFilter.eq(LDAP_ATTR_COMMON_NAME, self.groupname),
			).to_string()
