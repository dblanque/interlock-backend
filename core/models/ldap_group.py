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
	) -> None:
		...

	def __init__(self, **kwargs):
		super().__init__(**kwargs)

	def get_group_types(self, group_type: int = None) -> list[str]:
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

	def parse_group_type_and_scope(self):
		_type = 0
		for t in set(self.attributes[LOCAL_ATTR_GROUP_TYPE]):
			t: str
			if t.lower() == LDAPGroupTypes.TYPE_SECURITY.name.lower():
				_type -= LDAPGroupTypes[t].value
			else:
				_type += LDAPGroupTypes[t].value

		_scope = 0
		_scope += LDAPGroupTypes[self.attributes[LOCAL_ATTR_GROUP_SCOPE][0]].value
		_sum = _type + _scope

		# Validate
		_parsed_types, _parsed_scopes = self.get_group_types(_sum)
		if set(_parsed_types) != set(self.attributes[LOCAL_ATTR_GROUP_TYPE]):
			raise ValueError("Could not properly parse group type")
		if set(_parsed_scopes) != set(self.attributes[LOCAL_ATTR_GROUP_SCOPE]):
			raise ValueError("Could not properly parse group type")

		self.attributes[LOCAL_ATTR_GROUP_TYPE] = _sum

		if not LOCAL_ATTR_GROUP_TYPE in self.parsed_specials:
			self.parsed_specials.append(LOCAL_ATTR_GROUP_TYPE)

	def parse_common_name(self):
		# Set Common Name
		original_cn = safe_rdn(self.distinguished_name)[0]
		group_cn: str = self.attributes.get(LOCAL_ATTR_NAME, None)
		if not group_cn:
			group_cn = original_cn
		# If Group CN is present and has changed
		elif group_cn != original_cn:
			# Validate CN Identifier
			if group_cn.lower().startswith("cn="):
				split_cn = group_cn.split("=")
				if len(split_cn) != 2:
					raise exc_ldap.DistinguishedNameValidationError
				group_cn = f"CN={split_cn[-1]}"
			# Rename Group
			try:
				distinguished_name = (
					OrganizationalUnitMixin.move_or_rename_object(
						self,
						distinguished_name=distinguished_name,
						target_rdn=group_cn,
					)
				)
			except:
				raise exc_dirtree.DirtreeRename

		# Set group sAMAccountName to new CN, lower-cased
		self.attributes[LDAP_ATTR_USERNAME_SAMBA_ADDS] = str(group_cn).lower()
		if not LOCAL_ATTR_NAME in self.parsed_specials:
			self.parsed_specials.append(LOCAL_ATTR_NAME)

	def parse_group_operations(
		self,
		members_to_add=None,
		members_to_remove=None
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
				data={"ldap_response": self.connection.result})

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
				data={"ldap_response": self.connection.result})

	def parse_special_attributes(self):
		self.parse_group_type_and_scope()

	def parse_special_ldap_attributes(self):
		for attr_key in ATTRS_SPECIAL_LDAP:
			if not attr_key in self.entry.entry_attributes:
				continue

			attr_value = getldapattrvalue(self.entry, attr_key)
			if attr_key == LDAP_ATTR_GROUP_TYPE:
				group_types, group_scopes = self.get_group_types(attr_value)
				self.attributes[LOCAL_ATTR_GROUP_TYPE] = group_types
				self.attributes[LOCAL_ATTR_GROUP_SCOPE] = group_scopes

	def post_create(self):
		self.parse_group_operations(
			members_to_add=self.attributes.get(
				LOCAL_ATTR_GROUP_ADD_MEMBERS, []),
			members_to_remove=self.attributes.get(
				LOCAL_ATTR_GROUP_RM_MEMBERS, []),
		)

	def post_update(self):
		self.post_create()

	def __validate_kwargs__(self, kwargs: dict):
		kw_common_name = kwargs.pop("common_name", None)
		self.groupname = kwargs.pop(LDAP_ATTR_COMMON_NAME, kw_common_name)

		if self.entry and not isinstance(self.entry, LDAPEntry):
			raise TypeError(f"LDAPGroup entry must attr must be of type ldap3.Entry")

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
			_entry_dn = getattr(self.entry, "entry_dn", "")
			if _entry_dn:
				if not isinstance(_entry_dn, str):
					raise TypeError("entry_dn must be of type str")
				self.search_filter = LDAPFilter.eq(LDAP_ATTR_DN, _entry_dn).to_string()
		elif self.distinguished_name and isinstance(self.distinguished_name, str):
			self.search_filter = LDAPFilter.eq(LDAP_ATTR_DN, self.distinguished_name).to_string()
		elif self.groupname and isinstance(self.groupname, str):
			self.search_filter = LDAPFilter.and_(
				LDAPFilter.eq(LDAP_ATTR_OBJECT_CLASS, "group"),
				LDAPFilter.eq(LDAP_ATTR_COMMON_NAME, self.groupname)
			).to_string()
