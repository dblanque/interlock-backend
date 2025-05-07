################################################################################
#################### INTERLOCK IS LICENSED UNDER GNU AGPLv3 ####################
################## ORIGINAL PROJECT CREATED BY DYLAN BLANQUÉ ###################
########################## AND BR CONSULTING S.R.L. ############################
################################################################################
# Module: core.models.ldap_object
# Contains the Models for generic LDAP Objects
#
# ---------------------------------- IMPORTS -----------------------------------#
### Django
from django.utils.translation import gettext_lazy as _

### Interlock
from core.exceptions import (
	users as exc_user,
	groups as exc_group,
	dirtree as exc_dirtree,
	ldap as exc_ldap,
)
from core.ldap.constants import *
from core.ldap.countries import LDAP_COUNTRIES
from core.config.runtime import RuntimeSettings
from core.ldap.adsi import (
	calc_permissions,
	LDAP_BUILTIN_OBJECTS,
	list_user_perms,
	LDAP_UF_ACCOUNT_DISABLE,
	LDAP_UF_NORMAL_ACCOUNT,
)
from core.ldap.security_identifier import SID

### Others
from core.type_hints.connector import LDAPConnectionProtocol
from core.ldap.filter import LDAPFilter
from ldap3 import (
	Entry as LDAPEntry,
	Attribute as LDAPAttribute,
	SUBTREE,
	ALL_OPERATIONAL_ATTRIBUTES,
	MODIFY_DELETE,
	MODIFY_REPLACE,
)
from ldap3.utils.dn import safe_rdn
from core.views.mixins.ldap.organizational_unit import OrganizationalUnitMixin
from typing import overload
from enum import Enum
from logging import getLogger
from core.views.mixins.utils import getldapattrvalue
from core.ldap.types.group import (
	LDAPGroupTypes,
	LDAP_GROUP_TYPE_MAPPING,
	LDAP_GROUP_SCOPE_MAPPING,
)
################################################################################
logger = getLogger()

# TODO
# Add save method to LDAPObject
# Add Immutable or always excluded keys tuple

class LDAPObjectTypes(Enum):
	GENERIC = 1
	USER = 2
	GROUP = 3
	ORGANIZATIONAL_UNIT = 4
	COMPUTER = 5
	PRINTER = 6

DEFAULT_REQUIRED_LDAP_ATTRS = {
	LDAP_ATTR_DN,
	LDAP_ATTR_OBJECT_CATEGORY,
	LDAP_ATTR_OBJECT_CLASS,
}
DEFAULT_CONTAINER_TYPES = {
	"container",
	"organizational-unit",
}
# Immutable Attributes
ATTRS_IMMUTABLE = {
	LOCAL_ATTR_BAD_PWD_COUNT,
	LOCAL_ATTR_RELATIVE_ID,
	LOCAL_ATTR_SECURITY_ID,
	LOCAL_ATTR_GUID,
	LOCAL_ATTR_ACCOUNT_TYPE,
	LOCAL_ATTR_GROUP_MEMBERS,
	LOCAL_ATTR_USER_GROUPS,
	LOCAL_ATTR_CREATED,
	LOCAL_ATTR_MODIFIED,
	LOCAL_ATTR_UPN,
	LOCAL_ATTR_LAST_LOGIN,
	LOCAL_ATTR_PERMISSIONS,
	LOCAL_ATTR_USER_ADD_GROUPS,
	LOCAL_ATTR_USER_RM_GROUPS,
	LOCAL_ATTR_IS_ENABLED,
	LOCAL_ATTR_PASSWORD, # This is modified with a specific method
	LOCAL_ATTR_GROUP_ADD_MEMBERS,
	LOCAL_ATTR_GROUP_RM_MEMBERS,
	LOCAL_ATTR_GROUP_HAS_MEMBERS,
	LOCAL_ATTR_GROUP_MEMBERS,
	LOCAL_ATTR_NAME,
}
# Special Attributes
ATTRS_SPECIAL = {
	LOCAL_ATTR_UAC,
	LOCAL_ATTR_COUNTRY,
	LOCAL_ATTR_COUNTRY_ISO,
	LOCAL_ATTR_COUNTRY_ISO,
	LOCAL_ATTR_NAME,
	LOCAL_ATTR_GROUP_TYPE,
	LOCAL_ATTR_OBJECT_CATEGORY,
}

class LDAPObject:
	"""Fetches LDAP Object from a specified DN"""
	# Django
	use_in_migrations: bool = False

	# Type Hints
	type = None
	distinguished_name: str
	attributes: dict = None
	connection: LDAPConnectionProtocol = None
	entry: LDAPEntry = None
	excluded_attributes: list[str] = None
	required_attributes: list[str] = None
	search_attrs: list[str] | str = ALL_OPERATIONAL_ATTRIBUTES
	search_filter: str = None
	search_base: str = None
	parsed_specials: list[str] = None
	int_fields = (
		LOCAL_ATTR_COUNTRY_DCC,
		LOCAL_ATTR_UAC,
		LOCAL_ATTR_LAST_LOGIN,
		LOCAL_ATTR_BAD_PWD_COUNT,
		LOCAL_ATTR_PWD_SET_AT,
		LOCAL_ATTR_PRIMARY_GROUP_ID,
		LOCAL_ATTR_RELATIVE_ID,
		LOCAL_ATTR_ACCOUNT_TYPE,
	)

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
		skip_fetch: bool = False,
	) -> None:
		...

	def __init__(self, **kwargs) -> None:
		skip_fetch = kwargs.pop("skip_fetch", False)
		self.entry = kwargs.pop("entry", None)
		self.connection = kwargs.pop("connection", None)
		self.distinguished_name = kwargs.pop(LOCAL_ATTR_DN, None)
		self.__validate_kwargs__(kwargs=kwargs)

		self.search_base = RuntimeSettings.LDAP_AUTH_SEARCH_BASE
		self.parsed_specials = []
		self.attributes = {}
		self.excluded_attributes = []
		self.required_attributes = DEFAULT_REQUIRED_LDAP_ATTRS
		self.__set_kwargs__(kwargs)

		if not self.entry and not skip_fetch:
			self.__fetch_object__()
			self.__sync_object__()
		elif self.entry and not self.attributes:
			self.__sync_object__()

	def __validate_kwargs__(self):
		if self.entry and not isinstance(self.entry, LDAPEntry):
			raise TypeError("LDAPObject entry must attr must be of type ldap3.Entry")

		if not self.connection and not self.entry:
			raise Exception(
				"LDAPObject requires an LDAP Connection or an Entry to Initialize"
			)
		elif self.connection and not self.distinguished_name:
			raise Exception(
				"LDAPObject requires a Distinguished Name to search for the object"
			)
		
		if self.entry:
			_entry_dn = getattr(self.entry, "entry_dn", "")
			if _entry_dn:
				if not isinstance(_entry_dn, str):
					raise TypeError("entry_dn must be of type str")
				self.search_filter = LDAPFilter.eq(LDAP_ATTR_DN, _entry_dn).to_string()
		elif self.distinguished_name and isinstance(self.distinguished_name, str):
			self.search_filter = LDAPFilter.eq(LDAP_ATTR_DN, self.distinguished_name).to_string()

	def __set_kwargs__(self, kwargs):
		# Set passed kwargs from Object Call
		for kw in kwargs:
			setattr(self, kw, kwargs[kw])

		# Remove excluded attributes
		for attr in self.excluded_attributes:
			if attr in self.search_attrs:
				self.search_attrs.remove(attr)

		# Set required attributes, these are unremovable from the tree searches
		for attr in self.required_attributes:
			if attr not in self.search_attrs:
				self.search_attrs.append(attr)
		
		# Add primary_group_id fetching if groups are fetched,
		# as the primary group is not included in memberOf
		if LDAP_ATTR_USER_GROUPS in self.search_attrs:
			if not LDAP_ATTR_PRIMARY_GROUP_ID in self.search_attrs:
				self.search_attrs.append(LDAP_ATTR_PRIMARY_GROUP_ID)

	def __get_connection__(self):
		return self.connection

	def __get_entry__(self) -> LDAPEntry:
		return self.entry

	def __get_object__(self):
		return self.attributes

	@overload
	def get_local_alias_for_ldap_key(self, v: str, default: str = None): ...

	def get_local_alias_for_ldap_key(self, v: str, **kwargs):
		for local_alias, ldap_alias in LOCAL_ATTRS_MAP.items():
			if ldap_alias == v:
				return local_alias
		if "default" in kwargs:
			return kwargs.pop("default")
		raise ValueError(f"No alias for ldap key ({v})")

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

	def __sync_object__(self):
		if not self.entry:
			return

		# Set DN from Abstract Entry object (LDAP3)
		# Set searchResult attributes
		if self.entry:
			distinguished_name: str = self.entry.entry_dn
		else:
			distinguished_name: str = self.distinguished_name
		self.attributes = {}
		self.attributes[LOCAL_ATTR_NAME] = distinguished_name.split(",")[0].split("=")[1]
		self.attributes[LOCAL_ATTR_DN] = distinguished_name
		self.attributes[LOCAL_ATTR_TYPE] = LDAPObjectTypes.GENERIC.name if not self.type else self.type
		if LDAP_ATTR_OBJECT_CATEGORY in self.entry.entry_attributes:
			self.attributes[LOCAL_ATTR_OBJECT_CATEGORY] = (
				getldapattrvalue(self.entry, LDAP_ATTR_OBJECT_CATEGORY)
				.split(",")[0]
				.split("=")[1]
			)
		entry_object_classes: LDAPAttribute = getldapattrvalue(
			self.entry, LDAP_ATTR_OBJECT_CLASS, []
		)
		if (
			self.attributes[LOCAL_ATTR_NAME] in LDAP_BUILTIN_OBJECTS
			or "builtinDomain" in entry_object_classes
		):
			self.attributes[LOCAL_ATTR_BUILT_IN] = True

		for attr_key in self.entry.entry_attributes:
			attr_value = getldapattrvalue(self.entry, attr_key)
			local_key = self.get_local_alias_for_ldap_key(attr_key)

			if (
				attr_key == LDAP_ATTR_SECURITY_ID
				and self.__get_common_name__(distinguished_name).lower()
				!= LOCAL_ATTR_BUILT_IN
			):
				try:
					# Do not use getldapattr here, we want raw_values
					sid = SID(getattr(self.entry, attr_key))
					sid = sid.__str__()
					rid = int(sid.split("-")[-1])
					self.attributes[LOCAL_ATTR_SECURITY_ID] = sid
					self.attributes[LOCAL_ATTR_RELATIVE_ID] = rid
				except Exception as e:
					logger.error(
						"Could not translate SID Byte Array for "
						+ distinguished_name
					)
					logger.exception(e)
			elif attr_key == LDAP_ATTR_GROUP_TYPE:
				group_types, group_scopes = self.get_group_types(attr_value)
				self.attributes[LOCAL_ATTR_GROUP_TYPE] = group_types
				self.attributes[LOCAL_ATTR_GROUP_SCOPE] = group_scopes
			elif attr_value:
				self.attributes[local_key] = attr_value

		for fld in self.int_fields:
			if not fld in self.attributes:
				continue
			try:
				_v = int(self.attributes[fld])
				if fld == LOCAL_ATTR_COUNTRY_DCC and _v == 0:
					self.attributes.pop(fld, None)
					continue
				self.attributes[fld] = _v
			except:
				logger.error(
					f"Could not cast LDAP Object field to int ({fld})."
				)
				pass
		return

	def __fetch_object__(self):
		self.connection.search(
			search_base=self.search_base,
			search_filter=self.search_filter,
			search_scope=SUBTREE,
			attributes=self.search_attrs,
		)
		search_result = self.connection.entries
		if not search_result:
			self.entry = None
			return
		if len(search_result) > 1:
			logger.warning(
				"Search result for LDAP Object has more than one entries."
			)
			logger.warning("Search filter used: %s", self.search_filter)
		try:
			self.entry = search_result[0]
			self.distinguished_name = self.entry.entry_dn
		except Exception as e:
			raise ValueError("Error setting LDAP Object Entry Result") from e

	def __ldap_attrs__(self):
		if not self.attributes:
			return []
		return list(self.attributes.keys())

	def __get_common_name__(self, dn: str):
		return str(dn).split(",")[0].split("=")[-1]

	@property
	def exists(self) -> bool:
		self.__fetch_object__()
		return bool(self.connection.entries)

	def value_has_changed(self, local_alias: str, ldap_alias: str, /) -> bool:
		"""Checks if a local value differs from its entry counterpart
		
		Positional args only.
		"""
		if not local_alias:
			raise ValueError("local_alias cannot be falsy")
		if not ldap_alias:
			raise ValueError("ldap_alias cannot be falsy")
		if not isinstance(local_alias, str):
			raise TypeError("local_alias must be of type str")
		if not isinstance(ldap_alias, str):
			raise TypeError("ldap_alias must be of type str")

		entry_value = getldapattrvalue(self.entry, ldap_alias, None)
		local_value = self.attributes.get(local_alias, None)

		if entry_value is None and local_value is None:
			return False
		if local_alias in self.int_fields:
			entry_value = int(entry_value)
			local_value = int(local_value)
		elif isinstance(entry_value, list) or isinstance(local_value, list):
			# Have to contrast with single value sets, edge-case.
			if isinstance(entry_value, str):
				entry_value = {entry_value}
			else:
				entry_value = set(entry_value)
			if isinstance(local_value, str):
				local_value = {local_value}
			else:
				local_value = set(local_value)
		has_changed = entry_value != local_value
		return has_changed

	def parse_special_attributes(self):
		return

	def create(self):
		if self.entry:
			raise Exception("There is already an existing LDAP Entry.")
		attrs = {}
		self.attributes[LOCAL_ATTR_OBJECT_CLASS] = list({
			RuntimeSettings.LDAP_AUTH_OBJECT_CLASS,
			"top",
			"person",
			"organizationalPerson",
			"user",
		})

		self.parse_special_attributes()
		for local_alias, local_value in self.attributes.items():
			# Ignore if immutable or special
			if local_alias in ATTRS_IMMUTABLE:
				continue
			elif (
				local_alias in ATTRS_SPECIAL and
				not local_alias in self.parsed_specials
			):
				continue

			ldap_alias = LOCAL_ATTRS_MAP[local_alias]
			if local_value:
				attrs[ldap_alias] = local_value

		self.connection.add(
			dn=self.distinguished_name,
			object_class=RuntimeSettings.LDAP_AUTH_OBJECT_CLASS,
			attributes=attrs,
		)
		return getattr(
			self.connection.result,
			"description",
			""
		).lower() == "success"

	def update(self) -> bool:
		if not self.entry:
			raise ValueError("An existing LDAP Entry is required to perform an update")
		if not self.attributes:
			raise ValueError("New attributes must be set to perform an update")
		if not isinstance(self.entry, LDAPEntry):
			raise TypeError("self.entry must be of type ldap3.Entry")

		self.parse_special_attributes()
		replace_attrs = {}
		delete_attrs = {}
		for local_alias, local_value in self.attributes.items():
			# Ignore if immutable or special
			if local_alias in ATTRS_IMMUTABLE:
				continue
			elif (
				local_alias in ATTRS_SPECIAL and
				not local_alias in self.parsed_specials
			):
				continue

			# Ignore if local and remote values explicitly None
			ldap_alias = LOCAL_ATTRS_MAP[local_alias]
			if not self.value_has_changed(local_alias, ldap_alias):
				continue

			# If local value empty
			if not local_value and not local_value is False:
				delete_attrs[ldap_alias] = [(MODIFY_DELETE, [])]
			else:
				replace_attrs[ldap_alias] = [(MODIFY_REPLACE, local_value)]

		attrs = replace_attrs | delete_attrs
		if attrs:
			self.connection.modify(
				dn=self.entry.entry_dn,
				changes=attrs
			)
			return getattr(
				self.connection.result,
				"description",
				""
			).lower() == "success"
		return True

	def delete(self) -> bool:
		if self.entry:
			self.connection.delete(dn=self.entry.entry_dn)
		elif self.distinguished_name:
			self.connection.delete(dn=self.distinguished_name)
		else:
			raise Exception("Deletion requires a valid dn or entry.")

	def save(self):
		if not self.connection or not self.connection.bound:
			raise Exception(
				"LDAPObject requires a bound connection to save modifications")

		if not self.entry:
			self.create()
		else:
			self.update()

class LDAPUser(LDAPObject):
	type = LDAPObjectTypes.USER.name
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

	def __validate_kwargs__(self, kwargs: dict):
		kw_samaccountname = kwargs.pop(LDAP_ATTR_USERNAME_SAMBA_ADDS, None)
		self.username = kwargs.pop(LOCAL_ATTR_USERNAME, kw_samaccountname)

		# Type check Entry
		if self.entry and not isinstance(self.entry, LDAPEntry):
			raise TypeError("LDAPUser entry must attr must be of type ldap3.Entry")

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
			_entry_dn = getattr(self.entry, "entry_dn", "")
			if _entry_dn:
				if not isinstance(_entry_dn, str):
					raise TypeError("entry_dn must be of type str")
				self.search_filter = LDAPFilter.eq(
					LDAP_ATTR_DN,
					_entry_dn
				).to_string()
		elif self.distinguished_name and isinstance(self.distinguished_name, str):
			self.search_filter = LDAPFilter.eq(
				LDAP_ATTR_DN,
				self.distinguished_name
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
					*[LDAPFilter.eq(LDAP_ATTR_OBJECT_CLASS, auth_class)
	   				for auth_class in _USER_CLASSES]
				),
				LDAPFilter.eq(
					LDAP_ATTR_USERNAME_SAMBA_ADDS,
					self.username
				)
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
	) -> None:
		...

	def __init__(self, **kwargs):
		super().__init__(**kwargs)

	def parse_special_attributes(self):
		self.parse_country(self.attributes.get(LOCAL_ATTR_COUNTRY, None))
		self.parse_permissions(
			self.attributes.get(LOCAL_ATTR_PERMISSIONS, None)
		)
		self.parse_group_operations(
			groups_to_add=self.attributes.get(LOCAL_ATTR_USER_ADD_GROUPS, []),
			groups_to_remove=self.attributes.get(LOCAL_ATTR_USER_RM_GROUPS, []),
		)

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
			self.attributes[LOCAL_ATTR_COUNTRY_DCC] = LDAP_COUNTRIES[value]["dccCode"]
			self.attributes[LOCAL_ATTR_COUNTRY_ISO] = LDAP_COUNTRIES[value]["isoCode"]

		for attr in _COUNTRY_ATTRS:
			if not attr in self.parsed_specials:
				self.parsed_specials.append(attr)

	def parse_permissions(self, value: list[str]):
		if value is None:
			return
		if value and isinstance(value, list):
			self.attributes[LOCAL_ATTR_UAC] = calc_permissions(permission_list=value)
		else:
			self.attributes[LOCAL_ATTR_UAC] = calc_permissions([LDAP_UF_NORMAL_ACCOUNT])
		if not LOCAL_ATTR_UAC in self.parsed_specials:
			self.parsed_specials.append(LOCAL_ATTR_UAC)

	def parse_group_operations(self, groups_to_add = None, groups_to_remove = None):
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
			raise ValueError("%s attribute is required in entry search" \
				% (LDAP_ATTR_UAC))

		return not list_user_perms(
			user=self.entry,
			perm_search=LDAP_UF_ACCOUNT_DISABLE,
		)

class LDAPGroup(LDAPObject):
	type = LDAPObjectTypes.GROUP.name
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

	def parse_group_type_and_scope(self):
		self.attributes[LOCAL_ATTR_GROUP_TYPE] = (
			LDAP_GROUP_TYPE_MAPPING[self.attributes.get(LOCAL_ATTR_GROUP_TYPE)]
			+ LDAP_GROUP_SCOPE_MAPPING[self.attributes.get(LOCAL_ATTR_GROUP_SCOPE)]
		)
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
				members_to_add, self.distinguished_name
			)
			if not LOCAL_ATTR_GROUP_ADD_MEMBERS in self.parsed_specials:
				self.parsed_specials.append(LOCAL_ATTR_GROUP_ADD_MEMBERS)
		except Exception as e:
			logger.exception(e)
			raise exc_group.GroupMembersAdd(
				data={"ldap_response": self.connection.result})

		try:
			self.connection.extend.microsoft.remove_members_from_groups(
				members_to_remove, self.distinguished_name
			)
			if not LOCAL_ATTR_GROUP_RM_MEMBERS in self.parsed_specials:
				self.parsed_specials.append(LOCAL_ATTR_GROUP_RM_MEMBERS)
		except Exception as e:
			logger.exception(e)
			raise exc_group.GroupMembersRemove(
				data={"ldap_response": self.connection.result})

	def parse_special_attributes(self):
		self.parse_group_type_and_scope()
		self.parse_group_operations(
			members_to_add=self.attributes.get(LOCAL_ATTR_GROUP_ADD_MEMBERS, []),
			members_to_remove=self.attributes.get(LOCAL_ATTR_GROUP_RM_MEMBERS, []),
		)

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
