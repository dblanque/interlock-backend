################################################################################
#################### INTERLOCK IS LICENSED UNDER GNU AGPLv3 ####################
################## ORIGINAL PROJECT CREATED BY DYLAN BLANQUÉ ###################
########################## AND BR CONSULTING S.R.L. ############################
################################################################################
# Module: core.models.ldap_object
# Contains the Models for generic LDAP Objects
#
# ---------------------------------- IMPORTS ----------------------------------#
### Interlock
from core.constants.attrs import *
from core.config.runtime import RuntimeSettings
from core.ldap.adsi import LDAP_BUILTIN_OBJECTS
from core.ldap.security_identifier import SID
from core.utils.main import getlocalkeyforldapattr

### Others
from core.type_hints.connector import LDAPConnectionProtocol
from core.ldap.filter import LDAPFilter
from ldap3 import (
	Entry as LDAPEntry,
	Attribute as LDAPAttribute,
	SUBTREE,
	ALL_OPERATIONAL_ATTRIBUTES,
	ALL_ATTRIBUTES,
	MODIFY_DELETE,
	MODIFY_REPLACE,
)
from ldap3.utils.dn import safe_rdn
from typing import overload
from enum import Enum
from logging import getLogger
from core.utils.main import getldapattrvalue

################################################################################
logger = getLogger()


class LDAPObjectTypes(Enum):
	GENERIC = "generic"
	CONTAINER = "container"
	USER = "user"
	PERSON = "person"
	GROUP = "group"
	ORGANIZATIONAL_UNIT = "organizational-unit"
	COMPUTER = "computer"
	PRINTER = "printer"
	CONTACT = "contact"
	BUILTIN = "builtin-domain"


DEFAULT_REQUIRED_LDAP_ATTRS = {
	LDAP_ATTR_DN,
	LDAP_ATTR_OBJECT_CATEGORY,
	LDAP_ATTR_OBJECT_CLASS,
}
DEFAULT_CONTAINER_TYPES = {
	LDAPObjectTypes.CONTAINER.value,
	LDAPObjectTypes.ORGANIZATIONAL_UNIT.value,
}

# Immutable Attributes, these are read only
ATTRS_IMMUTABLE = {
	LOCAL_ATTR_DN,
	LOCAL_ATTR_TYPE,
	LOCAL_ATTR_PATH,
	LOCAL_ATTR_BAD_PWD_COUNT,
	LOCAL_ATTR_RELATIVE_ID,
	LOCAL_ATTR_SECURITY_ID,
	LOCAL_ATTR_GUID,
	LOCAL_ATTR_ACCOUNT_TYPE,
	LOCAL_ATTR_GROUP_MEMBERS,
	LOCAL_ATTR_CREATED,
	LOCAL_ATTR_MODIFIED,
	LOCAL_ATTR_UPN,
	LOCAL_ATTR_LAST_LOGIN_WIN32,
	LOCAL_ATTR_PERMISSIONS,
	LOCAL_ATTR_USER_GROUPS,
	LOCAL_ATTR_USER_ADD_GROUPS,
	LOCAL_ATTR_USER_RM_GROUPS,
	LOCAL_ATTR_IS_ENABLED,
	LOCAL_ATTR_PASSWORD,  # This is modified with a specific method
	LOCAL_ATTR_GROUP_ADD_MEMBERS,
	LOCAL_ATTR_GROUP_RM_MEMBERS,
	LOCAL_ATTR_GROUP_HAS_MEMBERS,
	LOCAL_ATTR_GROUP_MEMBERS,
	LOCAL_ATTR_NAME,
}
ATTRS_DELETE_PROTECTED = {
	LOCAL_ATTR_COUNTRY_DCC,
}

# Special Attributes, these will not be processed unless specified
ATTRS_SPECIAL = {
	LOCAL_ATTR_PASSWORD,
	LOCAL_ATTR_UAC,
	LOCAL_ATTR_COUNTRY,
	LOCAL_ATTR_COUNTRY_ISO,
	LOCAL_ATTR_COUNTRY_DCC,
	LOCAL_ATTR_NAME,
	LOCAL_ATTR_GROUP_TYPE,
	LOCAL_ATTR_GROUP_SCOPE,
	LOCAL_ATTR_OBJECT_CATEGORY,
	LOCAL_ATTR_USER_GROUPS,
}

ATTRS_SPECIAL_LDAP = {
	LDAP_ATTR_GROUP_TYPE,
}


class LDAPObject:
	"""Fetches LDAP Object from a specified DN"""

	# Django
	use_in_migrations: bool = False

	# Type Hints
	context: dict = None
	type = LDAPObjectTypes.GENERIC
	fetched: bool = False
	distinguished_name: str = None
	attributes: dict = None
	connection: LDAPConnectionProtocol = None
	entry: LDAPEntry = None
	excluded_ldap_attributes: list[str] = None
	search_attrs: list[str] | str = ALL_OPERATIONAL_ATTRIBUTES
	default_attrs = None
	search_filter: str = None
	search_base: str = None
	parsed_specials: list[str] = None
	int_fields = (
		LOCAL_ATTR_COUNTRY_DCC,
		LOCAL_ATTR_UAC,
		LOCAL_ATTR_LAST_LOGIN_WIN32,
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
		search_base: str = None,
		search_attrs: list[str] = None,
		excluded_ldap_attributes: list[str] = None,
		attributes: dict = None,
		skip_fetch: bool = False,
		context: dict = None,
	) -> None: ...

	def __init__(self, **kwargs) -> None:
		skip_fetch = kwargs.pop("skip_fetch", False)
		self.entry = kwargs.pop("entry", None)
		self.connection = kwargs.pop("connection", None)
		self.distinguished_name = kwargs.pop(LOCAL_ATTR_DN, None)
		self.__validate_init__(**kwargs)

		self.search_base = RuntimeSettings.LDAP_AUTH_SEARCH_BASE
		self.parsed_specials = []
		self.attributes = {}
		self.excluded_ldap_attributes = []
		self.__set_kwargs__(**kwargs)

		if not self.entry and not skip_fetch:
			self.__fetch_object__()
			self.__sync_object__()
		elif self.entry and not self.attributes:
			self.__sync_object__()

	def __set_dn_and_filter_from_entry__(self):
		_entry_dn = getattr(self.entry, "entry_dn", "")
		if not isinstance(_entry_dn, str):
			raise TypeError("entry_dn must be of type str")
		self.distinguished_name = _entry_dn
		self.search_filter = LDAPFilter.eq(LDAP_ATTR_DN, _entry_dn).to_string()

	def __validate_init__(self, **kwargs):
		"""Function that may be overridden by subclasses for connection and
		detail validation.
		"""
		if self.entry is not None:
			if not isinstance(self.entry, LDAPEntry):
				raise TypeError("LDAPObject entry must be of type ldap3.Entry")

		if not self.connection and not self.entry:
			raise Exception(
				"LDAPObject requires an LDAP Connection or Entry to Initialize"
			)
		elif self.connection and not self.distinguished_name:
			raise Exception(
				"LDAPObject requires a Distinguished Name to search for the object"
			)

		if self.entry:
			self.__set_dn_and_filter_from_entry__()
		elif self.distinguished_name and isinstance(
			self.distinguished_name, str
		):
			self.search_filter = LDAPFilter.eq(
				LDAP_ATTR_DN, self.distinguished_name
			).to_string()

	def __set_search_attrs__(self, search_attrs: list | tuple | set):
		if not search_attrs:
			return
		elif search_attrs in (
			ALL_OPERATIONAL_ATTRIBUTES,
			ALL_ATTRIBUTES,
		):
			self.search_attrs = search_attrs
			return

		if not isinstance(search_attrs, (set, tuple, list, str)):
			raise TypeError(
				"search_attrs must be of type set, tuple, list, or str"
			)

		# Convert to list if iterable
		if isinstance(
			search_attrs,
			(
				set,
				tuple,
			),
		):
			self.search_attrs = list(search_attrs)
		else:
			self.search_attrs = search_attrs

		# Remove excluded attributes
		for attr in self.excluded_ldap_attributes:
			if attr in self.search_attrs:
				self.search_attrs.remove(attr)

		# Add primary_group_id fetching if groups are fetched,
		# as the primary group is not included in memberOf
		if LDAP_ATTR_USER_GROUPS in self.search_attrs:
			if not LDAP_ATTR_PRIMARY_GROUP_ID in self.search_attrs:
				self.search_attrs.append(LDAP_ATTR_PRIMARY_GROUP_ID)

		if isinstance(self.search_attrs, list):
			self.search_attrs = tuple(self.search_attrs)

	def __set_kwargs__(self, **kwargs):
		"""Function to set kwargs after defaults have been set."""
		# Set passed kwargs from Object Call
		for kw in kwargs:
			setattr(self, kw, kwargs[kw])

		self.context = kwargs.pop("context", None)
		if self.context is None:
			self.context = {}

		self.__set_search_attrs__(
			kwargs.pop(
				"search_attrs",
				ALL_OPERATIONAL_ATTRIBUTES
				if not self.default_attrs
				else self.default_attrs,
			)
		)

	def __get_connection__(self):
		return self.connection

	def __get_entry__(self) -> LDAPEntry:
		return self.entry

	def __get_object__(self):
		return self.attributes

	def __sync_int_fields__(self):
		for fld in self.int_fields:
			if not fld in self.attributes:
				continue
			try:
				_v = int(self.attributes[fld])
				self.attributes[fld] = _v
			except:
				logger.error(
					f"Could not cast LDAP Object field to int ({fld})."
				)
				pass

	def parse_read_special_attributes(self):  # pragma: no cover
		"""
		Special LDAP Attribute parsing function (LDAP -> LOCAL Translation)
		"""
		return

	def parse_write_special_attributes(self):  # pragma: no cover
		"""
		Special LOCAL Attribute parsing function (LOCAL -> LDAP Translation)
		"""
		return

	def __sync_object__(self):
		if not self.entry:
			return

		# Set initial data
		self.attributes = {}

		# Set Distinguished Name from entry or self attribute.
		if self.entry:
			distinguished_name: str = self.entry.entry_dn
		else:
			distinguished_name: str = self.distinguished_name
		self.attributes[LOCAL_ATTR_DN] = distinguished_name

		# Set object type and category
		if self.entry:
			if LDAP_ATTR_OBJECT_CATEGORY in self.entry.entry_attributes:
				_object_category = getldapattrvalue(
					self.entry, LDAP_ATTR_OBJECT_CATEGORY
				)
				self.type = self.__get_common_name__(_object_category)
				self.type = LDAPObjectTypes(self.type.lower())
				self.attributes[LOCAL_ATTR_OBJECT_CATEGORY] = (
					self.__get_common_name__(_object_category)
				)

		# Set Name and Type
		self.attributes[LOCAL_ATTR_NAME] = self.__get_common_name__(
			distinguished_name
		)
		self.attributes[LOCAL_ATTR_TYPE] = (
			LDAPObjectTypes.GENERIC.value.lower()
			if not self.type.value
			else self.type.value.lower()
		)

		# Check if object is built-in
		entry_object_classes: LDAPAttribute = getldapattrvalue(
			self.entry, LDAP_ATTR_OBJECT_CLASS, []
		)
		if (
			self.attributes[LOCAL_ATTR_NAME] in LDAP_BUILTIN_OBJECTS
			or "builtinDomain" in entry_object_classes
		):
			self.attributes[LOCAL_ATTR_BUILT_IN] = True

		# Parse and set attributes with local alias
		for attr_key in self.entry.entry_attributes:
			if attr_key in (self.excluded_ldap_attributes or []):
				continue
			attr_value = getldapattrvalue(self.entry, attr_key)
			local_key = getlocalkeyforldapattr(attr_key, None)
			if not local_key:
				continue

			if (
				attr_key == LDAP_ATTR_SECURITY_ID and
				self.__get_common_name__(
					distinguished_name
				).lower() != LOCAL_ATTR_BUILT_IN and
				getldapattrvalue(self.entry, attr_key, None)
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
						"Could not translate SID Byte Array for %s",
						distinguished_name,
					)
					logger.exception(e)
			elif attr_key == LDAP_ATTR_BAD_PWD_COUNT:
				self.attributes[local_key] = attr_value
			elif attr_value and not attr_key in ATTRS_SPECIAL_LDAP:
				self.attributes[local_key] = attr_value

		self.parse_read_special_attributes()
		self.__sync_int_fields__()
		return

	def __fetch_object__(self):
		self.connection.search(
			search_base=self.search_base,
			search_filter=self.search_filter,
			search_scope=SUBTREE,
			attributes=self.search_attrs,
		)
		self.fetched = True
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

	def __ldap_attrs__(self) -> list:
		if not self.entry:
			return []
		return self.entry.entry_attributes

	def __get_common_name__(self, dn: str = None):
		"""Parses common name from distinguished name."""
		if dn and not isinstance(dn, str):
			raise TypeError("dn must be of type str or None.")
		if not dn and not self.distinguished_name:
			raise ValueError(
				"dn value is required if self has no distinguished_name attribute."
			)
		if not dn:
			dn = self.distinguished_name
		_rdn: str = safe_rdn(dn)[0]
		return _rdn.split("=")[-1]

	def pre_create(self):  # pragma: no cover
		"""Pre Creation operations"""
		return

	def pre_update(self):  # pragma: no cover
		"""Pre Creation operations"""
		return

	def pre_delete(self):  # pragma: no cover
		"""Pre Creation operations"""
		return

	def post_create(self):  # pragma: no cover
		"""Post Creation operations"""
		return

	def post_update(self):  # pragma: no cover
		"""Post Creation operations"""
		return

	def post_delete(self):  # pragma: no cover
		"""Post Creation operations"""
		return

	@property
	def exists(self) -> bool:
		"""Fetches LDAP Entry and checks if it exists in backend LDAP Server."""
		if not self.connection:
			raise Exception(
				"An LDAP Connection is required to check if the object exists."
			)
		if not self.connection.bound:
			raise Exception(
				"LDAP Connection must be bound to check if the object exists."
			)
		self.__fetch_object__()
		return bool(self.entry)

	def value_changed(self, local_alias: str, ldap_alias: str, /) -> bool:
		"""Checks if a local value differs from its entry counterpart

		Positional args only.
		"""
		if not local_alias:
			raise ValueError("local_alias is falsy or unmapped")
		if not ldap_alias:
			raise ValueError("ldap_alias is falsy or unmapped")
		if not isinstance(local_alias, str):
			raise TypeError("local_alias must be of type str")
		if not isinstance(ldap_alias, str):
			raise TypeError("ldap_alias must be of type str")

		entry_value = getldapattrvalue(self.entry, ldap_alias, None)
		local_value = self.attributes.get(local_alias, None)

		if entry_value is None and local_value is None:
			return False
		if local_alias in self.int_fields:
			if entry_value:
				entry_value = int(entry_value)
			if local_value:
				local_value = int(local_value)
		elif isinstance(entry_value, list) or isinstance(local_value, list):
			# Have to contrast with value sets, as LDAP can sometimes return
			# single element list/arrays, and we want to ensure de-duplicated
			# lists.
			if entry_value:
				if isinstance(entry_value, str):
					entry_value = [entry_value]
				elif not isinstance(entry_value, list):
					logger.warning(
						"Bad value type for local %s field", local_alias
					)
				entry_value = set(entry_value)
			else:
				entry_value = {}

			if local_value:
				if isinstance(local_value, str):
					local_value = [local_value]
				elif not isinstance(local_value, list):
					logger.warning(
						"Bad value type for ldap %s field", ldap_alias
					)
				local_value = set(local_value)
			else:
				local_value = {}

		# For verbosity
		has_changed = entry_value != local_value
		return has_changed

	def create(self):
		"""Creates LDAP Object with current instance attributes."""
		if self.entry:
			raise Exception("There is already an existing LDAP Entry.")
		attrs = {}
		_object_class = None
		if self.type == LDAPObjectTypes.USER:
			self.attributes[LOCAL_ATTR_OBJECT_CLASS] = list(
				{
					RuntimeSettings.LDAP_AUTH_OBJECT_CLASS,
					"top",  # Required by LDAP spec
					"person",
					"organizationalPerson",
					"user",
				}
			)
			_object_class = RuntimeSettings.LDAP_AUTH_OBJECT_CLASS
		elif self.type == LDAPObjectTypes.GROUP:
			self.attributes[LOCAL_ATTR_OBJECT_CLASS] = list(
				{
					"top",  # Required by LDAP spec
					"group",
				}
			)
			_object_class = "group"

		self.parse_write_special_attributes()
		for local_alias, local_value in self.attributes.items():
			# Ignore if immutable or special
			if local_alias in ATTRS_IMMUTABLE:
				continue
			elif (
				local_alias in ATTRS_SPECIAL
				and not local_alias in self.parsed_specials
			):
				continue

			ldap_alias = RuntimeSettings.LDAP_FIELD_MAP[local_alias]
			if local_value:
				attrs[ldap_alias] = local_value

		# Execute Operations
		self.pre_create()
		self.connection.add(
			dn=self.distinguished_name,
			object_class=_object_class,
			attributes=attrs,
		)
		self.post_create()
		return (
			getattr(self.connection.result, "description", "").lower()
			== "success"
		)

	def update(
		self,
		force_pre_update: bool = False,
		force_update: bool = False,
		force_post_update: bool = False,
	) -> bool:
		"""Updates LDAP Object with current instance attributes."""
		if not self.entry:
			raise ValueError(
				"An existing LDAP Entry is required to perform an update"
			)
		elif not isinstance(self.entry, LDAPEntry):
			raise TypeError("self.entry must be of type ldap3.Entry")
		if not self.attributes:
			raise ValueError("New attributes must be set to perform an update")

		self.parse_write_special_attributes()
		replace_attrs = {}
		delete_attrs = {}
		for local_alias, local_value in self.attributes.items():
			# Ignore if immutable or special
			if local_alias in ATTRS_IMMUTABLE:
				continue
			elif (
				local_alias in ATTRS_SPECIAL
				and not local_alias in self.parsed_specials
			):
				continue

			# Ignore if local and remote values explicitly None
			ldap_alias = RuntimeSettings.LDAP_FIELD_MAP[local_alias]
			if not self.value_changed(local_alias, ldap_alias):
				continue

			# If local value empty
			if not local_value:
				if (
					local_alias in self.int_fields
					and local_alias in ATTRS_DELETE_PROTECTED
				):
					delete_attrs[ldap_alias] = [(MODIFY_REPLACE, [0])]
				else:
					delete_attrs[ldap_alias] = [(MODIFY_DELETE, [])]
			else:
				if not isinstance(local_value, list):
					local_value = [local_value]
				replace_attrs[ldap_alias] = [(MODIFY_REPLACE, local_value)]

		attrs = replace_attrs | delete_attrs

		# Execute operations
		result = True
		## Pre-update
		if attrs or force_update or force_pre_update:
			self.pre_update()
		## Update
		if attrs or force_update:
			self.connection.modify(dn=self.entry.entry_dn, changes=attrs)
			result = (
				getattr(self.connection.result, "description", "").lower()
				== "success"
			)
		## Post-update
		if attrs or force_update or force_post_update:
			self.post_update()

		return result

	def delete(self) -> bool:
		"""Deletes LDAP Object from LDAP Server / Server Pool."""
		if not self.entry and not self.distinguished_name:
			raise Exception("Deletion requires a valid dn or entry.")
		self.pre_delete()
		if self.entry:
			self.connection.delete(dn=self.entry.entry_dn)
		elif self.distinguished_name:
			self.connection.delete(dn=self.distinguished_name)
		self.post_delete()
		return (
			getattr(self.connection.result, "description", "").lower()
			== "success"
		)

	def save(self, create_kwargs: dict = {}, update_kwargs: dict = {}) -> bool:
		"""Saves LDAP Object to LDAP Server / Server Pool."""
		result = None
		if not self.connection or not self.connection.bound:
			raise Exception(
				"LDAPObject requires a bound LDAP Connection to save modifications"
			)

		if not self.entry:
			result = self.create(**create_kwargs)
		else:
			result = self.update(**update_kwargs)
		self.parsed_specials = []
		return result
