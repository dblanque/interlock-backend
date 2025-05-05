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
from core.ldap.constants import (
	LOCAL_ATTRS_MAP,
	LDAP_ATTR_COUNTRY_DCC,
	LDAP_ATTR_UAC,
	LDAP_ATTR_LAST_LOGIN,
	LDAP_ATTR_BAD_PWD_COUNT,
	LDAP_ATTR_PWD_SET_AT,
	LDAP_ATTR_PRIMARY_GROUP_ID,
	LDAP_ATTR_SECURITY_ID,
	LDAP_ATTR_RELATIVE_ID,
	LDAP_ATTR_DN,
	LDAP_ATTR_OBJECT_CATEGORY,
	LDAP_ATTR_OBJECT_CLASS,
	LOCAL_ATTR_USERNAME,
	LDAP_ATTR_COMMON_NAME,
)
from core.config.runtime import RuntimeSettings
from core.ldap.adsi import LDAP_BUILTIN_OBJECTS, join_ldap_filter
from core.ldap.security_identifier import SID

### Others
from core.ldap.filter import LDAPFilter
from ldap3 import (
	Connection,
	Entry as LDAPEntry,
	Attribute as LDAPAttribute,
	SUBTREE,
)
from typing import TypedDict, Iterable
from typing_extensions import Required, NotRequired
from logging import getLogger
from core.views.mixins.utils import getldapattrvalue

################################################################################
logger = getLogger()

# TODO
# Add save method to LDAPObject
# Add Immutable or always excluded keys tuple

class LDAPObjectOptions(TypedDict):
	name: NotRequired[str]
	search_base: NotRequired[str]
	connection: Required[Connection]
	username_identifier: str
	excluded_ldap_attrs: NotRequired[list[str]]
	required_ldap_attrs: NotRequired[list[str]]
	container_types: NotRequired[list[str]]
	user_types: NotRequired[list[str]]
	ldap_attrs: NotRequired[list[str]]
	ldap_filter: NotRequired[str]


DEFAULT_REQUIRED_LDAP_ATTRS = [
	"distinguishedName",
	"objectCategory",
	"objectClass",
]
DEFAULT_CONTAINER_TYPES = ["container", "organizational-unit"]
DEFAULT_USER_TYPES = [
	"user",
	"person",
	"organizationalPerson",
]


class LDAPObject:
	"""
	## Interlock LDAP Object Abstraction
	Fetches LDAP Object from a specified DN

	Args:
		name (str): Object Name.
		search_base (str): LDAP Search Base.
		connection (Connection): LDAP Connection.
		username_identifier (str): Identifier used for Username Fields.
		excluded_ldap_attrs (list[str]): Fields to exclude from search.
		required_ldap_attrs (list[str]): Fields to re-add if missing in filter list.
		container_types (list[str]): Types that are containers (e.g.: organizational-unit)
		user_types (list[str]): Types that are user objects (e.g.: person)
		ldap_attrs (list[str]): Filters to fetch for LDAP object
		ldap_filter (str): Filter to identify LDAP Object in server
	"""

	# Django
	use_in_migrations: bool = False

	# Type Hints
	attr_map = LOCAL_ATTRS_MAP
	attributes: dict
	connection: Connection
	container_types: list[str]
	entry: LDAPEntry
	excluded_ldap_attrs: list[str]
	ldap_attrs: list[str]
	ldap_filter: str
	name: str
	required_ldap_attrs: list[str]
	search_base: str
	user_types: list[str]
	username_identifier: str

	INT_FIELDS = [
		LDAP_ATTR_COUNTRY_DCC,
		LDAP_ATTR_UAC,
		LDAP_ATTR_LAST_LOGIN,
		LDAP_ATTR_BAD_PWD_COUNT,
		LDAP_ATTR_PWD_SET_AT,
		LDAP_ATTR_PRIMARY_GROUP_ID,
		LDAP_ATTR_RELATIVE_ID,
	]

	def __init__(self, auto_fetch=True, **kwargs: LDAPObjectOptions) -> None:
		self.__validate_kwargs__(kwargs=kwargs)

		# Set LDAPTree Default Values
		self.entry = None
		self.attributes = None
		self.name = RuntimeSettings.LDAP_AUTH_SEARCH_BASE
		self.search_base = RuntimeSettings.LDAP_AUTH_SEARCH_BASE
		self.connection = kwargs.pop("connection")
		self.username_identifier = RuntimeSettings.LDAP_AUTH_USER_FIELDS[
			"username"
		]
		self.excluded_ldap_attrs = []
		self.required_ldap_attrs = DEFAULT_REQUIRED_LDAP_ATTRS
		self.container_types = DEFAULT_CONTAINER_TYPES
		self.user_types = DEFAULT_USER_TYPES
		self.ldap_attrs = RuntimeSettings.LDAP_DIRTREE_ATTRIBUTES
		if "dn" in kwargs:
			self.ldap_filter = LDAPFilter.eq(
				LDAP_ATTR_DN,
				str(kwargs['dn']),
			).to_string()

		self.__set_kwargs__(kwargs)

		if auto_fetch:
			self.__fetch_object__()

	def __validate_kwargs__(self, kwargs):
		if "connection" not in kwargs:
			raise Exception(
				"LDAP Object requires an LDAP Connection to Initialize"
			)
		if "dn" not in kwargs and "ldap_filter" not in kwargs:
			raise Exception(
				"LDAP Object requires a Distinguished Name or a valid ldap_filter to search for the object"
			)

	def __set_kwargs__(self, kwargs):
		# Set passed kwargs from Object Call
		for kw in kwargs:
			setattr(self, kw, kwargs[kw])

		# Remove excluded attributes
		for attr in self.excluded_ldap_attrs:
			if attr in self.ldap_attrs:
				self.ldap_attrs.remove(attr)

		# Set required attributes, these are unremovable from the tree searches
		for attr in self.required_ldap_attrs:
			if attr not in self.ldap_attrs:
				self.ldap_attrs.append(attr)

	def __get_connection__(self):
		return self.connection

	def __get_entry__(self) -> LDAPEntry:
		return self.entry

	def __get_object__(self):
		return self.attributes

	def __fetch_object__(self):
		self.connection.search(
			search_base=self.search_base,
			search_filter=self.ldap_filter,
			search_scope=SUBTREE,
			attributes=self.ldap_attrs,
		)
		search_result = self.connection.entries
		if not isinstance(search_result, Iterable) or not search_result:
			return
		if len(search_result) > 1:
			logger.warning(
				"Search result for LDAP Object has more than one entries."
			)
			logger.warning("Search filter used: %s", self.ldap_filter)
		try:
			self.entry = search_result[0]
		except Exception as e:
			raise ValueError("Error setting LDAP Object Entry Result") from e

		# Set DN from Abstract Entry object (LDAP3)
		# Set searchResult attributes
		distinguished_name: str = self.entry.entry_dn
		self.attributes = {}
		self.attributes["name"] = distinguished_name.split(",")[0].split("=")[1]
		self.attributes["distinguishedName"] = distinguished_name
		self.attributes["type"] = (
			getldapattrvalue(self.entry, LDAP_ATTR_OBJECT_CATEGORY)
			.split(",")[0]
			.split("=")[1]
		)
		entry_object_classes: LDAPAttribute = getldapattrvalue(
			self.entry, LDAP_ATTR_OBJECT_CLASS, []
		)
		if (
			self.attributes["name"] in LDAP_BUILTIN_OBJECTS
			or "builtinDomain" in entry_object_classes
		):
			self.attributes["builtin"] = True

		for attr_key in self.ldap_attrs:
			if not hasattr(self.entry, attr_key):
				continue
			attr_value = getldapattrvalue(self.entry, attr_key)

			if attr_key == self.username_identifier:
				self.attributes[attr_key] = attr_value
				self.attributes[LOCAL_ATTR_USERNAME] = attr_value
			elif attr_key == LDAP_ATTR_COMMON_NAME and "group" in entry_object_classes:
				self.attributes[attr_key] = attr_value
				self.attributes["groupname"] = attr_value
			elif (
				attr_key == LDAP_ATTR_SECURITY_ID
				and self.__get_common_name__(distinguished_name).lower()
				!= "builtin"
			):
				try:
					# Do not use getldapattr here, we want raw_values
					sid = SID(getattr(self.entry, attr_key))
					sid = sid.__str__()
					rid = int(sid.split("-")[-1])
					self.attributes[LDAP_ATTR_SECURITY_ID] = sid
					self.attributes[LDAP_ATTR_RELATIVE_ID] = rid
				except Exception as e:
					logger.error(
						"Could not translate SID Byte Array for "
						+ distinguished_name
					)
					logger.exception(e)
			elif attr_key not in self.attributes and attr_value is not None:
				self.attributes[attr_key] = attr_value

		for fld in self.INT_FIELDS:
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
		return self.attributes

	def __ldap_attrs__(self):
		if not self.attributes:
			return []
		return list(self.attributes.keys())

	def __mapped_attrs__(self) -> dict:
		if not self.attributes:
			return {}

		result = {}
		# Add mapped attrs
		for local_key, ldap_alias in LOCAL_ATTRS_MAP.items():
			if ldap_alias in self.attributes.keys():
				result[local_key] = self.attributes[ldap_alias]
		# Add unmapped attrs
		for _key, _value in self.attributes.items():
			if _value not in result.values():
				result[_key] = _value
		return result

	def __get_common_name__(self, dn: str):
		return str(dn).split(",")[0].split("=")[-1]

	def __setattr__(self, name, value):
		if name != "attr_map":
			if name in self.attr_map.keys():
				self.attributes[self.attr_map[name]] = value
				return
			elif name in self.attr_map.values():
				self.attributes[name] = value
				return
		return super().__setattr__(name, value)

	def __getattribute__(self, name):
		if name != "attr_map":
			if name in self.attr_map.keys():
				return self.attributes[self.attr_map[name]]
			if name in self.attr_map.values():
				return self.attributes[name]
		return super().__getattribute__(name)
