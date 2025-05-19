################################################################################
#################### INTERLOCK IS LICENSED UNDER GNU AGPLv3 ####################
################## ORIGINAL PROJECT CREATED BY DYLAN BLANQUÉ ###################
########################## AND BR CONSULTING S.R.L. ############################
################################################################################
# Module: core.models.ldap_tree
# Contains the Models for the LDAP Directory Tree
#
# ---------------------------------- IMPORTS -----------------------------------#
### Interlock
from core.models.ldap_object import LDAPObject, LDAPObjectTypes
from core.ldap.adsi import LDAP_BUILTIN_OBJECTS
from core.ldap.filter import LDAPFilter
from core.constants.attrs import *

### Others
from core.config.runtime import RuntimeSettings
from core.views.mixins.utils import getldapattrvalue
from core.type_hints.connector import LDAPConnectionProtocol
from typing import overload
from ldap3 import LEVEL, Entry as LDAPEntry
import logging

################################################################################
logger = logging.getLogger()


class LDAPTree(LDAPObject):
	"""
	## LDAPTree Object
	Fetches LDAP Directory Tree from the default Search Base or a specified Level
	"""

	# Django only
	use_in_migrations = False

	# Class attrs
	recursive = False

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
		recursive: bool = False,
		children_object_type: type = list,
	) -> None: ...

	def __init__(self, **kwargs):
		"""LDAP Tree Initialization"""
		# Set LDAPTree Default Values
		self.subobject_id = 0
		self.search_filter = LDAPFilter.and_(
			# Object Class
			LDAPFilter.or_(
				*[
					LDAPFilter.eq(LDAP_ATTR_OBJECT_CLASS, v)
					for v in (
						"user",
						"person",
						"group",
						"organizationalPerson",
						"computer",
					)
				]
			),
			# Object Category
			LDAPFilter.or_(
				*[
					LDAPFilter.eq(LDAP_ATTR_OBJECT_CATEGORY, v)
					for v in (
						"organizationalUnit",
						"top",
						"container",
					)
				],
				LDAPFilter.eq(LDAP_ATTR_OBJECT_CLASS, "builtinDomain"),
			),
		).to_string()
		self.children_object_type = list

		kwargs.pop("skip_fetch", None)
		for kw in (
			"children_object_type",
			"recursive",
		):
			if kw in kwargs:
				setattr(self, kw, kwargs.pop(kw))

		super().__init__(
			skip_fetch=True,
			search_attrs=kwargs.pop(
				"search_attrs",
				(
					# User Attrs
					LDAP_ATTR_OBJECT_CLASS,
					LDAP_ATTR_OBJECT_CATEGORY,
					RuntimeSettings.LDAP_OU_FIELD,
					# Group Attrs
					LDAP_ATTR_COMMON_NAME,
					LDAP_ATTR_GROUP_MEMBERS,
					LDAP_ATTR_DN,
					LDAP_ATTR_GROUP_TYPE,
				),
			),
			**kwargs,
		)

		self.children = self.__fetch_tree__()

	def __validate_init__(self, **kwargs):
		"""Super class override."""
		if not self.connection:
			raise Exception(
				"LDAP Object requires an LDAP Connection to Initialize"
			)

	def __fetch_object__(self):
		raise AttributeError(
			f"{type(self).__name__} has no attribute __fetch_object__"
		)

	def __fetch_tree__(self):
		self.connection.search(
			search_base=self.search_base,
			search_filter=self.search_filter,
			search_scope=LEVEL,
			attributes=self.search_attrs,
		)
		base_level: list = self.connection.entries
		if self.children_object_type == list:
			top_children = []
		else:
			top_children = {}

		# For each entity in the base level list
		for entry in base_level:
			entry: LDAPEntry
			# Set DN from Abstract Entry object (LDAP3)
			distinguished_name = entry.entry_dn
			# Set entity attributes
			_current_obj = {}
			_current_obj[LOCAL_ATTR_NAME] = (
				str(distinguished_name).split(",")[0].split("=")[1]
			)
			_current_obj[LOCAL_ATTR_ID] = self.subobject_id
			_current_obj[LOCAL_ATTR_DN] = distinguished_name
			_class = getldapattrvalue(entry, LDAP_ATTR_OBJECT_CLASS)
			_type = (
				getldapattrvalue(entry, LDAP_ATTR_OBJECT_CATEGORY)
				.split(",")[0]
				.split("=")[1]
			)
			_current_obj[LOCAL_ATTR_TYPE] = LDAPObjectTypes(_type.lower()).value
			if (
				_current_obj[LOCAL_ATTR_NAME] in LDAP_BUILTIN_OBJECTS
				or "builtinDomain" in _class
			):
				_current_obj[LOCAL_ATTR_BUILT_IN] = True
			else:
				_current_obj[LOCAL_ATTR_BUILT_IN] = False

			##################################
			# Recursive Children Search Here #
			##################################
			if self.recursive:
				_current_obj["children"] = self.__get_children__(
					distinguished_name
				)

			# If children object type should be Array
			if self.children_object_type == list:
				###### Append subobject to Array ######
				top_children.append(_current_obj)

				###### Increase subobject_id ######
				self.subobject_id += 1
			elif self.children_object_type == dict:
				###### Append subobject to Dict ######
				top_children[_current_obj[LOCAL_ATTR_DN]] = _current_obj
				top_children[_current_obj[LOCAL_ATTR_DN]].pop(LOCAL_ATTR_DN)

				###### Increase subobject_id ######
				self.subobject_id += 1
		return top_children

	def __get_tree_count__(self):
		count = 0

		for k, v in enumerate(self.children):
			count += 1
			if "children" in self.children[k]:
				count += self.__get_child_count__(self.children[k]["children"])

		return count

	def __get_child_count__(self, child):
		count = 0
		for k, v in enumerate(child):
			count += 1
			if "children" in child[k]:
				count += self.__get_child_count__(child[k]["children"])

		return count

	def __get_children__(self, distinguished_name):
		"""
		Function to recursively get Object Children
		Returns JSON Dict
		"""
		if not distinguished_name:
			raise ValueError("Distinguished Name is None.")

		common_name = self.__get_common_name__(distinguished_name)

		# If children object type should be Array
		if self.children_object_type == list:
			result = []
		elif self.children_object_type == dict:
			result = {}

		# Send Query to LDAP Server(s)
		self.connection.search(
			search_base=distinguished_name,
			search_filter=self.search_filter,
			search_scope=LEVEL,
			attributes=self.search_attrs,
		)

		for entry in self.connection.entries:
			entry: LDAPEntry  # Set the sub-object children
			children = None

			# Ignore self if somehow in search entries
			if entry.entry_dn == distinguished_name:
				continue

			# Setup sub-object main attributes
			self.subobject_id += 1
			_current_obj = LDAPObject(entry=entry).attributes
			_current_obj_tree_data = {
				LOCAL_ATTR_ID: self.subobject_id,
				LOCAL_ATTR_NAME: self.__get_common_name__(entry.entry_dn),
			}
			if (
				self.children_object_type == list
				and "children" not in _current_obj
			):
				_current_obj["children"] = []
			elif (
				self.children_object_type == dict
				and "children" not in _current_obj
			):
				_current_obj["children"] = {}
			else:
				raise ValueError(
					f"children_object_type ({self.children_object_type}) unsupported."
				)

			# Construct subobject
			if (
				_current_obj[LOCAL_ATTR_NAME] in LDAP_BUILTIN_OBJECTS
				or "builtinDomain"
				in getldapattrvalue(entry, LDAP_ATTR_OBJECT_CLASS)
				or common_name in LDAP_BUILTIN_OBJECTS
				or common_name == "Domain Controllers"
			) and (
				common_name.lower() != "computers"
				and common_name.lower() != "users"
			):
				_current_obj[LOCAL_ATTR_BUILT_IN] = True

			# Force exclude System folder, has a bunch of objects that aren't useful for administration
			if (
				self.recursive
				and _current_obj[LOCAL_ATTR_TYPE]
				in (
					"container",
					"organizational-unit",
				)
				and common_name.lower() != "system"
			):
				children = self.__get_children__(entry.entry_dn)

			# Set the sub-object children
			if children:
				if self.children_object_type == list:
					_current_obj["children"] = children
				else:
					_current_obj["children"].update(children)

			if self.children_object_type == list:
				result.append(_current_obj | _current_obj_tree_data)
			elif self.children_object_type == dict:
				result[entry.entry_dn] = _current_obj | _current_obj_tree_data

		if result:
			return result
		else:
			return None
