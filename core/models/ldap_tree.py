################################################################################
#################### INTERLOCK IS LICENSED UNDER GNU AGPLv3 ####################
################## ORIGINAL PROJECT CREATED BY DYLAN BLANQUÉ ###################
########################## AND BR CONSULTING S.R.L. ############################
################################################################################
# Module: core.models.ldap_tree
# Contains the Models for the LDAP Directory Tree
#
# ---------------------------------- IMPORTS -----------------------------------#
### Django
from django.utils.translation import gettext_lazy as _

### Interlock
from core.models.ldap_object import LDAPObject, LDAPObjectOptions
from ldap3 import Connection
from core.ldap.adsi import search_filter_from_dict, LDAP_BUILTIN_OBJECTS
from core.ldap.security_identifier import SID
from core.config.runtime import RuntimeSettings

### Others
from typing import TypedDict, Union
from typing_extensions import Required, NotRequired


################################################################################
class LDAPTreeOptions(LDAPObjectOptions):
	subobject_id: NotRequired[int]
	children_object_type: NotRequired[Union[str, type]]

class LDAPTree(LDAPObject):
	"""
	## LDAPTree Object
	Fetches LDAP Directory Tree from the default Search Base or a specified Level

	### Call example
	LDAPTree(**{
	    "key":"val",\n
	    ...
	})

	Args:
	 search_base: (OPTIONAL) | Default: RunningSettings.LDAP_AUTH_SEARCH_BASE
	 connection: (REQUIRED) | LDAP Connection Object
	 recursive: (OPTIONAL) | Whether or not the Tree should be Recursively searched
	 ldap_filter: (OPTIONAL) | LDAP Formatted Filter
	 ldap_attrs: (OPTIONAL) | LDAP Attributes to Fetch
	 excluded_ldap_attrs: (OPTIONAL) | LDAP Attributes to Exclude
	 children_object_type: (OPTIONAL) | Default: List/Array - Can be dict() or list()
	 test_fetch: (OPTIONAL) | Default: False - Only fetch one object to test
	"""

	use_in_migrations = False

	def __init__(self, **kwargs):
		super().__init__(auto_fetch=False)

		# Set LDAPTree Default Values
		self.subobject_id = 0
		self.ldap_filter = search_filter_from_dict(
			{**RuntimeSettings.LDAP_DIRTREE_CN_FILTER, **RuntimeSettings.LDAP_DIRTREE_OU_FILTER}
		)
		self.children_object_type = "array"

		# Set passed kwargs from Object Call
		for kw in kwargs:
			setattr(self, kw, kwargs[kw])

		# Set required attributes, these are unremovable from the tree searches
		for attr in self.required_ldap_attrs:
			if attr not in self.ldap_attrs:
				self.ldap_attrs.append(attr)

		self.children = self.__fetch_tree__()

	def __fetch_object__(self):
		raise AttributeError(f"{type(self).__name__} has no attribute __fetch_object__")

	def __fetch_tree__(self):
		self.connection.search(
			search_base=self.search_base,
			search_filter=self.ldap_filter,
			search_scope="LEVEL",
			attributes=self.ldap_attrs,
		)
		baseLevelList = self.connection.entries
		if self.children_object_type == "array":
			children = []
		else:
			children = {}

		if self.test_fetch == True:
			baseLevelList = [baseLevelList[0]]

		# For each entity in the base level list
		for entity in baseLevelList:
			# Set DN from Abstract Entry object (LDAP3)
			distinguishedName = entity.entry_dn
			# Set entity attributes
			currentEntity = {}
			currentEntity["name"] = str(distinguishedName).split(",")[0].split("=")[1]
			currentEntity["id"] = self.subobject_id
			currentEntity["distinguishedName"] = distinguishedName
			currentEntity["type"] = str(entity.objectCategory).split(",")[0].split("=")[1]
			if (
				currentEntity["name"] in LDAP_BUILTIN_OBJECTS
				or "builtinDomain" in entity.objectClass
			):
				currentEntity["builtin"] = True

			##################################
			# Recursive Children Search Here #
			##################################
			if self.recursive == True:
				currentEntity["children"] = self.__get_children__(distinguishedName)

			# If children object type should be Array
			if self.children_object_type == "array":
				###### Append subobject to Array ######
				children.append(currentEntity)

				###### Increase subobject_id ######
				self.subobject_id += 1
			elif self.children_object_type == "dict":
				###### Append subobject to Dict ######
				children["dict"][currentEntity["distinguishedName"]] = currentEntity
				children["dict"][currentEntity["distinguishedName"]].pop("distinguishedName")

				###### Increase subobject_id ######
				self.subobject_id += 1
		return children

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

	def __get_children__(self, distinguishedName):
		"""
		Function to recursively get Object Children
		Returns JSON Dict
		"""
		if distinguishedName is None:
			raise ValueError("LDAPTree.__getObjectChildren__() - ERROR: Distinguished Name is None")

		# If children object type should be Array
		if self.children_object_type == "array":
			result = []
		else:
			result = {}

		# Send Query to LDAP Server(s)
		ldapSearch = self.connection.extend.standard.paged_search(
			search_base=distinguishedName,
			search_filter=self.ldap_filter,
			search_scope="LEVEL",
			attributes=self.ldap_attrs,
		)

		user_types = [
			"user",
			"person",
			"organizationalPerson",
		]

		for entry in ldapSearch:
			currentObject = {}
			# Set sub-object main attributes
			self.subobject_id += 1
			currentObject["id"] = self.subobject_id
			currentObject["name"] = str(entry["dn"]).split(",")[0].split("=")[1]
			currentObject["distinguishedName"] = entry["dn"]
			currentObject["type"] = (
				str(entry["attributes"]["objectCategory"]).split(",")[0].split("=")[1]
			)
			if (
				currentObject["name"] in LDAP_BUILTIN_OBJECTS
				or "builtinDomain" in entry["attributes"]["objectClass"]
				or self.__get_common_name__(distinguishedName) in LDAP_BUILTIN_OBJECTS
				or self.__get_common_name__(distinguishedName) == "Domain Controllers"
			) and (
				self.__get_common_name__(distinguishedName).lower() != "computers"
				and self.__get_common_name__(distinguishedName).lower() != "users"
			):
				currentObject["builtin"] = True
			# Set the sub-object children
			if self.children_object_type == "array" and "children" not in currentObject:
				currentObject["children"] = []
			elif "children" not in currentObject:
				currentObject["children"] = {}

			# Set all other attributes
			for attr in entry["attributes"]:
				if attr in self.ldap_attrs or self.ldap_attrs == "*":
					if (
						attr == self.username_identifier
						and self.username_identifier in entry["attributes"]
					):
						# For class in user classes check if it's in object
						for cla in user_types:
							if (
								cla in entry["attributes"]["objectClass"]
								and "contact" not in entry["attributes"]["objectClass"]
							):
								value = entry["attributes"][attr][0]
								currentObject["username"] = value
					elif attr == "cn" and "group" in entry["attributes"]["objectClass"]:
						value = entry["attributes"][attr][0]
						currentObject["groupname"] = value
					elif attr == "objectCategory":
						value = self.__get_common_name__(entry["attributes"][attr])
						currentObject["type"] = value
					elif (
						attr == "objectSid"
						and "group" in entry["attributes"]["objectClass"]
						and self.__get_common_name__(distinguishedName).lower() != "builtin"
					):
						try:
							sid = SID(entry["attributes"][attr])
							sid = sid.__str__()
							rid = sid.split("-")[-1]
							value = sid
							currentObject["objectRid"] = rid
						except Exception as e:
							print("Could not translate SID Byte Array for " + distinguishedName)
							print(e)
					elif attr not in self.excluded_ldap_attrs:
						try:
							if (
								isinstance(entry["attributes"][attr], list)
								and len(entry["attributes"][attr]) > 1
							):
								value = entry["attributes"][attr]
							elif entry["attributes"][attr] != []:
								value = entry["attributes"][attr][0]
						except Exception as e:
							print(e)
							exc_message = f"Could not set attribute {attr} for {currentObject['distinguishedName']}"
							raise Exception(exc_message)

					try:
						currentObject[attr] = value
					except Exception as e:
						print(f"Exception on key: {attr}")
						print(f"Object: {distinguishedName}")
						print(e)

			# Force exclude System folder, has a bunch of objects that aren't useful for administration
			if (
				self.recursive == True
				and currentObject["type"].lower() in self.container_types
				and self.__get_common_name__(distinguishedName).lower() != "system"
			):
				children = self.__get_children__(entry["dn"])
			else:
				children = []

			# Set the sub-object children
			if self.children_object_type == "array" and children:
				currentObject["children"] = children
			elif children:
				currentObject["children"].update(children)

			if not currentObject["children"]:
				del currentObject["children"]
			result.append(currentObject)

		if result:
			return result
		else:
			return None
