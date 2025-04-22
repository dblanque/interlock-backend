################################################################################
#################### INTERLOCK IS LICENSED UNDER GNU AGPLv3 ####################
################## ORIGINAL PROJECT CREATED BY DYLAN BLANQUÉ ###################
########################## AND BR CONSULTING S.R.L. ############################
################################################################################
# Module: core.views.mixins.ldap.group
# Contains the Mixin for Group related operations

# ---------------------------------- IMPORTS -----------------------------------#
### ViewSets
from rest_framework import viewsets

### Interlock
from core.ldap.adsi import join_ldap_filter
from core.ldap.types.group import LDAPGroupTypes
from core.ldap.security_identifier import SID
from core.ldap.connector import LDAPConnector
from core.config.runtime import RuntimeSettings

### Models
from core.views.mixins.logs import LogMixin
from core.models.application import ApplicationSecurityGroup

### Core
from core.models.choices.log import (
	LOG_ACTION_CREATE,
	LOG_ACTION_READ,
	LOG_ACTION_UPDATE,
	LOG_ACTION_DELETE,
	LOG_CLASS_GROUP,
	LOG_TARGET_ALL,
)
from core.ldap.filter import LDAPFilter
from core.models.ldap_object import LDAPObject
from core.views.mixins.ldap.organizational_unit import OrganizationalUnitMixin

### Exceptions
import traceback
from core.exceptions import ldap as exc_ldap, groups as exc_groups, dirtree as exc_dirtree

### Others
from core.views.mixins.utils import getldapattr
from typing import List
from django.db import transaction
from copy import deepcopy
import ldap3
from ldap3 import MODIFY_DELETE, MODIFY_REPLACE, Entry as LDAPEntry, Connection
import logging
################################################################################

DBLogMixin = LogMixin()
logger = logging.getLogger(__name__)


class GroupViewMixin(viewsets.ViewSetMixin):
	ldap_connection: Connection = None
	ldap_filter_object = None
	ldap_filter_attr = None

	def get_group_types(self, group_type: int = None, debug=False) -> List[str]:
		sum = 0
		result = []
		if not isinstance(group_type, (int, str)) or group_type is False:
			raise TypeError("group_type must be of type int.")

		if isinstance(group_type, str):
			try:
				group_type = int(group_type)
			except:
				raise ValueError("group_type could not be cast to int.")
		group_type_last_int = int(str(group_type)[-1])
		if group_type < -1:
			sum -= LDAPGroupTypes.GROUP_SECURITY.value
			result.append(LDAPGroupTypes.GROUP_SECURITY.name)

			if (group_type_last_int % 2) != 0:
				sum += LDAPGroupTypes.GROUP_SYSTEM.value
				result.append(LDAPGroupTypes.GROUP_SYSTEM.name)
			if group_type == (sum + 2):
				sum += LDAPGroupTypes.GROUP_GLOBAL.value
				result.append(LDAPGroupTypes.GROUP_GLOBAL.name)
			if group_type == (sum + 4):
				sum += LDAPGroupTypes.GROUP_DOMAIN_LOCAL.value
				result.append(LDAPGroupTypes.GROUP_DOMAIN_LOCAL.name)
			if group_type == (sum + 8):
				sum += LDAPGroupTypes.GROUP_UNIVERSAL.value
				result.append(LDAPGroupTypes.GROUP_UNIVERSAL.name)
		else:
			result.append(LDAPGroupTypes.GROUP_DISTRIBUTION.name)

			if (group_type_last_int % 2) != 0:
				sum += LDAPGroupTypes.GROUP_SYSTEM.value
				result.append(LDAPGroupTypes.GROUP_SYSTEM.name)
			if group_type == (sum + 2):
				sum += LDAPGroupTypes.GROUP_GLOBAL.value
				result.append(LDAPGroupTypes.GROUP_GLOBAL.name)
			if group_type == (sum + 4):
				sum += LDAPGroupTypes.GROUP_DOMAIN_LOCAL.value
				result.append(LDAPGroupTypes.GROUP_DOMAIN_LOCAL.name)
			if group_type == (sum + 8):
				sum += LDAPGroupTypes.GROUP_UNIVERSAL.value
				result.append(LDAPGroupTypes.GROUP_UNIVERSAL.name)

		if sum != group_type:
			raise ValueError("Invalid group type integer")

		if debug:
			return (result, group_type,)
		else:
			return result

	@staticmethod
	def get_group_by_rid(rid: int = None, attributes: List[str] = None) -> dict | None:
		if not attributes:
			attributes = ["objectSid", "distinguishedName"]
		if isinstance(rid, list):
			rid = rid[0]
		if rid is None or rid is False:
			raise ValueError("rid cannot be None or False")

		# Cast to Integer just in case
		try:
			rid = int(rid)
		except Exception as e:
			logger.exception(e)
			logger.error(str(rid))
			raise ValueError("Could not cast rid to int") from e

		with LDAPConnector(force_admin=True) as ldc:
			connection = ldc.connection
			connection.search(
				search_base=RuntimeSettings.LDAP_AUTH_SEARCH_BASE,
				search_filter=LDAPFilter.eq("objectClass", "group").to_string(),
				search_scope=ldap3.SUBTREE,
				attributes=attributes,
			)

			for g in connection.entries:
				g: LDAPEntry
				# Do not use getldapattr here, we want raw_values
				_sid_attr = getattr(g, "objectSid", None)
				if not _sid_attr:
					continue
				_sid = SID(_sid_attr)
				_sid = _sid.__str__()
				_rid = int(_sid.split("-")[-1])
				if rid != _rid:
					continue

				result = LDAPObject(
					connection=connection,
					dn=g.entry_dn,
					ldap_attrs=attributes,
				)
				return result.attributes
		return None

	def list_groups(self) -> tuple[list[dict], list[str]]:
		data = []
		self.ldap_connection.search(
			search_base=RuntimeSettings.LDAP_AUTH_SEARCH_BASE,
			search_filter=self.ldap_filter_object,
			attributes=self.ldap_filter_attr,
		)
		ldap_entries = self.ldap_connection.entries

		# Remove attributes to return as table headers
		valid_attributes: List[str] = self.ldap_filter_attr
		remove_attributes = ["distinguishedName", "member"]

		for attr in remove_attributes:
			if attr in valid_attributes:
				valid_attributes.remove(attr)

		for group_entry in ldap_entries:
			group_entry: LDAPEntry
			# For each attribute in group object attributes
			group_dict = {}
			# Add entry DN to response dictionary
			group_dict["distinguishedName"] = group_entry.entry_dn

			for attr_key in group_entry.entry_attributes:
				# Parse Group Type
				if attr_key == "groupType":
					group_dict[attr_key] = self.get_group_types(
						group_type=int(getldapattr(group_entry, attr_key))
					)
				# Do the standard for every other key
				elif attr_key in valid_attributes:
					group_dict[attr_key] = getldapattr(group_entry, attr_key, None)

			# Check if group has Members
			if getldapattr(group_entry, "member", None):
				group_dict["hasMembers"] = True
			else:
				group_dict["hasMembers"] = False

			data.append(group_dict)

		valid_attributes.append("hasMembers")

		DBLogMixin.log(
			user=self.request.user.id,
			operation_type=LOG_ACTION_READ,
			log_target_class=LOG_CLASS_GROUP,
			log_target=LOG_TARGET_ALL,
		)
		return data, valid_attributes

	def fetch_group(self):
		self.ldap_connection.search(
			search_base=RuntimeSettings.LDAP_AUTH_SEARCH_BASE,
			search_filter=self.ldap_filter_object,
			attributes=self.ldap_filter_attr,
		)
		ldap_group_entry: LDAPEntry = self.ldap_connection.entries[0]

		# Remove attributes to return as table headers
		valid_attributes: list[str] = self.ldap_filter_attr
		valid_attributes.remove("distinguishedName")

		# For each attribute in group object attributes
		group_dict = {}
		# Add entry DN to response dictionary
		group_dict["distinguishedName"] = ldap_group_entry.entry_dn

		for attr_key in ldap_group_entry.entry_attributes:
			if not attr_key in valid_attributes:
				continue

			attr_value = getldapattr(ldap_group_entry, attr_key, None)
			# Parse Group Type
			if attr_key == "groupType":
				group_type = int(attr_value)
				group_dict[attr_key] = self.get_group_types(group_type=group_type)
			elif attr_key == "member":
				attr_members = attr_value if isinstance(attr_value, list) \
								else [attr_value]
				member_list = []

				# Fetch members
				for member_user_dn in attr_members:
					args = {
						"connection": self.ldap_connection,
						"dn": member_user_dn,
						"ldap_attrs": [
							"cn",
							"distinguishedName",
							RuntimeSettings.LDAP_AUTH_USER_FIELDS["username"],
							"givenName",
							"sn",
							"objectCategory",
							"objectClass",
						],
					}
					member_list.append(LDAPObject(**args).attributes)
				group_dict[attr_key] = member_list
			# Do the standard for every other key
			elif attr_key == "objectSid":
				# Don't use getldapattr for the sid, we need raw bytes
				sid = SID(getattr(ldap_group_entry, attr_key))
				sid = sid.__str__()
				rid = sid.split("-")[-1]
				group_dict[attr_key] = sid
				group_dict["objectRid"] = int(rid)
			else:
				group_dict[attr_key] = attr_value

		DBLogMixin.log(
			user=self.request.user.id,
			operation_type=LOG_ACTION_READ,
			log_target_class=LOG_CLASS_GROUP,
			log_target=group_dict["cn"],
		)
		return group_dict, valid_attributes

	def create_group(self, group_data: dict, exclude_keys=["member", "path"]):
		if group_data.get("path", None):
			distinguishedName = "cn=" + group_data["cn"] + "," + group_data["path"]
		else:
			distinguishedName = (
				f"CN={group_data['cn']},CN=Users,{RuntimeSettings.LDAP_AUTH_SEARCH_BASE}"
			)

		group_cn: str = group_data.get("cn")
		group_data[RuntimeSettings.LDAP_GROUP_FIELD] = group_cn.lower()

		args = {
			"connection": self.ldap_connection,
			"ldap_filter": self.ldap_filter_object,
			"ldap_attrs": self.ldap_filter_attr,
			"hideErrors": True,
		}

		# !!! CHECK IF GROUP EXISTS !!! #
		try:
			group_exists = LDAPObject(**args).attributes
			group_exists = len(group_exists) > 0
		except:
			group_exists = False

		# If group exists, return error
		if group_exists:
			raise exc_ldap.LDAPObjectExists(data={"group": group_data["cn"]})

		# Set group Type
		if "groupType" not in group_data or "groupScope" not in group_data:
			self.ldap_connection.unbind()
			group_data = {"group": group_data["cn"]}
			raise exc_groups.GroupScopeOrTypeMissing(data=group_data)

		sum = RuntimeSettings.LDAP_GROUP_TYPE_MAPPING[int(group_data["groupType"])]
		sum += RuntimeSettings.LDAP_GROUP_SCOPE_MAPPING[int(group_data["groupScope"])]
		group_data["groupType"] = sum
		group_data.pop("groupScope")

		group_dict = deepcopy(group_data)
		for key in group_data:
			if key in exclude_keys:
				logger.debug("Removing key from dictionary: " + key)
				group_dict.pop(key)

		group_dict["cn"] = group_dict["cn"]
		if "membersToAdd" in group_dict:
			membersToAdd = group_dict.pop("membersToAdd")
		else:
			membersToAdd = []

		logger.debug("Creating group in DN Path: " + group_data["path"])
		try:
			self.ldap_connection.add(distinguishedName, "group", attributes=group_dict)
		except Exception as e:
			self.ldap_connection.unbind()
			print(e)
			group_data = {"ldap_response": self.ldap_connection.result}
			raise exc_groups.GroupCreate(data=group_data)

		if len(membersToAdd) > 0:
			try:
				self.ldap_connection.extend.microsoft.add_members_to_groups(
					membersToAdd, distinguishedName
				)
			except Exception as e:
				try:
					self.ldap_connection.delete(distinguishedName)
					group_data = {"ldap_response": self.ldap_connection.result}
					raise exc_groups.GroupMembersAdd
				except Exception as e:
					self.ldap_connection.unbind()
				self.ldap_connection.unbind()
				print(e)
				group_data = {"ldap_response": self.ldap_connection.result}
				raise exc_groups.GroupMembersAdd

		DBLogMixin.log(
			user=self.request.user.id,
			operation_type=LOG_ACTION_CREATE,
			log_target_class=LOG_CLASS_GROUP,
			log_target=group_dict["cn"],
		)
		return self.ldap_connection

	def update_group(self, group_data: dict, unbind_on_error: bool = True):
		data = self.request.data
		group_cn = None

		# Set Distinguished Name
		if "distinguishedName" not in group_data:
			if unbind_on_error:
				self.ldap_connection.unbind()
			raise exc_groups.GroupDistinguishedNameMissing
		else:
			distinguished_name: str = group_data["distinguishedName"]
			relative_dn: str = distinguished_name.split(",")[0]

		# Set Common Name
		if "cn" not in group_data:
			group_cn = relative_dn
		# If Group CN was modified
		else:
			group_cn = f"CN={group_data['cn']}"
			relative_dn = group_cn
			if relative_dn == distinguished_name:
				raise exc_dirtree.DirtreeDistinguishedNameConflict
			try:
				distinguished_name = OrganizationalUnitMixin.move_or_rename_object(
					self, distinguished_name=distinguished_name, target_rdn=group_cn
				)
			except:
				exc_dirtree.DirtreeRename()

		if group_cn.startswith("CN="):
			group_cn = group_cn.split("CN=")[-1]

		group_data[RuntimeSettings.LDAP_GROUP_FIELD] = str(group_cn).lower()
		# Send LDAP Query for user being created to see if it exists
		args = {
			"connection": self.ldap_connection,
			"dn": distinguished_name,
			"ldap_attrs": self.ldap_filter_attr,
			"hideErrors": True,
		}

		# !!! CHECK IF GROUP EXISTS !!! #
		# We also need to fetch the existing LDAP group object to know what
		# kind of operation to apply when updating attributes
		try:
			fetched_group_entry = LDAPObject(**args).attributes
			group_entry_exists = len(fetched_group_entry) > 0
		except:
			group_entry_exists = False

		# If group exists, return error
		if not group_entry_exists:
			self.ldap_connection.unbind()
			data = {"group": group_cn}
			raise exc_groups.GroupDoesNotExist(data=data)

		# Set group Type
		if "groupType" not in group_data or "groupScope" not in group_data:
			self.ldap_connection.unbind()
			data = {"group": group_cn}
			raise exc_groups.GroupScopeOrTypeMissing(data=data)

		castGroupType = int(group_data["groupType"])
		castGroupScope = int(group_data["groupScope"])
		sum = RuntimeSettings.LDAP_GROUP_TYPE_MAPPING[castGroupType]
		sum += RuntimeSettings.LDAP_GROUP_SCOPE_MAPPING[castGroupScope]
		group_data["groupType"] = sum
		group_data.pop("groupScope")

		excludeKeys = [
			"cn",
			"member",
			"path",
			"distinguishedName",
			"objectSid",  # LDAP Bytes attr
			"objectRid",  # LDAP Bytes attr
		]

		group_dict = deepcopy(group_data)
		for key in group_data:
			if key in excludeKeys:
				logger.debug("Removing key from dictionary: " + key)
				group_dict.pop(key)

		if "membersToAdd" in data and "membersToRemove" in data:
			if (data["membersToAdd"] == data["membersToRemove"] and data["membersToAdd"]) != []:
				self.ldap_connection.unbind()
				logger.error(data)
				raise exc_groups.BadMemberSelection

		if "membersToAdd" in group_dict:
			membersToAdd = group_dict.pop("membersToAdd")
		else:
			membersToAdd = None
		if "membersToRemove" in group_dict:
			membersToRemove = group_dict.pop("membersToRemove")
		else:
			membersToRemove = None

		# We need to check if the attributes exist in the LDAP Object already
		# To know what operation to apply. This is VERY important.
		arguments = {}
		operation = None
		for key in group_dict:
			try:
				if key in fetched_group_entry and group_dict[key] == "" and key != "groupType":
					operation = MODIFY_DELETE
					self.ldap_connection.modify(
						distinguished_name,
						{key: [(operation), []]},
					)
				elif group_dict[key] != "":
					operation = MODIFY_REPLACE
					if key == "groupType":
						previousGroupTypes = self.get_group_types(
							group_type=int(fetched_group_entry[key])
						)
						# If we're trying to go from Group Global to Domain Local Scope or viceversa
						# We need to make it universal first, otherwise the LDAP server denies the update request
						# Sucks but we have to do this :/
						if ("GROUP_GLOBAL" in previousGroupTypes and castGroupScope == 1) or (
							"GROUP_DOMAIN_LOCAL" in previousGroupTypes and castGroupScope == 0
						):
							passthroughSum = RuntimeSettings.LDAP_GROUP_TYPE_MAPPING[castGroupType]
							passthroughSum += RuntimeSettings.LDAP_GROUP_SCOPE_MAPPING[2]
							logger.debug(passthroughSum)
							logger.debug(group_dict[key])
							# Change to Universal Scope
							self.ldap_connection.modify(
								distinguished_name,
								{key: [(operation, [passthroughSum])]},
							)
							# Change to Target Scope (Global or Domain Local)
							self.ldap_connection.modify(
								distinguished_name,
								{key: [(operation, [group_dict[key]])]},
							)
						else:
							self.ldap_connection.modify(
								distinguished_name,
								{key: [(operation, [group_dict[key]])]},
							)
					else:
						if isinstance(group_dict[key], list):
							self.ldap_connection.modify(
								distinguished_name,
								{key: [(operation, group_dict[key])]},
							)
						else:
							self.ldap_connection.modify(
								distinguished_name,
								{key: [(operation, [group_dict[key]])]},
							)
				else:
					logger.info("No suitable operation for attribute " + key)
					pass
			except:
				logger.error(traceback.format_exc())
				logger.warning(
					"Unable to update group '%s' with attribute '%s'", str(group_cn), str(key)
				)
				logger.warning("Attribute Value:" + str(group_dict[key]))
				if operation is not None:
					logger.warning("Operation Type: " + str(operation))
				self.ldap_connection.unbind()
				raise exc_groups.GroupUpdate

		logger.debug(self.ldap_connection.result)

		if membersToAdd is not None:
			if len(membersToAdd) > 0:
				try:
					self.ldap_connection.extend.microsoft.add_members_to_groups(
						membersToAdd, distinguished_name
					)
				except Exception as e:
					self.ldap_connection.unbind()
					print(e)
					raise exc_groups.GroupMembersAdd

		if membersToRemove is not None:
			if len(membersToRemove) > 0:
				try:
					self.ldap_connection.extend.microsoft.remove_members_from_groups(
						membersToRemove, distinguished_name
					)
				except Exception as e:
					self.ldap_connection.unbind()
					print(e)
					raise exc_groups.GroupMembersRemove

		DBLogMixin.log(
			user=self.request.user.id,
			operation_type=LOG_ACTION_UPDATE,
			log_target_class=LOG_CLASS_GROUP,
			log_target=group_cn,
		)
		return self.ldap_connection

	def delete_group(self, group_data: dict, unbind_on_error: bool = True):
		if "cn" not in group_data:
			logger.error(group_data)
			if unbind_on_error:
				self.ldap_connection.unbind()
			raise exc_groups.GroupDoesNotExist

		if "distinguishedName" in group_data:
			distinguishedName = group_data["distinguishedName"]
		else:
			logger.error(group_data)
			if unbind_on_error:
				self.ldap_connection.unbind()
			raise exc_groups.GroupDoesNotExist

		if str(group_data["cn"]).startswith("Domain "):
			logger.error(group_data)
			if unbind_on_error:
				self.ldap_connection.unbind()
			raise exc_groups.GroupBuiltinProtect

		try:
			self.ldap_connection.delete(distinguishedName)
		except:
			self.ldap_connection.unbind()
			data = {"ldap_response": self.ldap_connection.result}
			raise exc_groups.GroupDelete(data=data)

		with transaction.atomic():
			asg_queryset = ApplicationSecurityGroup.objects.filter(
				ldap_objects__contains=[distinguishedName]
			)
			if asg_queryset.count() > 0:
				for asg in list(asg_queryset):
					asg.ldap_objects.remove(distinguishedName)
					asg.save()

		DBLogMixin.log(
			user=self.request.user.id,
			operation_type=LOG_ACTION_DELETE,
			log_target_class=LOG_CLASS_GROUP,
			log_target=group_data["cn"],
		)
		return self.ldap_connection
