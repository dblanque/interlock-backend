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
from core.ldap.types.group import (
	LDAPGroupTypes,
	LDAP_GROUP_SCOPE_MAPPING,
	LDAP_GROUP_TYPE_MAPPING,
	MAPPED_GROUP_TYPE_DISTRIBUTION,
	MAPPED_GROUP_TYPE_SECURITY,
	MAPPED_GROUP_SCOPE_GLOBAL,
	MAPPED_GROUP_SCOPE_DOMAIN_LOCAL,
	MAPPED_GROUP_SCOPE_UNIVERSAL,
)
from core.ldap.security_identifier import SID
from core.ldap.connector import LDAPConnector
from core.config.runtime import RuntimeSettings

### Models
from core.views.mixins.logs import LogMixin
from core.models.application import ApplicationSecurityGroup

### LDAP3
import ldap3
from ldap3 import MODIFY_DELETE, MODIFY_REPLACE, Entry as LDAPEntry, Connection
from ldap3.extend import (
	ExtendedOperationsRoot,
	MicrosoftExtendedOperations,
)

### Core
from core.ldap.constants import (
	LDAP_ATTR_DN,
	LDAP_ATTR_FIRST_NAME,
	LDAP_ATTR_LAST_NAME,
	LDAP_ATTR_OBJECT_CATEGORY,
	LDAP_ATTR_OBJECT_CLASS,
	LDAP_ATTR_COMMON_NAME,
	LDAP_ATTR_EMAIL,
	LDAP_ATTR_GROUP_MEMBERS,
	LDAP_ATTR_SECURITY_ID,
	LDAP_ATTR_RELATIVE_ID,
	LDAP_ATTR_GROUP_TYPE,
	LOCAL_LDAP_ATTR_GROUP_SCOPE,
)
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
from core.exceptions import (
	ldap as exc_ldap,
	groups as exc_groups,
	dirtree as exc_dirtree,
)

### Others
from rest_framework.request import Request
from ldap3.utils.dn import safe_dn, safe_rdn
from core.views.mixins.utils import getldapattrvalue
from typing import List, TypedDict, Required, NotRequired, Literal
from django.db import transaction
import logging
################################################################################

DBLogMixin = LogMixin()
logger = logging.getLogger(__name__)


class GroupDict(TypedDict):
	cn: str
	member: list[str]
	path: str
	distinguishedName: str
	objectSid: str
	objectRid: int
	groupType: Literal[0, 1]
	groupScope: Literal[0, 1, 2]
	membersToAdd: list[str]
	membersToRemove: list[str]
	mail: str


class GroupViewMixin(viewsets.ViewSetMixin):
	ldap_connection: Connection = None
	ldap_filter_object = None
	ldap_filter_attr = None
	request: Request

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
			sum -= LDAPGroupTypes.TYPE_SECURITY.value
			result.append(LDAPGroupTypes.TYPE_SECURITY.name)

			if (group_type_last_int % 2) != 0:
				sum += LDAPGroupTypes.TYPE_SYSTEM.value
				result.append(LDAPGroupTypes.TYPE_SYSTEM.name)
			if group_type == (sum + 2):
				sum += LDAPGroupTypes.SCOPE_GLOBAL.value
				result.append(LDAPGroupTypes.SCOPE_GLOBAL.name)
			if group_type == (sum + 4):
				sum += LDAPGroupTypes.SCOPE_DOMAIN_LOCAL.value
				result.append(LDAPGroupTypes.SCOPE_DOMAIN_LOCAL.name)
			if group_type == (sum + 8):
				sum += LDAPGroupTypes.SCOPE_UNIVERSAL.value
				result.append(LDAPGroupTypes.SCOPE_UNIVERSAL.name)
		else:
			result.append(LDAPGroupTypes.TYPE_DISTRIBUTION.name)

			if (group_type_last_int % 2) != 0:
				sum += LDAPGroupTypes.TYPE_SYSTEM.value
				result.append(LDAPGroupTypes.TYPE_SYSTEM.name)
			if group_type == (sum + 2):
				sum += LDAPGroupTypes.SCOPE_GLOBAL.value
				result.append(LDAPGroupTypes.SCOPE_GLOBAL.name)
			if group_type == (sum + 4):
				sum += LDAPGroupTypes.SCOPE_DOMAIN_LOCAL.value
				result.append(LDAPGroupTypes.SCOPE_DOMAIN_LOCAL.name)
			if group_type == (sum + 8):
				sum += LDAPGroupTypes.SCOPE_UNIVERSAL.value
				result.append(LDAPGroupTypes.SCOPE_UNIVERSAL.name)

		if sum != group_type:
			raise ValueError("Invalid group type integer")

		if debug:
			return (
				result,
				group_type,
			)
		else:
			return result

	@staticmethod
	def get_group_by_rid(
		rid: int = None, attributes: List[str] = None
	) -> dict | None:
		if not attributes:
			attributes = [LDAP_ATTR_SECURITY_ID, LDAP_ATTR_DN]
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
				search_filter=LDAPFilter.eq(
					LDAP_ATTR_OBJECT_CLASS, "group").to_string(),
				search_scope=ldap3.SUBTREE,
				attributes=attributes,
			)

			for g in connection.entries:
				g: LDAPEntry
				# Do not use getldapattr here, we want raw_values
				_sid_attr = getattr(g, LDAP_ATTR_SECURITY_ID, None)
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
		headers: List[str] = self.ldap_filter_attr
		remove_attributes = [LDAP_ATTR_DN, LDAP_ATTR_GROUP_MEMBERS]

		for attr in remove_attributes:
			if attr in headers:
				headers.remove(attr)

		for group_entry in ldap_entries:
			group_entry: LDAPEntry
			# For each attribute in group object attributes
			group_dict = {}
			# Add entry DN to response dictionary
			group_dict[LDAP_ATTR_DN] = group_entry.entry_dn

			for attr_key in group_entry.entry_attributes:
				# Parse Group Type
				if attr_key == LDAP_ATTR_GROUP_TYPE:
					group_dict[attr_key] = self.get_group_types(
						group_type=int(getldapattrvalue(group_entry, attr_key))
					)
				# Do the standard for every other key
				elif attr_key in headers:
					group_dict[attr_key] = getldapattrvalue(
						group_entry, attr_key, None
					)

			# Check if group has Members
			if getldapattrvalue(group_entry, LDAP_ATTR_GROUP_MEMBERS, None):
				group_dict["hasMembers"] = True
			else:
				group_dict["hasMembers"] = False

			data.append(group_dict)

		# Add hasMembers header
		headers.append("hasMembers")

		DBLogMixin.log(
			user=self.request.user.id,
			operation_type=LOG_ACTION_READ,
			log_target_class=LOG_CLASS_GROUP,
			log_target=LOG_TARGET_ALL,
		)
		return data, headers

	def fetch_group(self):
		self.ldap_connection.search(
			search_base=RuntimeSettings.LDAP_AUTH_SEARCH_BASE,
			search_filter=self.ldap_filter_object,
			attributes=self.ldap_filter_attr,
		)
		ldap_group_entry: LDAPEntry = self.ldap_connection.entries[0]

		# Remove attributes to return as table headers
		headers: list[str] = self.ldap_filter_attr
		headers.remove(LDAP_ATTR_DN)

		# For each attribute in group object attributes
		group_dict = {}
		# Add entry DN to response dictionary
		group_dict[LDAP_ATTR_DN] = ldap_group_entry.entry_dn

		for attr_key in ldap_group_entry.entry_attributes:
			if not attr_key in headers:
				continue

			attr_value = getldapattrvalue(ldap_group_entry, attr_key, None)
			# Parse Group Type
			if attr_key == LDAP_ATTR_GROUP_TYPE:
				group_type = int(attr_value)
				group_dict[attr_key] = self.get_group_types(
					group_type=group_type
				)
			elif attr_key == LDAP_ATTR_GROUP_MEMBERS:
				_username_field = RuntimeSettings.LDAP_AUTH_USER_FIELDS[
					"username"
				]
				attr_members = (
					attr_value if isinstance(attr_value, list) else [attr_value]
				)
				member_list = []

				# Fetch members
				for member_user_dn in attr_members:
					member_list.append(
						LDAPObject(
							**{
								"connection": self.ldap_connection,
								"dn": member_user_dn,
								"ldap_attrs": [
									LDAP_ATTR_COMMON_NAME,
									LDAP_ATTR_DN,
									_username_field,
									LDAP_ATTR_FIRST_NAME,
									LDAP_ATTR_LAST_NAME,
									LDAP_ATTR_OBJECT_CATEGORY,
									LDAP_ATTR_OBJECT_CLASS,
								],
							}
						).attributes
					)
				group_dict[attr_key] = member_list
			# Do the standard for every other key
			elif attr_key == LDAP_ATTR_SECURITY_ID:
				# Don't use getldapattr for the sid, we need raw bytes
				sid = SID(getattr(ldap_group_entry, attr_key))
				sid = sid.__str__()
				rid = sid.split("-")[-1]
				group_dict[attr_key] = sid
				group_dict[LDAP_ATTR_RELATIVE_ID] = int(rid)
			else:
				group_dict[attr_key] = attr_value

		DBLogMixin.log(
			user=self.request.user.id,
			operation_type=LOG_ACTION_READ,
			log_target_class=LOG_CLASS_GROUP,
			log_target=group_dict[LDAP_ATTR_COMMON_NAME],
		)
		return group_dict, headers

	def create_group(
		self,
		group_data: GroupDict,
		exclude_keys=None,
	) -> Connection:
		if not exclude_keys:
			exclude_keys = [LDAP_ATTR_GROUP_MEMBERS, "path", "membersToAdd"]
		# Type hinting defs
		extended_operations: ExtendedOperationsRoot = (
			self.ldap_connection.extend
		)
		eo_microsoft: MicrosoftExtendedOperations = (
			extended_operations.microsoft
		)
		group_cn: str = group_data.get(LDAP_ATTR_COMMON_NAME, None)
		if not group_cn:
			raise ValueError("group_cn cannot be None or falsy value.")

		group_path = group_data.get("path", None)
		if group_path:
			distinguished_name = f"CN={group_cn},{group_path}"
			logger.debug(f"Creating group in DN Path: {group_path}")
		else:
			distinguished_name = "CN=%s,CN=Users,%s" % (
				group_cn,
				RuntimeSettings.LDAP_AUTH_SEARCH_BASE,
			)

		group_data[RuntimeSettings.LDAP_GROUP_FIELD] = group_cn.lower()

		# !!! CHECK IF GROUP EXISTS !!! #
		# If group exists, return error
		self.ldap_connection.search(
			search_base=RuntimeSettings.LDAP_AUTH_SEARCH_BASE,
			search_filter=self.ldap_filter_object,
			search_scope=ldap3.SUBTREE,
			attributes=self.ldap_filter_attr,
		)
		if self.ldap_connection.entries:
			raise exc_ldap.LDAPObjectExists(data={"group": group_data[LDAP_ATTR_COMMON_NAME]})

		# Change group type if necessary
		group_type = group_data.pop(LDAP_ATTR_GROUP_TYPE, None)
		group_scope = group_data.pop(LOCAL_LDAP_ATTR_GROUP_SCOPE, None)
		if (group_type is not None and group_scope is None) or (
			group_type is None and group_scope is not None
		):
			raise exc_groups.GroupTypeMissingField
		group_data[LDAP_ATTR_GROUP_TYPE] = (
			LDAP_GROUP_TYPE_MAPPING[int(group_type)]
			+ LDAP_GROUP_SCOPE_MAPPING[int(group_scope)]
		)

		members_to_add = group_data.pop("membersToAdd", [])
		for _key in exclude_keys:
			logger.debug("Removing key from dictionary: " + _key)
			group_data.pop(_key, None)

		try:
			self.ldap_connection.add(
				dn=distinguished_name,
				object_class="group",
				attributes=group_data,
			)
		except Exception as e:
			logger.exception(e)
			raise exc_groups.GroupCreate(
				data={"ldap_response": self.ldap_connection.result}
			)

		if members_to_add:
			try:
				eo_microsoft.add_members_to_groups(
					members_to_add, distinguished_name
				)
			except Exception as e:
				logger.exception(e)
				group_data = {"ldap_response": self.ldap_connection.result}
				raise exc_groups.GroupMembersAdd

		DBLogMixin.log(
			user=self.request.user.id,
			operation_type=LOG_ACTION_CREATE,
			log_target_class=LOG_CLASS_GROUP,
			log_target=group_data[LDAP_ATTR_COMMON_NAME],
		)
		return self.ldap_connection

	def update_group_type(
		self,
		distinguished_name: str,
		selected_scope: int,
		selected_type: int,
		new_group_type: int,
		old_group_type: int,
	):
		"""Updates an LDAP Group's type and scope.

		Args:
			distinguished_name (str): The Group's SAFE Distinguished Name.
			selected_scope (int): Group scope key in LDAP_GROUP_SCOPE_MAPPING
			selected_type (int): Group type key in LDAP_GROUP_TYPE_MAPPING
			new_group_type (int): Group type as required by LDAP Spec.
			old_group_type (int): Previous group type integer.
		"""
		if not isinstance(distinguished_name, str):
			raise TypeError("distinguished_name must be of type str.")
		for arg, arg_value in [
			("selected_scope", selected_scope),
			("selected_type", selected_type),
			("new_group_type", new_group_type),
			("old_group_type", old_group_type),
		]:
			if not isinstance(arg_value, int):
				raise TypeError(f"{arg} must be of type int.")

		if new_group_type != old_group_type:
			previous_group_type_names = self.get_group_types(
				group_type=old_group_type
			)

			# If we're trying to go from Group Global to Domain Local Scope
			# or viceversa, we need to make it universal first, otherwise
			# the LDAP server denies the update request.
			#
			# Sucks but we have to do this :/
			if (
				LDAPGroupTypes.SCOPE_GLOBAL.name in previous_group_type_names
				and selected_scope == MAPPED_GROUP_SCOPE_DOMAIN_LOCAL
			) or (
				LDAPGroupTypes.SCOPE_DOMAIN_LOCAL.name
				in previous_group_type_names
				and selected_scope == MAPPED_GROUP_SCOPE_GLOBAL
			):
				# Sum type and scope
				intermediate_group_type = (
					LDAP_GROUP_TYPE_MAPPING[selected_type]  # Group Type
					+ LDAP_GROUP_SCOPE_MAPPING[
						MAPPED_GROUP_SCOPE_UNIVERSAL
					]  # Universal
				)
				# Log if necessary
				logger.debug(intermediate_group_type)
				logger.debug(new_group_type)
				# Change to Universal Scope First
				self.ldap_connection.modify(
					distinguished_name,
					{
						LDAP_ATTR_GROUP_TYPE: [
							(MODIFY_REPLACE, [intermediate_group_type])
						]
					},
				)
				# Change to Target Scope (Global or Domain Local)
				self.ldap_connection.modify(
					distinguished_name,
					{LDAP_ATTR_GROUP_TYPE: [(MODIFY_REPLACE, [new_group_type])]},
				)
			else:
				self.ldap_connection.modify(
					distinguished_name,
					{LDAP_ATTR_GROUP_TYPE: [(MODIFY_REPLACE, [new_group_type])]},
				)

	def update_group(self, group_data: GroupDict):
		# Type hinting defs
		extended_operations: ExtendedOperationsRoot = (
			self.ldap_connection.extend
		)
		eo_microsoft: MicrosoftExtendedOperations = (
			extended_operations.microsoft
		)

		# Set Distinguished Name
		distinguished_name = group_data.get(LDAP_ATTR_DN, None)
		if not distinguished_name:
			raise exc_groups.GroupDistinguishedNameMissing
		else:
			try:
				safe_dn(distinguished_name)
			except:
				raise exc_ldap.DistinguishedNameValidationError

		# !!! CHECK IF GROUP EXISTS AND FETCH ATTRS !!! #
		# We need to fetch the existing LDAP group object to know what
		# kind of operation to apply when updating attributes
		try:
			fetched_group_attrs = LDAPObject(
				**{
					"connection": self.ldap_connection,
					"dn": distinguished_name,
					"ldap_attrs": self.ldap_filter_attr,
				}
			).attributes
		except:
			raise exc_groups.GroupDoesNotExist

		# Set Common Name
		original_cn = safe_rdn(distinguished_name)[0]
		group_cn: str = group_data.get(LDAP_ATTR_COMMON_NAME, None)
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
		group_data[RuntimeSettings.LDAP_GROUP_FIELD] = str(group_cn).lower()

		# Validate incorrect add-remove relationships
		members_to_add = group_data.pop("membersToAdd", [])
		members_to_remove = group_data.pop("membersToRemove", [])
		if members_to_add and members_to_remove:
			for g_add, g_remove in zip(members_to_add, members_to_remove):
				# g_add and g_remove should be distinguished names
				if g_add == g_remove:
					logger.error(
						f"Group Member {g_add} cannot be added and removed."
					)
					raise exc_groups.BadMemberSelection

		# Change group type if necessary
		group_type = group_data.pop(LDAP_ATTR_GROUP_TYPE, None)
		group_scope = group_data.pop(LOCAL_LDAP_ATTR_GROUP_SCOPE, None)
		if (group_type is not None and group_scope is None) or (
			group_type is None and group_scope is not None
		):
			raise exc_groups.GroupTypeMissingField

		# Only updates group type it if value has changed
		if group_type and group_scope:
			# Cast to int
			group_type = int(group_type)
			group_scope = int(group_scope)
			self.update_group_type(
				distinguished_name=distinguished_name,
				selected_scope=group_scope,
				selected_type=group_type,
				new_group_type=(
					LDAP_GROUP_TYPE_MAPPING[group_type]
					+ LDAP_GROUP_SCOPE_MAPPING[group_scope]
				),
				old_group_type=int(fetched_group_attrs[LDAP_ATTR_GROUP_TYPE]),
			)

		# Update EMAIL Attr if any
		group_email_attr = group_data.get(LDAP_ATTR_EMAIL, None)
		if group_email_attr is not None and fetched_group_attrs.get(
			LDAP_ATTR_EMAIL, None
		):
			try:
				if group_email_attr == "":
					self.ldap_connection.modify(
						distinguished_name,
						{LDAP_ATTR_EMAIL: [(MODIFY_DELETE, [])]},
					)
				else:
					self.ldap_connection.modify(
						distinguished_name,
						{LDAP_ATTR_EMAIL: [(MODIFY_REPLACE, [group_email_attr])]},
					)
			except Exception as e:
				logger.exception(e)
				raise exc_groups.GroupUpdate

		logger.debug(self.ldap_connection.result)
		if members_to_add:
			try:
				eo_microsoft.add_members_to_groups(
					members_to_add, distinguished_name
				)
			except Exception as e:
				logger.exception(e)
				raise exc_groups.GroupMembersAdd

		if members_to_remove:
			try:
				eo_microsoft.remove_members_from_groups(
					members_to_remove, distinguished_name
				)
			except Exception as e:
				logger.exception(e)
				raise exc_groups.GroupMembersRemove

		DBLogMixin.log(
			user=self.request.user.id,
			operation_type=LOG_ACTION_UPDATE,
			log_target_class=LOG_CLASS_GROUP,
			log_target=group_cn,
		)
		return self.ldap_connection

	def delete_group(self, group_data: GroupDict):
		distinguished_name = group_data.get(LDAP_ATTR_DN, None)
		if not distinguished_name:
			logger.error(group_data)
			raise exc_ldap.DistinguishedNameValidationError

		# !!! CHECK IF GROUP EXISTS AND FETCH ATTRS !!! #
		# We need to fetch the existing LDAP group object to know what
		# kind of operation to apply when updating attributes
		try:
			fetched_group_attrs = LDAPObject(
				**{
					"connection": self.ldap_connection,
					"dn": distinguished_name,
					"ldap_attrs": self.ldap_filter_attr,
				}
			).attributes
		except:
			raise exc_groups.GroupDoesNotExist

		# Check if group is a builtin object
		group_cn: str = fetched_group_attrs[LDAP_ATTR_COMMON_NAME]
		if group_cn.lower().startswith("cn="):
			group_cn = group_cn.split("=")[-1]

		if group_cn.lower() not in distinguished_name.lower():
			raise exc_ldap.DistinguishedNameValidationError

		group_types = self.get_group_types(
			group_type=int(fetched_group_attrs[LDAP_ATTR_GROUP_TYPE])
		)
		if (
			LDAPGroupTypes.TYPE_SYSTEM.name in group_types
			or group_cn.lower().startswith("domain ")
		):
			raise exc_groups.GroupBuiltinProtect

		try:
			self.ldap_connection.delete(dn=distinguished_name)
		except:
			raise exc_groups.GroupDelete(
				data={"ldap_response": self.ldap_connection.result}
			)

		with transaction.atomic():
			asg_queryset = ApplicationSecurityGroup.objects.filter(
				ldap_objects__contains=[distinguished_name]
			)
			if asg_queryset.count() > 0:
				for asg in list(asg_queryset):
					asg.ldap_objects.remove(distinguished_name)
					asg.save()

		DBLogMixin.log(
			user=self.request.user.id,
			operation_type=LOG_ACTION_DELETE,
			log_target_class=LOG_CLASS_GROUP,
			log_target=group_cn,
		)
		return self.ldap_connection
