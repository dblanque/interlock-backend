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
from core.ldap.types.group import LDAPGroupTypes
from core.ldap.security_identifier import SID
from core.ldap.connector import LDAPConnector
from core.config.runtime import RuntimeSettings

### Models
from core.views.mixins.logs import LogMixin
from core.models.application import ApplicationSecurityGroup

### LDAP3
import ldap3
from ldap3 import Entry as LDAPEntry, Connection

### Core
from core.constants.attrs import *
from core.models.choices.log import (
	LOG_ACTION_CREATE,
	LOG_ACTION_READ,
	LOG_ACTION_UPDATE,
	LOG_ACTION_DELETE,
	LOG_CLASS_GROUP,
	LOG_TARGET_ALL,
)
from core.ldap.filter import LDAPFilter
from core.models.ldap_group import LDAPGroup
from core.models.ldap_object import LDAPObject
from rest_framework import serializers

### Exceptions
from core.exceptions import (
	ldap as exc_ldap,
	groups as exc_groups,
)

### Others
from rest_framework.request import Request
from ldap3.utils.dn import safe_dn
from core.views.mixins.utils import getldapattrvalue
from typing import List, TypedDict, Literal
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
					LDAP_ATTR_OBJECT_CLASS, "group"
				).to_string(),
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

				result = LDAPGroup(
					connection=connection,
					distinguished_name=g.entry_dn,
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

		for group_entry in ldap_entries:
			group_entry: LDAPEntry
			group_obj = LDAPGroup(entry=group_entry)
			group_dict = group_obj.attributes

			# Check if group has Members
			if getldapattrvalue(group_entry, LDAP_ATTR_GROUP_MEMBERS, None):
				group_dict[LOCAL_ATTR_GROUP_HAS_MEMBERS] = True
			else:
				group_dict[LOCAL_ATTR_GROUP_HAS_MEMBERS] = False
			data.append(group_dict)

		# Remove attributes to return as table headers
		headers = (
			LOCAL_ATTR_NAME,
			LOCAL_ATTR_GROUP_TYPE,
			LOCAL_ATTR_GROUP_SCOPE,
			LOCAL_ATTR_GROUP_HAS_MEMBERS,
		)

		DBLogMixin.log(
			user=self.request.user.id,
			operation_type=LOG_ACTION_READ,
			log_target_class=LOG_CLASS_GROUP,
			log_target=LOG_TARGET_ALL,
		)
		return data, headers

	def fetch_group(self):
		_username_field = RuntimeSettings.LDAP_FIELD_MAP["username"]

		self.ldap_connection.search(
			search_base=RuntimeSettings.LDAP_AUTH_SEARCH_BASE,
			search_filter=self.ldap_filter_object,
			attributes=self.ldap_filter_attr,
		)
		group_obj = LDAPGroup(entry=self.ldap_connection.entries[0])

		attr_members = getldapattrvalue(
			group_obj.entry, LDAP_ATTR_GROUP_MEMBERS, []
		)
		member_list = []
		if attr_members:
			attr_members = (
				attr_members
				if isinstance(attr_members, list)
				else [attr_members]
			)

			# Expand members to objects
			for member_user_dn in attr_members:
				member_list.append(
					LDAPObject(
						connection=self.ldap_connection,
						distinguished_name=member_user_dn,
						search_attrs=[
							LDAP_ATTR_COMMON_NAME,
							LDAP_ATTR_DN,
							_username_field,
							LDAP_ATTR_FIRST_NAME,
							LDAP_ATTR_LAST_NAME,
							LDAP_ATTR_OBJECT_CATEGORY,
							LDAP_ATTR_OBJECT_CLASS,
						],
					).attributes
				)
			group_obj.attributes[LOCAL_ATTR_GROUP_MEMBERS] = member_list

		group_dict = group_obj.attributes

		DBLogMixin.log(
			user=self.request.user.id,
			operation_type=LOG_ACTION_READ,
			log_target_class=LOG_CLASS_GROUP,
			log_target=group_dict[LOCAL_ATTR_NAME],
		)
		return group_dict

	def create_group(self, group_data: dict) -> Connection:
		group_name: str = group_data.get(LOCAL_ATTR_NAME, None)
		if not group_name:
			raise ValueError("group_cn cannot be None or falsy value.")

		group_path = group_data.pop(LOCAL_ATTR_PATH, None)
		if group_path:
			distinguished_name = f"CN={group_name},{group_path}"
			logger.debug(f"Creating group in DN Path: {group_path}")
		else:
			distinguished_name = "CN=%s,CN=Users,%s" % (
				group_name,
				RuntimeSettings.LDAP_AUTH_SEARCH_BASE,
			)

		# !!! CHECK IF GROUP EXISTS !!! #
		# If group exists, return error
		self.ldap_connection.search(
			search_base=RuntimeSettings.LDAP_AUTH_SEARCH_BASE,
			search_filter=self.ldap_filter_object,
			search_scope=ldap3.SUBTREE,
			attributes=self.ldap_filter_attr,
		)
		if self.ldap_connection.entries:
			raise exc_ldap.LDAPObjectExists(
				data={"group": group_data[LOCAL_ATTR_NAME]}
			)

		group_obj = LDAPGroup(
			connection=self.ldap_connection,
			attributes=group_data,
			distinguished_name=distinguished_name,
		)
		group_obj.save()

		DBLogMixin.log(
			user=self.request.user.id,
			operation_type=LOG_ACTION_CREATE,
			log_target_class=LOG_CLASS_GROUP,
			log_target=group_data[LOCAL_ATTR_NAME],
		)
		return self.ldap_connection

	def update_group(self, data: dict):
		# Set Distinguished Name
		distinguished_name = data.get(LOCAL_ATTR_DN, None)
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
		group_obj = LDAPGroup(
			connection=self.ldap_connection,
			distinguished_name=distinguished_name,
			search_attrs=self.ldap_filter_attr,
		)
		group_types = group_obj.attributes.get(LOCAL_ATTR_GROUP_TYPE, [])
		if LDAPGroupTypes.TYPE_SYSTEM.name in group_types:
			if not LDAPGroupTypes.TYPE_SYSTEM.name in data.get(
				LOCAL_ATTR_GROUP_TYPE
			):
				raise serializers.ValidationError(
					{
						LOCAL_ATTR_GROUP_TYPE: "System Group cannot have its SYSTEM flag removed."
					}
				)
		if not group_obj.exists:
			raise exc_groups.GroupDoesNotExist

		group_obj.attributes = data
		group_obj.save()

		DBLogMixin.log(
			user=self.request.user.id,
			operation_type=LOG_ACTION_UPDATE,
			log_target_class=LOG_CLASS_GROUP,
			log_target=group_obj.attributes.get(LOCAL_ATTR_NAME),
		)
		return self.ldap_connection

	def delete_group(self, group_data: GroupDict):
		distinguished_name = group_data.get(LOCAL_ATTR_DN, None)
		if not distinguished_name:
			logger.error(group_data)
			raise exc_ldap.DistinguishedNameValidationError

		# !!! CHECK IF GROUP EXISTS AND FETCH ATTRS !!! #
		# We need to fetch the existing LDAP group object to know what
		# kind of operation to apply when updating attributes
		group_obj = LDAPGroup(
			connection=self.ldap_connection,
			distinguished_name=distinguished_name,
			search_attrs=self.ldap_filter_attr,
		)
		if not group_obj.exists:
			raise exc_groups.GroupDoesNotExist

		# Check if group is a builtin object
		group_cn: str = group_obj.attributes.get(LOCAL_ATTR_NAME)
		if group_cn.lower().startswith("cn="):
			group_cn = group_cn.split("=")[-1]

		if group_cn.lower() not in distinguished_name.lower():
			raise exc_ldap.DistinguishedNameValidationError

		group_types = group_obj.attributes.get(LOCAL_ATTR_GROUP_TYPE)
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
