################################################################################
#################### INTERLOCK IS LICENSED UNDER GNU AGPLv3 ####################
################## ORIGINAL PROJECT CREATED BY DYLAN BLANQUÉ ###################
########################## AND BR CONSULTING S.R.L. ############################
################################################################################
# Module: core.views.mixins.group
# Contains the Mixin for Group related operations

#---------------------------------- IMPORTS -----------------------------------#
### ViewSets
from rest_framework import viewsets

### Interlock
from interlock_backend.ldap.adsi import search_filter_add
from interlock_backend.ldap.groupTypes import LDAP_GROUP_TYPES
from interlock_backend.ldap.securityIdentifier import SID
from interlock_backend.ldap.connector import LDAPConnector
from core.models.ldap_settings_runtime import RuntimeSettings

### Models
from core.views.mixins.logs import LogMixin
from core.models.application import ApplicationSecurityGroup

### Core
from core.exceptions.ldap import CouldNotOpenConnection
from core.models.ldap_object import LDAPObject
from core.views.mixins.ldap.organizational_unit import OrganizationalUnitMixin

### Exceptions
import traceback
from core.exceptions import ldap as exc_ldap, groups as exc_groups, dirtree as exc_dirtree

### Others
from django.db import transaction
from copy import deepcopy
import ldap3
from ldap3 import (
	MODIFY_DELETE,
	MODIFY_REPLACE
)
import logging
################################################################################

DBLogMixin = LogMixin()
logger = logging.getLogger(__name__)
class GroupViewMixin(viewsets.ViewSetMixin):
	ldap_connection = None
	ldap_filter_object = None
	ldap_filter_attr = None

	def getGroupByRID(ridToSearch=None, attributes=['objectSid','distinguishedName']):
		if ridToSearch is None:
			raise ValueError("RID To Search cannot be None")

		# Cast to Integer just in case
		try:
			ridToSearch = int(ridToSearch)
		except Exception as e:
			print(ridToSearch)
			print(e)
			raise ValueError("RID To Search must be an Integer")

		# Open LDAP Connection
		try:
			ldapConnection = LDAPConnector(force_admin=True).connection
		except Exception as e:
			print(e)
			raise CouldNotOpenConnection

		searchFilter = search_filter_add("", "objectClass=group")

		ldapConnection.search(
			RuntimeSettings.LDAP_AUTH_SEARCH_BASE,
			search_filter=searchFilter,
			search_scope=ldap3.SUBTREE,
			attributes=attributes,
		)

		for g in ldapConnection.entries:
			sid = SID(g.objectSid)
			sid = sid.__str__()
			rid = int(sid.split("-")[-1])
			value = sid
			if rid == ridToSearch:
				args = {
					"connection": ldapConnection,
					"dn": g.distinguishedName,
					"ldapAttributes": attributes
				}
				result = LDAPObject(**args)
				ldapConnection.unbind()
				return result.attributes

	def getGroupType(self, groupTypeInt=None, debug=False):
		sum = 0
		groupTypes = []
		groupTypeLastInt = int(str(groupTypeInt)[-1])
		if groupTypeInt != 0 and groupTypeInt is None:
			self.ldap_connection.unbind()
			raise ValueError("Invalid Group Type Integer")
		if groupTypeInt < -1:
			sum -= LDAP_GROUP_TYPES['GROUP_SECURITY']
			groupTypes.append('GROUP_SECURITY')

			if (groupTypeLastInt % 2) != 0:
				sum += LDAP_GROUP_TYPES['GROUP_SYSTEM']
				groupTypes.append('GROUP_SYSTEM')
			if groupTypeInt == (sum + 2):
				sum += LDAP_GROUP_TYPES['GROUP_GLOBAL']
				groupTypes.append('GROUP_GLOBAL')
			if groupTypeInt == (sum + 4):
				sum += LDAP_GROUP_TYPES['GROUP_DOMAIN_LOCAL']
				groupTypes.append('GROUP_DOMAIN_LOCAL')
			if groupTypeInt == (sum + 8):
				sum += LDAP_GROUP_TYPES['GROUP_UNIVERSAL']
				groupTypes.append('GROUP_UNIVERSAL')
		else:
			groupTypes.append('GROUP_DISTRIBUTION')

			if (groupTypeLastInt % 2) != 0:
				sum += LDAP_GROUP_TYPES['GROUP_SYSTEM']
				groupTypes.append('GROUP_SYSTEM')
			if groupTypeInt == (sum + 2):
				sum += LDAP_GROUP_TYPES['GROUP_GLOBAL']
				groupTypes.append('GROUP_GLOBAL')
			if groupTypeInt == (sum + 4):
				sum += LDAP_GROUP_TYPES['GROUP_DOMAIN_LOCAL']
				groupTypes.append('GROUP_DOMAIN_LOCAL')
			if groupTypeInt == (sum + 8):
				sum += LDAP_GROUP_TYPES['GROUP_UNIVERSAL']
				groupTypes.append('GROUP_UNIVERSAL')

		if sum != groupTypeInt:
			return Exception
		
		for k, v in enumerate(groupTypes):
			if v == 'GROUP_SYSTEM':
				groupTypes.pop(k)
				groupTypes.append(v)

		if debug == True:
			return [ groupTypes, groupTypeInt ]
		else:
			return groupTypes
		
	def list_groups(self):
		data = []
		self.ldap_connection.search(
			RuntimeSettings.LDAP_AUTH_SEARCH_BASE, 
			self.ldap_filter_object,
			attributes=self.ldap_filter_attr
		)
		ldap_entries = self.ldap_connection.entries

		# Remove attributes to return as table headers
		valid_attributes = self.ldap_filter_attr
		remove_attributes = [
			'distinguishedName',
			'member'
		]

		for attr in remove_attributes:
			if attr in valid_attributes:
				valid_attributes.remove(str(attr))

		for group in ldap_entries:
			# For each attribute in group object attributes
			group_dict = {}
			for attr_key in dir(group):
				# Parse Group Type
				if attr_key == 'groupType':
					groupVal = int(str(getattr(group, attr_key)))
					group_dict[attr_key] = self.getGroupType(groupTypeInt=groupVal)
				# Do the standard for every other key
				elif attr_key in valid_attributes:
					str_key = str(attr_key)
					str_value = str(getattr(group, attr_key))
					if str_value == "[]":
						group_dict[str_key] = ""
					else:
						group_dict[str_key] = str_value

			# Check if group has Members
			if str(getattr(group, 'member')) == "[]" or getattr(group, 'member') is None:
				group_dict['hasMembers'] = False
			else:
				group_dict['hasMembers'] = True

			# Add entry DN to response dictionary
			group_dict['distinguishedName'] = group.entry_dn

			data.append(group_dict)

		valid_attributes.append('hasMembers')

		if RuntimeSettings.LDAP_LOG_READ == True:
			# Log this action to DB
			DBLogMixin.log(
				user_id=self.request.user.id,
				actionType="READ",
				objectClass="GROUP",
				affectedObject="ALL"
			)
		return data, valid_attributes

	def fetch_group(self):
		self.ldap_connection.search(
			RuntimeSettings.LDAP_AUTH_SEARCH_BASE, 
			self.ldap_filter_object,
			attributes=self.ldap_filter_attr
		)
		group = self.ldap_connection.entries

		# Remove attributes to return as table headers
		valid_attributes = self.ldap_filter_attr
		remove_attributes = [
			'distinguishedName',
			# 'member'
		]

		for attr in remove_attributes:
			if attr in valid_attributes:
				valid_attributes.remove(str(attr))

		# For each attribute in group object attributes
		group_dict = {}
		for attr_key in dir(group[0]):
			if attr_key in valid_attributes:
				str_key = str(attr_key)
				realValue = getattr(group[0],attr_key)
				str_value = str(realValue)
				if str_value == "[]":
					group_dict[str_key] = ""
				# Parse Group Type
				elif str_key == 'groupType':
					groupVal = int(str(getattr(group[0], str_key)))
					group_dict[str_key] = self.getGroupType(groupTypeInt=groupVal)
				elif str_key == 'member':
					memberArray = []
					memberAttributes = [
						'cn',
						'distinguishedName',
						RuntimeSettings.LDAP_AUTH_USER_FIELDS["username"],
						'givenName',
						'sn',
						'objectCategory',
						'objectClass'
					]
					# Fetch members
					for u in getattr(group[0], str_key):
						args = {
							"connection": self.ldap_connection,
							"dn": u,
							"ldapAttributes": memberAttributes
						}
						memberObject = LDAPObject(**args)
						self.ldap_connection = memberObject.__getConnection__()
						memberArray.append(memberObject.attributes)
					group_dict[str_key] = memberArray
				# Do the standard for every other key
				elif str_key == 'objectSid':
					sid = SID(realValue)
					sid = sid.__str__()
					rid = sid.split("-")[-1]
					group_dict[str_key] = sid
					group_dict['objectRid'] = int(rid)
				else:
					group_dict[str_key] = str_value

				if group_dict[str_key] == "":
					del group_dict[str_key]

			# Add entry DN to response dictionary
			group_dict['distinguishedName'] = str(group[0].entry_dn)

		if RuntimeSettings.LDAP_LOG_READ == True:
			# Log this action to DB
			DBLogMixin.log(
				user_id=self.request.user.id,
				actionType="READ",
				objectClass="GROUP",
				affectedObject=group_dict['cn']
			)
		return group_dict, valid_attributes

	def create_group(self, group_data: dict, exclude_keys=['member', 'path']):
		if group_data['path'] is not None and group_data['path'] != "":
			distinguishedName = "cn=" + group_data['cn'] + "," + group_data['path']
		else:
			distinguishedName = 'CN='+group_data['cn']+',OU=Users,'+RuntimeSettings.LDAP_AUTH_SEARCH_BASE

		group_data[RuntimeSettings.LDAP_GROUP_FIELD] = str(group_data['cn']).lower()

		args = {
			"connection": self.ldap_connection,
			"ldapFilter": self.ldap_filter_object,
			"ldapAttributes": self.ldap_filter_attr,
			"hideErrors": True
		}

		# !!! CHECK IF GROUP EXISTS !!! #
		try:
			groupExists = LDAPObject(**args).attributes
			groupExists = len(groupExists) > 0
		except:
			groupExists = False

		# If group exists, return error
		if groupExists == True:
			self.ldap_connection.unbind()
			group_data = {
				"group": group_data['cn']
			}
			raise exc_ldap.LDAPObjectExists(data=group_data)

		# Set group Type
		if 'groupType' not in group_data or 'groupScope' not in group_data:
			self.ldap_connection.unbind()
			group_data = {
				"group": group_data['cn']
			}
			raise exc_groups.GroupScopeOrTypeMissing(data=group_data)

		sum = RuntimeSettings.LDAP_GROUP_TYPE_MAPPING[int(group_data['groupType'])]
		sum += RuntimeSettings.LDAP_GROUP_SCOPE_MAPPING[int(group_data['groupScope'])]
		group_data['groupType'] = sum
		group_data.pop('groupScope')

		group_dict = deepcopy(group_data)
		for key in group_data:
			if key in exclude_keys:
				logger.debug("Removing key from dictionary: " + key)
				group_dict.pop(key)

		group_dict['cn'] = group_dict['cn']
		if 'membersToAdd' in group_dict:
			membersToAdd = group_dict.pop('membersToAdd')
		else:
			membersToAdd = []

		logger.debug('Creating group in DN Path: ' + group_data['path'])
		try:
			self.ldap_connection.add(distinguishedName, 'group', attributes=group_dict)
		except Exception as e:
			self.ldap_connection.unbind()
			print(e)
			group_data = {
				"ldap_response": self.ldap_connection.result
			}
			raise exc_groups.GroupCreate(data=group_data)

		if len(membersToAdd) > 0:
			try:
				self.ldap_connection.extend.microsoft.add_members_to_groups(membersToAdd, distinguishedName)
			except Exception as e:
				try:
					self.ldap_connection.delete(distinguishedName)
					group_data = {
						"ldap_response": self.ldap_connection.result
					}
					raise exc_groups.GroupMembersAdd
				except Exception as e:
					self.ldap_connection.unbind()
				self.ldap_connection.unbind()
				print(e)
				group_data = {
					"ldap_response": self.ldap_connection.result
				}
				raise exc_groups.GroupMembersAdd

		if RuntimeSettings.LDAP_LOG_CREATE == True:
			# Log this action to DB
			DBLogMixin.log(
				user_id=self.request.user.id,
				actionType="CREATE",
				objectClass="GROUP",
				affectedObject=group_dict['cn']
			)
		return self.ldap_connection

	def update_group(self, group_data: dict, unbind_on_error: bool = True):
		data = self.request.data
		group_cn = None

		# Set Distinguished Name
		if 'distinguishedName' not in group_data:
			if unbind_on_error: self.ldap_connection.unbind()
			raise exc_groups.GroupDistinguishedNameMissing
		else:
			distinguished_name: str = group_data['distinguishedName']
			relative_dn: str = distinguished_name.split(",")[0]

		# Set Common Name
		if 'cn' not in group_data:
			group_cn = relative_dn
		# If Group CN was modified
		else:
			group_cn = f"CN={group_data['cn']}"
			relative_dn = group_cn
			if relative_dn == distinguished_name:
				raise exc_dirtree.DirtreeDistinguishedNameConflict
			try:
				distinguished_name = OrganizationalUnitMixin.move_or_rename_object(
					self,
					distinguished_name=distinguished_name,
					relative_dn=group_cn
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
			"ldapAttributes": self.ldap_filter_attr,
			"hideErrors": True
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
			data = {
				"group": group_cn
			}
			raise exc_groups.GroupDoesNotExist(data=data)

		# Set group Type
		if 'groupType' not in group_data or 'groupScope' not in group_data:
			self.ldap_connection.unbind()
			data = {
				"group": group_cn
			}
			raise exc_groups.GroupScopeOrTypeMissing(data=data)

		castGroupType = int(group_data['groupType'])
		castGroupScope = int(group_data['groupScope'])
		sum = RuntimeSettings.LDAP_GROUP_TYPE_MAPPING[castGroupType]
		sum += RuntimeSettings.LDAP_GROUP_SCOPE_MAPPING[castGroupScope]
		group_data['groupType'] = sum
		group_data.pop('groupScope')

		excludeKeys = [
			'cn',
			'member', 
			'path',
			'distinguishedName',
			'objectSid', # LDAP Bytes attr
			'objectRid' # LDAP Bytes attr
		]

		group_dict = deepcopy(group_data)
		for key in group_data:
			if key in excludeKeys:
				logger.debug("Removing key from dictionary: " + key)
				group_dict.pop(key)

		if 'membersToAdd' in data and 'membersToRemove' in data:
			if (
				data['membersToAdd'] == data['membersToRemove'] and
				data['membersToAdd']
			) != []:
				self.ldap_connection.unbind()
				logger.error(data)
				raise exc_groups.BadMemberSelection

		if 'membersToAdd' in group_dict:
			membersToAdd = group_dict.pop('membersToAdd')
		else:
			membersToAdd = None
		if 'membersToRemove' in group_dict:
			membersToRemove = group_dict.pop('membersToRemove')
		else:
			membersToRemove = None

		# We need to check if the attributes exist in the LDAP Object already
		# To know what operation to apply. This is VERY important.
		arguments = {}
		operation = None
		for key in group_dict:
				try:
					if key in fetched_group_entry and group_dict[key] == "" and key != 'groupType':
						operation = MODIFY_DELETE
						self.ldap_connection.modify(
							distinguished_name,
							{key: [( operation ), []]},
						)
					elif group_dict[key] != "":
						operation = MODIFY_REPLACE
						if key == 'groupType':
							previousGroupTypes = self.getGroupType(groupTypeInt=int(fetched_group_entry[key]))
							# If we're trying to go from Group Global to Domain Local Scope or viceversa
							# We need to make it universal first, otherwise the LDAP server denies the update request
							# Sucks but we have to do this :/
							if ('GROUP_GLOBAL' in previousGroupTypes and castGroupScope == 1) or ('GROUP_DOMAIN_LOCAL' in previousGroupTypes and castGroupScope == 0):
								passthroughSum = RuntimeSettings.LDAP_GROUP_TYPE_MAPPING[castGroupType]
								passthroughSum += RuntimeSettings.LDAP_GROUP_SCOPE_MAPPING[2]
								logger.debug(passthroughSum)
								logger.debug(group_dict[key])
								# Change to Universal Scope
								self.ldap_connection.modify(
									distinguished_name,
									{key: [( operation, [ passthroughSum ])]},
								)
								# Change to Target Scope (Global or Domain Local)
								self.ldap_connection.modify(
									distinguished_name,
									{key: [( operation, [ group_dict[key] ])]},
								)
							else:
								self.ldap_connection.modify(
									distinguished_name,
									{key: [( operation, [ group_dict[key] ])]},
								)
						else:
							if isinstance(group_dict[key], list):
								self.ldap_connection.modify(
									distinguished_name,
									{key: [( operation, group_dict[key])]},
								)
							else:
								self.ldap_connection.modify(
									distinguished_name,
									{key: [( operation, [ group_dict[key] ])]},
								)
					else:
						logger.info("No suitable operation for attribute " + key)
						pass
				except:
					logger.error(traceback.format_exc())
					logger.warning("Unable to update group '" + str(group_cn) + "' with attribute '" + str(key) + "'")
					logger.warning("Attribute Value:" + str(group_dict[key]))
					if operation is not None:
						logger.warning("Operation Type: " + str(operation))
					self.ldap_connection.unbind()
					raise exc_groups.GroupUpdate

		logger.debug(self.ldap_connection.result)

		if membersToAdd is not None:
			if len(membersToAdd) > 0:
				try:
					self.ldap_connection.extend.microsoft.add_members_to_groups(membersToAdd, distinguished_name)
				except Exception as e:
					self.ldap_connection.unbind()
					print(e)
					raise exc_groups.GroupMembersAdd

		if membersToRemove is not None:
			if len(membersToRemove) > 0:
				try:
					self.ldap_connection.extend.microsoft.remove_members_from_groups(membersToRemove, distinguished_name)
				except Exception as e:
					self.ldap_connection.unbind()
					print(e)
					raise exc_groups.GroupMembersRemove

		if RuntimeSettings.LDAP_LOG_UPDATE == True:
			# Log this action to DB
			DBLogMixin.log(
				user_id=self.request.user.id,
				actionType="UPDATE",
				objectClass="GROUP",
				affectedObject=group_cn
			)
		return self.ldap_connection

	def delete_group(self, group_data: dict, unbind_on_error: bool = True):
		if 'cn' not in group_data:
			logger.error(group_data)
			if unbind_on_error: self.ldap_connection.unbind()
			raise exc_groups.GroupDoesNotExist

		if 'distinguishedName' in group_data:
			distinguishedName = group_data['distinguishedName']
		else:
			logger.error(group_data)
			if unbind_on_error: self.ldap_connection.unbind()
			raise exc_groups.GroupDoesNotExist

		if str(group_data['cn']).startswith("Domain "):
			logger.error(group_data)
			if unbind_on_error: self.ldap_connection.unbind()
			raise exc_groups.GroupBuiltinProtect

		try:
			self.ldap_connection.delete(distinguishedName)
		except:
			self.ldap_connection.unbind()
			data = {
				"ldap_response": self.ldap_connection.result
			}
			raise exc_groups.GroupDelete(data=data)

		with transaction.atomic():
			asg_queryset = ApplicationSecurityGroup.objects.filter(
				ldap_objects__contains=[distinguishedName]
			)
			if asg_queryset.count() > 0:
				for asg in list(asg_queryset):
					asg.ldap_objects.remove(distinguishedName)
					asg.save()

		if RuntimeSettings.LDAP_LOG_DELETE == True:
			# Log this action to DB
			DBLogMixin.log(
				user_id=self.request.user.id,
				actionType="DELETE",
				objectClass="GROUP",
				affectedObject=group_data['cn']
			)
		return self.ldap_connection