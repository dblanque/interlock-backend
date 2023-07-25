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
from interlock_backend.ldap.adsi import bin_as_hex, search_filter_add
from interlock_backend.ldap.groupTypes import LDAP_GROUP_TYPES
from interlock_backend.ldap.securityIdentifier import SID
from interlock_backend.ldap.connector import LDAPConnector
from interlock_backend.ldap.constants_cache import *

### Core
from core.exceptions.ldap import CouldNotOpenConnection
from core.models.ldapObject import LDAPObject

### Others
import ldap3
import logging
################################################################################

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
			ldapConnection = LDAPConnector().connection
		except Exception as e:
			print(e)
			raise CouldNotOpenConnection

		searchFilter = search_filter_add("", "objectClass=group")

		ldapConnection.search(
			LDAP_AUTH_SEARCH_BASE,
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
			raise Exception
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
		
	
