################################################################################
#################### INTERLOCK IS LICENSED UNDER GNU GPLv3 #####################
################## ORIGINAL PROJECT CREATED BY DYLAN BLANQUÉ ###################
########################## AND BR CONSULTING S.R.L. ############################
################################################################################
# Module: core.views.mixins.group
# Contains the Mixin for Group related operations

#---------------------------------- IMPORTS -----------------------------------#
### ViewSets
from rest_framework import viewsets

### Interlock
from interlock_backend.ldap.adsi import bin_as_hex, addSearchFilter
from interlock_backend.ldap.groupTypes import LDAP_GROUP_TYPES
from interlock_backend.ldap.securityIdentifier import SID
from interlock_backend.ldap.connector import LDAPConnector
from interlock_backend.ldap.settings_func import SettingsList

### Core
from core.exceptions.ldap import CouldNotOpenConnection
from core.models.ldapObject import LDAPObject

### Others
import ldap3
import logging
################################################################################

logger = logging.getLogger(__name__)
class GroupViewMixin(viewsets.ViewSetMixin):

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

        ######################## Get Latest Settings ###########################
        ldap_settings_list = SettingsList(**{"search":{
            'LDAP_AUTH_USERNAME_IDENTIFIER',
            'LDAP_AUTH_OBJECT_CLASS',
            'LDAP_AUTH_SEARCH_BASE',
            'LDAP_LOG_READ'
        }})

        # Open LDAP Connection
        try:
            ldapConnection = LDAPConnector().connection
        except Exception as e:
            print(e)
            raise CouldNotOpenConnection

        searchFilter = addSearchFilter("", "objectClass=group")

        ldapConnection.search(
            ldap_settings_list.LDAP_AUTH_SEARCH_BASE,
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

    pass