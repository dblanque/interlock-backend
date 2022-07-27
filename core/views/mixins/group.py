from rest_framework import viewsets
from interlock_backend.ldap.adsi import bin_as_hex
from interlock_backend.ldap.groupTypes import LDAP_GROUP_TYPES
import logging

logger = logging.getLogger(__name__)
class GroupViewMixin(viewsets.ViewSetMixin):

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