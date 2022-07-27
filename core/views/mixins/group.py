from rest_framework import viewsets
from interlock_backend.ldap.adsi import bin_as_hex
from interlock_backend.ldap.groupTypes import LDAP_GROUP_TYPES
import logging

logger = logging.getLogger(__name__)
class GroupViewMixin(viewsets.ViewSetMixin):

    def getGroupType(self, groupTypeInt=None, groupTypeIntAsBin=None):
        i = 0
        groupTypes = []
        if groupTypeInt is None and groupTypeIntAsBin is None:
            raise Exception
        if groupTypeIntAsBin is None:
            groupTypeInt = str(groupTypeInt)
            groupTypeInt = int(groupTypeInt)
            groupTypeIntAsBin = str(bin(groupTypeInt))[3:].zfill(32)

        groupTypeIntAsBin = str(groupTypeIntAsBin)
        for n in range(0, 32): # Loop for each bit in 0-32
            i += 1
            if groupTypeIntAsBin[n] == "1": # If permission matches enter for loop to 
                                        # search which one it is in the dictionary
                for perm_name in LDAP_GROUP_TYPES:
                    perm_binary = LDAP_GROUP_TYPES[perm_name]['val_bin']
                    perm_index = LDAP_GROUP_TYPES[perm_name]['index']
                    if perm_index == n:
                        logger.debug("Group Int: " + groupTypeIntAsBin)
                        logger.debug("Permission Name: " + perm_name)
                        logger.debug("Permission Index: " + str(perm_index))
                        logger.debug("Permission Index (From User): " + str(n))
                        logger.debug("Permission Binary Value (From Constant): " + perm_binary)
                        logger.debug("Permission Hex Value (From Constant): " + bin_as_hex(perm_binary))
                        groupTypes.append(perm_name)
        return groupTypes

    pass