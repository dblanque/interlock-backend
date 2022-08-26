################################################################################
#################### INTERLOCK IS LICENSED UNDER GNU GPLv3 #####################
################## ORIGINAL PROJECT CREATED BY DYLAN BLANQUÉ ###################
########################## AND BR CONSULTING S.R.L. ############################
################################################################################
# Module: core.views.mixins.user
# Contains the Mixin for User related operations

#---------------------------------- IMPORTS -----------------------------------#
### ViewSets
from rest_framework import viewsets

### Interlock
from interlock_backend.ldap.adsi import addSearchFilter
from interlock_backend.ldap.constants_cache import *

### Models
from core.models.ldapObject import LDAPObject
################################################################################

class UserViewMixin(viewsets.ViewSetMixin):
    def getUserObjectFilter(self, username):
        authUsernameIdentifier = LDAP_AUTH_USERNAME_IDENTIFIER
        authObjectClass = LDAP_AUTH_OBJECT_CLASS
        excludeComputerAccounts = EXCLUDE_COMPUTER_ACCOUNTS

        objectClassFilter = "(objectclass=" + authObjectClass + ")"

        # Exclude Computer Accounts if settings allow it
        if excludeComputerAccounts == True:
            objectClassFilter = addSearchFilter(objectClassFilter, "!(objectclass=computer)")

        # Add filter for username
        objectClassFilter = addSearchFilter(
            objectClassFilter,
            authUsernameIdentifier + "=" + username
            )
        return objectClassFilter

    def getUserObject(self, connection, username, attributes=[LDAP_AUTH_USERNAME_IDENTIFIER, 'distinguishedName'], objectClassFilter=None):
        """ Default: Search for the dn from a username string param.
        
        Can also be used to fetch entire object from that username string or filtered attributes.

        ARGUMENTS

        :connection: LDAP Connection Object

        :username: (String) -- User to be searched

        :attributes: (String || List) -- Attributes to return in entry, default are DN and username Identifier

        e.g.: sAMAccountName

        :objectClassFilter: (String) -- Default is obtained from settings

        Returns the connection.
        """
        if objectClassFilter == None:
            objectClassFilter = self.getUserObjectFilter(username)

        connection.search(
            LDAP_AUTH_SEARCH_BASE, 
            objectClassFilter, 
            attributes=attributes
        )

        return connection

    def getGroupAttributes(self, groupDn, connection, idFilter=None, classFilter=None):
        attributes = [ 'objectSid' ]
        if idFilter is None:
            idFilter =  "distinguishedName=" + groupDn
        if classFilter is None:
            classFilter = "objectClass=group"
        objectClassFilter = ""
        objectClassFilter = addSearchFilter(objectClassFilter, classFilter)
        objectClassFilter = addSearchFilter(objectClassFilter, idFilter)
        args = {
            "connection": connection,
            "ldapFilter": objectClassFilter,
            "ldapAttributes": attributes
        }
        group = LDAPObject(**args)
        return group.attributes