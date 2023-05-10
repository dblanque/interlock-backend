################################################################################
#################### INTERLOCK IS LICENSED UNDER GNU AGPLv3 ####################
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
from interlock_backend.ldap import adsi as ldap_adsi

### Models
from core.models.ldapObject import LDAPObject
from core.models.log import logToDB
from ldap3 import (
    MODIFY_ADD,
    MODIFY_DELETE,
    MODIFY_INCREMENT,
    MODIFY_REPLACE
)

from core.exceptions import (
    base as exc_base,
    users as exc_user, 
    ldap as exc_ldap
)
import traceback
import logging
################################################################################

logger = logging.getLogger(__name__)

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

    def enable_ldap_user(self, request, connection, user_object, settings):
        user_to_enable = user_object['username']
        authSearchBase = settings["authSearchBase"]
        authUsernameIdentifier = settings["authUsernameIdentifier"]
        excludeComputerAccounts = settings["excludeComputerAccounts"]
        attributes = settings["attributes"]
        objectClassFilter = settings["objectClassFilter"]

        # Exclude Computer Accounts if settings allow it
        if excludeComputerAccounts == True:
            objectClassFilter = ldap_adsi.addSearchFilter(objectClassFilter, "!(objectclass=computer)")

        # Add filter for username
        objectClassFilter = ldap_adsi.addSearchFilter(
            objectClassFilter, 
            authUsernameIdentifier + "=" + user_to_enable
            )

        connection.search(
            authSearchBase, 
            objectClassFilter, 
            attributes=attributes
        )

        user = connection.entries
        dn = str(user[0].distinguishedName)
        permList = ldap_adsi.list_user_perms(user[0], isObject=False)
        
        try:
            newPermINT = ldap_adsi.calc_permissions(permList, removePerm='LDAP_UF_ACCOUNT_DISABLE')
        except:
            print(traceback.format_exc())
            connection.unbind()
            raise exc_user.UserPermissionError

        connection.modify(dn,
            {'userAccountControl':[(MODIFY_REPLACE, [ newPermINT ])]}
        )

        if LDAP_LOG_UPDATE == True:
            # Log this action to DB
            logToDB(
                user_id=request.user.id,
                actionType="UPDATE",
                objectClass="USER",
                affectedObject=user_to_enable,
                extraMessage="ENABLE"
            )
        
        logger.debug(connection.result)
        return connection

    def disable_ldap_user(self, request, connection, user_object, settings):
        authSearchBase = settings["authSearchBase"]
        authUsernameIdentifier = settings["authUsernameIdentifier"]
        authObjectClass = settings["authObjectClass"]
        excludeComputerAccounts = settings["excludeComputerAccounts"]
        attributes = settings["attributes"]
        objectClassFilter = settings["objectClassFilter"]

        user_to_disable = user_object['username']

        # Exclude Computer Accounts if settings allow it
        if excludeComputerAccounts == True:
            objectClassFilter = ldap_adsi.addSearchFilter(objectClassFilter, "!(objectclass=computer)")

        # Add filter for username
        objectClassFilter = ldap_adsi.addSearchFilter(
            objectClassFilter, 
            authUsernameIdentifier + "=" + user_to_disable
            )

        connection.search(
            authSearchBase, 
            objectClassFilter, 
            attributes=attributes
        )

        user = connection.entries
        dn = str(user[0].distinguishedName)
        permList = ldap_adsi.list_user_perms(user[0], isObject=False)

        try:
            newPermINT = ldap_adsi.calc_permissions(permList, addPerm='LDAP_UF_ACCOUNT_DISABLE')
        except:
            print(traceback.format_exc())
            connection.unbind()
            raise exc_user.UserPermissionError

        connection.modify(dn,
            {'userAccountControl':[(MODIFY_REPLACE, [ newPermINT ])]}
        )

        if LDAP_LOG_UPDATE == True:
            # Log this action to DB
            logToDB(
                user_id=request.user.id,
                actionType="UPDATE",
                objectClass="USER",
                affectedObject=user_to_disable,
                extraMessage="DISABLE"
            )

        logger.debug("Located in: "+__name__+".disable")
        logger.debug(connection.result)
        return connection

    def unlock_ldap_user(self, request, connection, user_object):
        userToUpdate = user_object['username']
        # If data request for deletion has user DN
        if 'distinguishedName' in user_object.keys() and user_object['distinguishedName'] != "":
            logger.debug('Updating with distinguishedName obtained from front-end')
            logger.debug(user_object['distinguishedName'])
            dn = user_object['distinguishedName']
        # Else, search for username dn
        else:
            logger.debug('Updating with user dn search method')
            connection = self.getUserObject(connection, userToUpdate)
            
            user = connection.entries
            dn = str(user[0].distinguishedName)
            logger.debug(dn)

        if not dn or dn == "":
            connection.unbind()
            raise exc_user.UserDoesNotExist

        connection.extend.microsoft.unlock_account(dn)
        if LDAP_LOG_UPDATE == True:
            # Log this action to DB
            logToDB(
                user_id=request.user.id,
                actionType="UPDATE",
                objectClass="USER",
                affectedObject=userToUpdate,
                extraMessage="UNLOCK"
            )
        return connection
    
    def delete_ldap_user(self, request, connection, user_object, authUsernameIdentifier):
        if authUsernameIdentifier in user_object:
            username = user_object[authUsernameIdentifier]
        elif 'username' in user_object:
            username = user_object['username']
        else:
            raise exc_user.BaseException

        # If data request for deletion has user DN
        if 'distinguishedName' in user_object.keys() and user_object['distinguishedName'] != "":
            logger.debug('Deleting with distinguishedName obtained from front-end')
            logger.debug(user_object['distinguishedName'])
            distinguishedName = user_object['distinguishedName']
            if not distinguishedName or distinguishedName == "":
                connection.unbind()
                raise exc_user.UserDoesNotExist
            try:
                connection.delete(distinguishedName)
            except Exception as e:
                connection.unbind()
                print(e)
                data = {
                    "ldap_response": connection.result
                }
                raise exc_ldap.BaseException(data=data)
        # Else, search for username dn
        else:
            logger.debug('Deleting with user dn search method')
            c = self.getUserObject(c, username)

            user = connection.entries
            dn = str(user[0].distinguishedName)
            logger.debug(dn)

            if not dn or dn == "":
                connection.unbind()
                raise exc_user.UserDoesNotExist
            try:
                connection.delete(dn)
            except Exception as e:
                connection.unbind()
                print(e)
                data = {
                    "ldap_response": connection.result
                }
                raise exc_ldap.BaseException(data=data)

        if LDAP_LOG_DELETE == True:
            # Log this action to DB
            logToDB(
                user_id=request.user.id,
                actionType="DELETE",
                objectClass="USER",
                affectedObject=username
            )

        return connection
