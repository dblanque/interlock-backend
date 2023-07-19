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
from interlock_backend.ldap.adsi import search_filter_add
from interlock_backend.ldap.constants_cache import *
from interlock_backend.ldap import adsi as ldap_adsi
from interlock_backend.ldap.accountTypes import LDAP_ACCOUNT_TYPES

### Models
from core.models.ldapObject import LDAPObject
from core.models.log import logToDB
from ldap3 import (
    MODIFY_ADD,
    MODIFY_DELETE,
    MODIFY_INCREMENT,
    MODIFY_REPLACE
)

### Mixins
from .group import GroupViewMixin

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
    def get_user_object_filter(self, username):
        authUsernameIdentifier = LDAP_AUTH_USERNAME_IDENTIFIER
        authObjectClass = LDAP_AUTH_OBJECT_CLASS
        excludeComputerAccounts = EXCLUDE_COMPUTER_ACCOUNTS

        objectClassFilter = "(objectclass=" + authObjectClass + ")"

        # Exclude Computer Accounts if settings allow it
        if excludeComputerAccounts == True:
            objectClassFilter = search_filter_add(objectClassFilter, "!(objectclass=computer)")

        # Add filter for username
        objectClassFilter = search_filter_add(
            objectClassFilter,
            authUsernameIdentifier + "=" + username
            )
        return objectClassFilter

    def get_user_object(self, connection, username, attributes=[LDAP_AUTH_USERNAME_IDENTIFIER, 'distinguishedName'], objectClassFilter=None):
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
            objectClassFilter = self.get_user_object_filter(username)

        connection.search(
            LDAP_AUTH_SEARCH_BASE, 
            objectClassFilter, 
            attributes=attributes
        )

        return connection

    def get_group_attributes(self, groupDn, connection, idFilter=None, classFilter=None):
        attributes = [ 'objectSid' ]
        if idFilter is None:
            idFilter =  "distinguishedName=" + groupDn
        if classFilter is None:
            classFilter = "objectClass=group"
        objectClassFilter = ""
        objectClassFilter = search_filter_add(objectClassFilter, classFilter)
        objectClassFilter = search_filter_add(objectClassFilter, idFilter)
        args = {
            "connection": connection,
            "ldapFilter": objectClassFilter,
            "ldapAttributes": attributes
        }
        group = LDAPObject(**args)
        return group.attributes
    
    def ldap_user_list(self, request, connection, settings):
        user_list = list()
        objectClassFilter = "(objectclass=" + settings["authObjectClass"] + ")"

        # Exclude Computer Accounts if settings allow it
        if settings["excludeComputerAccounts"] == True:
            objectClassFilter = ldap_adsi.search_filter_add(objectClassFilter, "!(objectclass=computer)")
        
        # Exclude Contacts
        objectClassFilter = ldap_adsi.search_filter_add(objectClassFilter, "!(objectclass=contact)")

        try:
            connection.search(
                settings["authSearchBase"],
                objectClassFilter,
                attributes=settings["attributes"]
            )
        except:            
            connection.unbind()
            raise
        userList = connection.entries

        if LDAP_LOG_READ == True:
            # Log this action to DB
            logToDB(
                user_id=request.user.id,
                actionType="READ",
                objectClass="USER",
                affectedObject="ALL"
            )

        # Remove attributes to return as table headers
        valid_attributes = settings["attributes"]
        remove_attributes = [ 
            'distinguishedName', 
            'userAccountControl', 
            'displayName' 
        ]
        for attr in remove_attributes:
            if attr in valid_attributes:
                valid_attributes.remove(str(attr))

        valid_attributes.append('is_enabled')

        for user in userList:
            # Uncomment line below to see all attributes in user object
            # print(dir(user))

            # For each attribute in user object attributes
            user_dict = {}
            for attr_key in dir(user):
                if attr_key in valid_attributes:
                    str_key = str(attr_key)
                    str_value = str(getattr(user,attr_key))
                    if str_value == "[]":
                        user_dict[str_key] = ""
                    else:
                        user_dict[str_key] = str_value
                if attr_key == settings["authUsernameIdentifier"]:
                    user_dict['username'] = str_value

            # Add entry DN to response dictionary
            user_dict['distinguishedName'] = user.entry_dn

            # Check if user is disabled
            user_dict['is_enabled'] = True
            try:
                if ldap_adsi.list_user_perms(user, permissionToSearch="LDAP_UF_ACCOUNT_DISABLE"):
                    user_dict['is_enabled'] = False
            except Exception as e:
                print(e)
                print(f"Could not get user status for DN: {user_dict['distinguishedName']}")

            user_list.append(user_dict)
        result = dict()
        result["users"] = user_list
        result["headers"] = valid_attributes
        return result
    
    def ldap_user_insert(self, connection, settings, data):
        # TODO Check by authUsernameIdentifier and CN
        if data['path'] is not None and data['path'] != "":
            user_dn = 'CN='+data['username']+','+data['path']
        else:
            user_dn = 'CN='+data['username']+',OU=Users,'+settings["authSearchBase"]
        user_perms = 0

        # Add permissions selected in user creation
        for perm in data['permission_list']:
            permValue = int(ldap_adsi.LDAP_PERMS[perm]['value'])
            try:
                user_perms += permValue
                logger.debug("Located in: "+__name__+".insert")
                logger.debug("Permission Value added (cast to string): " + str(permValue))
            except Exception as error:
                # If there's an error unbind the connection and print traceback
                connection.unbind()
                print(traceback.format_exc())
                raise exc_user.UserPermissionError # Return error code to client

        # Add Normal Account permission to list
        user_perms += ldap_adsi.LDAP_PERMS['LDAP_UF_NORMAL_ACCOUNT']['value']
        logger.debug("Final User Permissions Value: " + str(user_perms))

        arguments = dict()
        arguments['userAccountControl'] = user_perms
        arguments[settings["authUsernameIdentifier"]] = str(data['username']).lower()
        arguments['objectClass'] = ['top', 'person', 'organizationalPerson', 'user']
        arguments['userPrincipalName'] = data['username'] + '@' + settings["authDomain"]

        excluded_keys = [
            'password', 
            'passwordConfirm',
            'path',
            'permission_list', # This array was parsed and calculated, then changed to userAccountControl
            'distinguishedName', # We don't want the front-end generated DN
            'username' # LDAP Uses sAMAccountName
        ]
        for key in data:
            if key not in excluded_keys:
                logger.debug("Key in data: " + key)
                logger.debug("Value for key above: " + data[key])
                arguments[key] = data[key]

        logger.debug(f'Creating user in DN Path: {user_dn}')
        try:
            connection.add(user_dn, settings["authObjectClass"], attributes=arguments)
        except Exception as e:
            connection.unbind()
            print(e)
            print(f'Could not create User: {user_dn}')
            data = {
                "ldap_response": connection.result
            }
            raise exc_user.UserCreate(data=data)

        return {
            "connection": connection,
            "user_dn": user_dn
        }

    def set_ldap_password(self, connection, user_dn, user_pwd):
        try:
            connection.extend.microsoft.modify_password(
                user=user_dn, 
                new_password=user_pwd
            )
        except Exception as e:
            connection.unbind()
            print(e)
            print(f'Could not update password for User DN: {user_dn}')
            data = {
                "ldap_response": connection.result
            }
            raise exc_user.UserUpdateError(data=data)
        return connection

    def ldap_user_exists(self, connection, settings, user_search):
        # Send LDAP Query for user being created to see if it exists
        settings["attributes"] = [
            settings["authUsernameIdentifier"],
            'distinguishedName',
            'userPrincipalName',
        ]
        connection = self.get_user_object(connection, user_search, attributes=settings["attributes"])
        user = connection.entries

        # If user exists, return error
        if user != []:
            connection.unbind()
            exception = exc_ldap.LDAPObjectExists
            data = {
                "code": "user_exists",
                "user": data['username']
            }
            exception.set_detail(exception, data)
            raise exception
        return connection

    def ldap_user_fetch(self, request, connection, settings, user_search):
        objectClassFilter = "(objectclass=" + settings["authObjectClass"] + ")"

        # Exclude Computer Accounts if settings allow it
        if settings["excludeComputerAccounts"] == True:
            objectClassFilter = ldap_adsi.search_filter_add(objectClassFilter, "!(objectclass=computer)")

        # Add filter for username
        objectClassFilter = ldap_adsi.search_filter_add(objectClassFilter, settings["authUsernameIdentifier"] + "=" + user_search)
        
        user_obj = LDAPObject(**{
            "connection": connection,
            "ldapFilter": objectClassFilter,
            "ldapAttributes": settings["attributes"]
        })
        user_entry = user_obj.entry
        user_dict = user_obj.attributes

        if LDAP_LOG_READ == True:
            # Log this action to DB
            logToDB(
                user_id=request.user.id,
                actionType="READ",
                objectClass="USER",
                affectedObject=user_search
            )

        memberOfObjects = list()
        if 'memberOf' in user_dict:
            memberOf = user_dict.pop('memberOf')
            if isinstance(memberOf, list):
                for g in memberOf:
                    memberOfObjects.append( self.get_group_attributes(g, connection) )
            else:
                g = memberOf
                memberOfObjects.append( self.get_group_attributes(g, connection) )

        ### Also add default Users Group to be available as Selectable PID
        memberOfObjects.append( GroupViewMixin.getGroupByRID(user_dict['primaryGroupID']) )

        if len(memberOfObjects) > 0:
            user_dict['memberOfObjects'] = memberOfObjects
        else:
            connection.unbind()
            raise exc_user.UserGroupsFetchError

        del memberOfObjects

        # Check if user is disabled
        user_dict['is_enabled'] = True
        try:
            if ldap_adsi.list_user_perms(user_entry, permissionToSearch="LDAP_UF_ACCOUNT_DISABLE", isObject=False):
                user_dict['is_enabled'] = False
        except Exception as e:
            print(e)
            print(user_dict['distinguishedName'])

        # Check if user is disabled
        try:
            userPermissions = ldap_adsi.list_user_perms(user_entry, permissionToSearch=None, isObject=False)
            user_dict['permission_list'] = userPermissions
        except Exception as e:
            print(e)
            print(user_dict['distinguishedName'])

        # Replace sAMAccountType Value with String Corresponding
        userAccountType = int(user_dict['sAMAccountType'])
        for accountType in LDAP_ACCOUNT_TYPES:
            accountTypeValue = LDAP_ACCOUNT_TYPES[accountType]
            if accountTypeValue == userAccountType:
                user_dict['sAMAccountType'] = accountType
        return user_dict

    def ldap_user_enable(self, request, connection, user_object, settings):
        user_to_enable = user_object['username']
        authSearchBase = settings["authSearchBase"]
        authUsernameIdentifier = settings["authUsernameIdentifier"]
        excludeComputerAccounts = settings["excludeComputerAccounts"]
        attributes = settings["attributes"]
        objectClassFilter = settings["objectClassFilter"]

        # Exclude Computer Accounts if settings allow it
        if excludeComputerAccounts == True:
            objectClassFilter = ldap_adsi.search_filter_add(objectClassFilter, "!(objectclass=computer)")

        # Add filter for username
        objectClassFilter = ldap_adsi.search_filter_add(
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

    def ldap_user_disable(self, request, connection, user_object, settings):
        authSearchBase = settings["authSearchBase"]
        authUsernameIdentifier = settings["authUsernameIdentifier"]
        authObjectClass = settings["authObjectClass"]
        excludeComputerAccounts = settings["excludeComputerAccounts"]
        attributes = settings["attributes"]
        objectClassFilter = settings["objectClassFilter"]

        user_to_disable = user_object['username']

        # Exclude Computer Accounts if settings allow it
        if excludeComputerAccounts == True:
            objectClassFilter = ldap_adsi.search_filter_add(objectClassFilter, "!(objectclass=computer)")

        # Add filter for username
        objectClassFilter = ldap_adsi.search_filter_add(
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

    def ldap_user_unlock(self, request, connection, user_object):
        userToUpdate = user_object['username']
        # If data request for deletion has user DN
        if 'distinguishedName' in user_object.keys() and user_object['distinguishedName'] != "":
            logger.debug('Updating with distinguishedName obtained from front-end')
            logger.debug(user_object['distinguishedName'])
            dn = user_object['distinguishedName']
        # Else, search for username dn
        else:
            logger.debug('Updating with user dn search method')
            connection = self.get_user_object(connection, userToUpdate)
            
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
    
    def ldap_user_delete(self, request, connection, user_object, authUsernameIdentifier):
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
            c = self.get_user_object(c, username)

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
