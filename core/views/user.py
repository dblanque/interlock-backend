################################## IMPORTS #####################################
### Exceptions
from django.core.exceptions import PermissionDenied
from core.exceptions import (
    users as user_exceptions, 
    ldap as ldap_exceptions
)

### Models
from core.models import User
from core.models.log import logToDB
from core.models.ldapObject import LDAPObject

### Mixins
from .mixins.user import UserViewMixin

### ViewSets
from .base import BaseViewSet

### REST Framework
from rest_framework.response import Response
from rest_framework import viewsets
from rest_framework.exceptions import NotFound
from rest_framework.decorators import action

### Others
from interlock_backend.ldap.connector import openLDAPConnection
from interlock_backend.ldap.settings_func import SettingsList
from interlock_backend.ldap import adsi as ldap_adsi
from interlock_backend.ldap.countries import LDAP_COUNTRIES
from interlock_backend.ldap.accountTypes import LDAP_ACCOUNT_TYPES
from interlock_backend.ldap.encrypt import validateUser
from ldap3 import (
    MODIFY_ADD,
    MODIFY_DELETE,
    MODIFY_INCREMENT,
    MODIFY_REPLACE
)
import ldap3
import traceback
import logging
################################################################################

logger = logging.getLogger(__name__)

class UserViewSet(BaseViewSet, UserViewMixin):
    queryset = User.objects.all()

    def list(self, request):
        user = request.user
        validateUser(request=request, requestUser=user)
        data = []
        code = 0
        code_msg = 'ok'

        ######################## Get Latest Settings ###########################
        ldap_settings_list = SettingsList(**{"search":{
            'LDAP_AUTH_USERNAME_IDENTIFIER',
            'LDAP_AUTH_OBJECT_CLASS',
            'LDAP_AUTH_SEARCH_BASE',
            'EXCLUDE_COMPUTER_ACCOUNTS',
            'LDAP_LOG_READ'
        }})
        authUsernameIdentifier = ldap_settings_list.LDAP_AUTH_USERNAME_IDENTIFIER
        authObjectClass = ldap_settings_list.LDAP_AUTH_OBJECT_CLASS
        authSearchBase = ldap_settings_list.LDAP_AUTH_SEARCH_BASE
        excludeComputerAccounts = ldap_settings_list.EXCLUDE_COMPUTER_ACCOUNTS
        ########################################################################

        # Open LDAP Connection
        try:
            c = openLDAPConnection(user.dn, user.encryptedPassword, request.user)
        except Exception as e:
            print(e)
            raise ldap_exceptions.CouldNotOpenConnection
        attributes = [
            'givenName',
            'sn',
            'displayName',
            authUsernameIdentifier,
            'mail',
            'distinguishedName',
            'userAccountControl'
        ]

        objectClassFilter = "(objectclass=" + authObjectClass + ")"

        # Exclude Computer Accounts if settings allow it
        if excludeComputerAccounts == True:
            objectClassFilter = ldap_adsi.addSearchFilter(objectClassFilter, "!(objectclass=computer)")

        c.search(
            authSearchBase,
            objectClassFilter,
            attributes=attributes
        )
        list = c.entries

        if ldap_settings_list.LDAP_LOG_READ == True:
            # Log this action to DB
            logToDB(
                user_id=request.user.id,
                actionType="READ",
                objectClass="USER",
                affectedObject="ALL"
            )

        # Remove attributes to return as table headers
        valid_attributes = attributes
        remove_attributes = [ 
            'distinguishedName', 
            'userAccountControl', 
            'displayName' 
        ]
        for attr in remove_attributes:
            if attr in valid_attributes:
                valid_attributes.remove(str(attr))

        valid_attributes.append('is_enabled')

        for user in list:
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
                if attr_key == authUsernameIdentifier:
                    user_dict['username'] = str_value

            # Add entry DN to response dictionary
            user_dict['dn'] = user.entry_dn

            # Check if user is disabled
            if ldap_adsi.list_user_perms(user, permissionToSearch="LDAP_UF_ACCOUNT_DISABLE") == True:
                user_dict['is_enabled'] = False
            else:
                user_dict['is_enabled'] = True

            data.append(user_dict)

        # Close / Unbind LDAP Connection
        c.unbind()
        return Response(
             data={
                'code': code,
                'code_msg': code_msg,
                'users': data,
                'headers': valid_attributes
             }
        )

    @action(detail=False,methods=['post'])
    def fetch(self, request):
        user = request.user
        validateUser(request=request, requestUser=user)
        code = 0
        code_msg = 'ok'
        data = request.data
        userToSearch = data["username"]

        ######################## Get Latest Settings ###########################
        ldap_settings_list = SettingsList(**{"search":{
            'LDAP_AUTH_USERNAME_IDENTIFIER',
            'LDAP_AUTH_OBJECT_CLASS',
            'LDAP_AUTH_SEARCH_BASE',
            'EXCLUDE_COMPUTER_ACCOUNTS',
            'LDAP_LOG_READ'
        }})
        authUsernameIdentifier = ldap_settings_list.LDAP_AUTH_USERNAME_IDENTIFIER
        authObjectClass = ldap_settings_list.LDAP_AUTH_OBJECT_CLASS
        authSearchBase = ldap_settings_list.LDAP_AUTH_SEARCH_BASE
        excludeComputerAccounts = ldap_settings_list.EXCLUDE_COMPUTER_ACCOUNTS
        ########################################################################

        # Open LDAP Connection
        try:
            c = openLDAPConnection(user.dn, user.encryptedPassword, request.user)
        except Exception as e:
            print(e)
            raise ldap_exceptions.CouldNotOpenConnection
        attributes = [ 
            'givenName', 
            'sn', 
            'displayName', 
            authUsernameIdentifier, 
            'mail',
            'telephoneNumber',
            'streetAddress',
            'postalCode',
            'l', # Local / City
            'st', # State/Province
            'countryCode', # INT
            'co', # 2 Letter Code for Country
            'c', # Full Country Name
            'wWWHomePage',
            'distinguishedName',
            'userPrincipalName',
            'userAccountControl', # Permission ACLs
            'whenCreated',
            'whenChanged',
            'lastLogon',
            'badPwdCount',
            'pwdLastSet',
            'primaryGroupID',
            'objectClass',
            'objectCategory',
            'objectSid',
            'sAMAccountType',
            'memberOf',
        ]

        objectClassFilter = "(objectclass=" + authObjectClass + ")"

        # Exclude Computer Accounts if settings allow it
        if excludeComputerAccounts == True:
            objectClassFilter = ldap_adsi.addSearchFilter(objectClassFilter, "!(objectclass=computer)")

        # Add filter for username
        objectClassFilter = ldap_adsi.addSearchFilter(objectClassFilter, authUsernameIdentifier + "=" + userToSearch)
        
        user_obj = LDAPObject(**{
            "connection": c,
            "ldapFilter": objectClassFilter,
            "ldapAttributes": attributes
        })
        user_entry = user_obj.entry
        user_dict = user_obj.attributes

        if ldap_settings_list.LDAP_LOG_READ == True:
            # Log this action to DB
            logToDB(
                user_id=request.user.id,
                actionType="READ",
                objectClass="USER",
                affectedObject=data['username']
            )

        memberOfObjects = list()
        attributes = [ 'objectSid' ]
        if 'memberOf' in user_dict:
            if isinstance(user_dict['memberOf'], list):
                for g in user_dict['memberOf']:
                    objectClassFilter = ""
                    objectClassFilter = ldap_adsi.addSearchFilter(objectClassFilter, "objectClass=group")
                    objectClassFilter = ldap_adsi.addSearchFilter(objectClassFilter, "distinguishedName=" + g)
                    args = {
                        "connection": c,
                        "ldapFilter": objectClassFilter,
                        "ldapAttributes": attributes
                    }
                    group = LDAPObject(**args)
                    memberOfObjects.append(group.attributes)

                    del group
                    del objectClassFilter
            else:
                g = user_dict['memberOf']
                objectClassFilter = ""
                objectClassFilter = ldap_adsi.addSearchFilter(objectClassFilter, "objectClass=group")
                objectClassFilter = ldap_adsi.addSearchFilter(objectClassFilter, "distinguishedName=" + g)
                group = LDAPObject(**{
                            "connection": c,
                            "ldapFilter": "(objectClass=group)",
                            "ldapAttributes": attributes
                        })
                memberOfObjects.append(group.attributes)

            if len(memberOfObjects) > 0:
                user_dict['memberOfObjects'] = memberOfObjects

        # Check if user is disabled
        if ldap_adsi.list_user_perms(user_entry, permissionToSearch="LDAP_UF_ACCOUNT_DISABLE", isObject=False) == True:
            user_dict['is_enabled'] = False
        else:
            user_dict['is_enabled'] = True

        # Check if user is disabled
        userPermissions = ldap_adsi.list_user_perms(user_entry, permissionToSearch=None, isObject=False)
        user_dict['permission_list'] = userPermissions

        # Replace sAMAccountType Value with String Corresponding
        userAccountType = int(user_dict['sAMAccountType'])
        for accountType in LDAP_ACCOUNT_TYPES:
            accountTypeValue = LDAP_ACCOUNT_TYPES[accountType]
            if accountTypeValue == userAccountType:
                user_dict['sAMAccountType'] = accountType

        # Close / Unbind LDAP Connection
        c.unbind()
        return Response(
             data={
                'code': code,
                'code_msg': code_msg,
                'data': user_dict
             }
        )

    @action(detail=False,methods=['post'])
    def insert(self, request):
        user = request.user
        validateUser(request=request, requestUser=user)
        code = 0
        code_msg = 'ok'
        data = request.data

        if data['password'] != data['passwordConfirm']:
            exception = user_exceptions.UserPasswordsDontMatch
            data = {
                "code": "user_passwords_dont_match",
                "user": data['username']
            }
            exception.setDetail(exception, data)
            raise exception

        userToSearch = data["username"]

        ######################## Get Latest Settings ###########################
        ldap_settings_list = SettingsList(**{"search":{
            'LDAP_AUTH_USERNAME_IDENTIFIER',
            'LDAP_AUTH_OBJECT_CLASS',
            'LDAP_DOMAIN',
            'LDAP_AUTH_SEARCH_BASE',
            'LDAP_LOG_CREATE'
        }})
        authUsernameIdentifier = ldap_settings_list.LDAP_AUTH_USERNAME_IDENTIFIER
        authObjectClass = ldap_settings_list.LDAP_AUTH_OBJECT_CLASS
        authDomain = ldap_settings_list.LDAP_DOMAIN
        authSearchBase = ldap_settings_list.LDAP_AUTH_SEARCH_BASE
        ########################################################################

        # Open LDAP Connection
        try:
            c = openLDAPConnection(user.dn, user.encryptedPassword, request.user)
        except Exception as e:
            print(e)
            raise ldap_exceptions.CouldNotOpenConnection

        # Send LDAP Query for user being created to see if it exists
        attributes = [
            authUsernameIdentifier,
            'distinguishedName',
            'userPrincipalName',
        ]
        c = self.getUserObject(c, userToSearch, attributes=attributes)
        user = c.entries

        # If user exists, return error
        if user != []:
            exception = user_exceptions.UserExists
            data = {
                "code": "user_exists",
                "user": data['username']
            }
            exception.setDetail(exception, data)
            raise exception

        userDN = 'CN='+data['username']+','+data['path'] or 'CN='+data['username']+',OU=Users,'+authSearchBase
        userPermissions = 0

        # Add permissions selected in user creation
        for perm in data['permission_list']:
            permValue = int(ldap_adsi.LDAP_PERMS[perm]['value'])
            try:
                userPermissions += permValue
                logger.debug("Located in: "+__name__+".insert")
                logger.debug("Permission Value added (cast to string): " + str(permValue))
            except Exception as error:
                # If there's an error unbind the connection and print traceback
                c.unbind()
                print(traceback.format_exc())
                raise user_exceptions.user_exceptions.UserPermissionError # Return error code to client

        # Add Normal Account permission to list
        userPermissions += ldap_adsi.LDAP_PERMS['LDAP_UF_NORMAL_ACCOUNT']['value']
        logger.debug("Final User Permissions Value: " + str(userPermissions))

        arguments = dict()
        arguments['userAccountControl'] = userPermissions
        arguments[authUsernameIdentifier] = str(data['username']).lower()
        arguments['objectClass'] = ['top', 'person', 'organizationalPerson', 'user']
        arguments['userPrincipalName'] = data['username'] + '@' + authDomain

        excludeKeys = [
            'password', 
            'passwordConfirm',
            'path',
            'permission_list', # This array was parsed and calculated, then changed to userAccountControl
            'distinguishedName', # We don't want the front-end generated DN
            'username' # LDAP Uses sAMAccountName
        ]
        for key in data:
            if key not in excludeKeys:
                logger.debug("Key in data: " + key)
                logger.debug("Value for key above: " + data[key])
                arguments[key] = data[key]

        arguments['givenName'] = arguments['givenName'].capitalize()
        arguments['sn'] = arguments['sn'].capitalize()

        logger.debug('Creating user in DN Path: ' + userDN)
        c.add(userDN, authObjectClass, attributes=arguments)
        # TODO - Test if password changes correctly?
        c.extend.microsoft.modify_password(userDN, data['password'])

        if ldap_settings_list.LDAP_LOG_CREATE == True:
            # Log this action to DB
            logToDB(
                user_id=request.user.id,
                actionType="CREATE",
                objectClass="USER",
                affectedObject=data['username']
            )

        # Unbind the connection
        c.unbind()
        return Response(
             data={
                'code': code,
                'code_msg': code_msg,
                'data': data['username']
             }
        )

    def update(self, request, pk=None):
        user = request.user
        validateUser(request=request, requestUser=user)
        code = 0
        code_msg = 'ok'
        data = request.data

        ######################## Get Latest Settings ###########################
        ldap_settings_list = SettingsList(**{"search":{
            'LDAP_AUTH_USERNAME_IDENTIFIER',
            'LDAP_LOG_UPDATE'
        }})
        authUsernameIdentifier = ldap_settings_list.LDAP_AUTH_USERNAME_IDENTIFIER
        ########################################################################

        excludeKeys = [
            'password', 
            'passwordConfirm',
            'path',
            'permission_list', # This array is parsed and calculated later
            'distinguishedName', # We don't want the front-end generated DN
            'username', # LDAP Uses sAMAccountName
            'whenChanged',
            'whenCreated',
            'lastLogon',
            'badPwdCount',
            'pwdLastSet',
            'is_enabled',
            'sAMAccountType',
            'objectCategory',
            'primaryGroupID'
        ]

        userToUpdate = data['username']
        permList = data['permission_list']
        for key in excludeKeys:
            if key in data:
                del data[key]

        # Open LDAP Connection
        try:
            c = openLDAPConnection(user.dn, user.encryptedPassword, request.user)
        except Exception as e:
            print(e)
            raise ldap_exceptions.CouldNotOpenConnection

        # Get basic attributes for this user from AD to compare query and get dn
        attributes = [
            authUsernameIdentifier,
            'distinguishedName',
            'userPrincipalName',
            'userAccountControl',
        ]
        c = self.getUserObject(c, userToUpdate, attributes=ldap3.ALL_ATTRIBUTES)

        user = c.entries
        dn = str(user[0].distinguishedName)

        if 'LDAP_UF_LOCKOUT' in permList:
            # Default is 30 Minutes
            data['lockoutTime'] = 30 

        try:
            newPermINT = ldap_adsi.calc_permissions(permList)
        except:
            print(traceback.format_exc())
            raise user_exceptions.user_exceptions.UserPermissionError

        logger.debug("Located in: "+__name__+".update")
        logger.debug("New Permission Integer (cast to String):" + str(newPermINT))
        data['userAccountControl'] = newPermINT

        if data['co'] != "":
            # Set numeric country code (DCC Standard)
            data['countryCode'] = LDAP_COUNTRIES[data['co']]['dccCode']
            # Set ISO Country Code
            data['c'] = LDAP_COUNTRIES[data['co']]['isoCode']

        arguments = dict()
        for key in data:
                try:
                    if key in user[0].entry_attributes and data[key] == "":
                        operation = MODIFY_DELETE
                        c.modify(
                            dn,
                            {key: [( operation ), []]},
                        )
                    elif data[key] != "":
                        operation = MODIFY_REPLACE
                        if isinstance(data[key], list):
                            c.modify(
                                dn,
                                {key: [( operation, data[key])]},
                            )
                        else:
                            c.modify(
                                dn,
                                {key: [( operation, [ data[key] ])]},
                            )
                    else:
                        logger.info("No suitable operation for attribute " + key)
                        pass
                except:
                    print(traceback.format_exc())
                    logger.warn("Unable to update user '" + userToUpdate + "' with attribute '" + key + "'")
                    logger.warn("Attribute Value:" + data[key])
                    logger.warn("Operation Type: " + operation)
                    raise user_exceptions.UserUpdateError

        logger.debug(c.result)

        if ldap_settings_list.LDAP_LOG_UPDATE == True:
            # Log this action to DB
            logToDB(
                user_id=request.user.id,
                actionType="UPDATE",
                objectClass="USER",
                affectedObject=data['username']
            )

        # Unbind the connection
        c.unbind()
        return Response(
             data={
                'code': code,
                'code_msg': code_msg,
                'data': data
             }
        )

    @action(detail=False,methods=['post'])
    def disable(self, request):
        user = request.user
        validateUser(request=request, requestUser=user)
        code = 0
        code_msg = 'ok'
        data = request.data

        ######################## Get Latest Settings ###########################
        ldap_settings_list = SettingsList(**{"search":{
            'LDAP_AUTH_SEARCH_BASE',
            'LDAP_AUTH_USERNAME_IDENTIFIER',
            'LDAP_AUTH_OBJECT_CLASS',
            'EXCLUDE_COMPUTER_ACCOUNTS',
            'LDAP_LOG_UPDATE'
        }})
        authSearchBase = ldap_settings_list.LDAP_AUTH_SEARCH_BASE
        authUsernameIdentifier = ldap_settings_list.LDAP_AUTH_USERNAME_IDENTIFIER
        authObjectClass = ldap_settings_list.LDAP_AUTH_OBJECT_CLASS
        excludeComputerAccounts = ldap_settings_list.EXCLUDE_COMPUTER_ACCOUNTS
        ########################################################################

        userToDisable = data['username']
        # Open LDAP Connection
        try:
            c = openLDAPConnection(user.dn, user.encryptedPassword, request.user)
        except Exception as e:
            print(e)
            raise ldap_exceptions.CouldNotOpenConnection

        attributes = [
            authUsernameIdentifier,
            'distinguishedName',
            'userPrincipalName',
            'userAccountControl',
        ]
        objectClassFilter = "(objectclass=" + authObjectClass + ")"

        # Exclude Computer Accounts if settings allow it
        if excludeComputerAccounts == True:
            objectClassFilter = ldap_adsi.addSearchFilter(objectClassFilter, "!(objectclass=computer)")

        # Add filter for username
        objectClassFilter = ldap_adsi.addSearchFilter(
            objectClassFilter, 
            authUsernameIdentifier + "=" + userToDisable
            )

        c.search(
            authSearchBase, 
            objectClassFilter, 
            attributes=attributes
        )

        user = c.entries
        dn = str(user[0].distinguishedName)
        permList = ldap_adsi.list_user_perms(user[0], isObject=False)

        try:
            newPermINT = ldap_adsi.calc_permissions(permList, addPerm='LDAP_UF_ACCOUNT_DISABLE')
        except:
            print(traceback.format_exc())
            raise user_exceptions.user_exceptions.UserPermissionError

        if ldap_settings_list.LDAP_LOG_UPDATE == True:
            # Log this action to DB
            logToDB(
                user_id=request.user.id,
                actionType="UPDATE",
                objectClass="USER",
                affectedObject=userToDisable,
                extraMessage="DISABLE"
            )

        c.modify(dn,
            {'userAccountControl':[(MODIFY_REPLACE, [ newPermINT ])]}
        )

        logger.debug("Located in: "+__name__+".disable")
        logger.debug(c.result)

        # Unbind the connection
        c.unbind()
        return Response(
             data={
                'code': code,
                'code_msg': code_msg
             }
        )

    @action(detail=False,methods=['post'])
    def enable(self, request):
        user = request.user
        validateUser(request=request, requestUser=user)
        code = 0
        code_msg = 'ok'
        data = request.data

        ######################## Get Latest Settings ###########################
        ldap_settings_list = SettingsList(**{"search":{
            'LDAP_AUTH_SEARCH_BASE',
            'LDAP_AUTH_USERNAME_IDENTIFIER',
            'LDAP_AUTH_OBJECT_CLASS',
            'EXCLUDE_COMPUTER_ACCOUNTS',
            'LDAP_LOG_UPDATE'
        }})
        authSearchBase = ldap_settings_list.LDAP_AUTH_SEARCH_BASE
        authUsernameIdentifier = ldap_settings_list.LDAP_AUTH_USERNAME_IDENTIFIER
        authObjectClass = ldap_settings_list.LDAP_AUTH_OBJECT_CLASS
        excludeComputerAccounts = ldap_settings_list.EXCLUDE_COMPUTER_ACCOUNTS
        ########################################################################

        userToEnable = data['username']
        # Open LDAP Connection
        try:
            c = openLDAPConnection(user.dn, user.encryptedPassword, request.user)
        except Exception as e:
            print(e)
            raise ldap_exceptions.CouldNotOpenConnection

        attributes = [
            authUsernameIdentifier,
            'distinguishedName',
            'userPrincipalName',
            'userAccountControl'
        ]
        objectClassFilter = "(objectclass=" + authObjectClass + ")"

        # Exclude Computer Accounts if settings allow it
        if excludeComputerAccounts == True:
            objectClassFilter = ldap_adsi.addSearchFilter(objectClassFilter, "!(objectclass=computer)")

        # Add filter for username
        objectClassFilter = ldap_adsi.addSearchFilter(
            objectClassFilter, 
            authUsernameIdentifier + "=" + userToEnable
            )

        c.search(
            authSearchBase, 
            objectClassFilter, 
            attributes=attributes
        )

        user = c.entries
        dn = str(user[0].distinguishedName)
        permList = ldap_adsi.list_user_perms(user[0], isObject=False)
        
        try:
            newPermINT = ldap_adsi.calc_permissions(permList, removePerm='LDAP_UF_ACCOUNT_DISABLE')
        except:
            print(traceback.format_exc())
            raise user_exceptions.UserPermissionError

        if ldap_settings_list.LDAP_LOG_UPDATE == True:
            # Log this action to DB
            logToDB(
                user_id=request.user.id,
                actionType="UPDATE",
                objectClass="USER",
                affectedObject=userToEnable,
                extraMessage="ENABLE"
            )

        c.modify(dn,
            {'userAccountControl':[(MODIFY_REPLACE, [ newPermINT ])]}
        )
        
        logger.debug(c.result)

        # Unbind the connection
        c.unbind()
        return Response(
             data={
                'code': code,
                'code_msg': code_msg
             }
        )

    @action(detail=False, methods=['post'])
    def delete(self, request, pk=None):
        user = request.user
        validateUser(request=request, requestUser=user)
        code = 0
        code_msg = 'ok'
        data = request.data

        ldap_settings_list = SettingsList(**{"search":{
            'LDAP_LOG_DELETE'
        }})

        # Open LDAP Connection
        try:
            c = openLDAPConnection(user.dn, user.encryptedPassword, request.user)
        except Exception as e:
            print(e)
            raise ldap_exceptions.CouldNotOpenConnection

        # If data request for deletion has user DN
        if 'dn' in data.keys() and data['dn'] != "":
            logger.debug('Deleting with dn obtained from front-end')
            logger.debug(data['dn'])
            dn = data['dn']
            if not dn or dn == "":
                raise user_exceptions.UserDoesNotExist
            c.delete(dn)
        # Else, search for username dn
        else:
            logger.debug('Deleting with user dn search method')
            userToDelete = data['username']
            c = self.getUserObject(c, userToDelete)

            user = c.entries
            dn = str(user[0].distinguishedName)
            logger.debug(dn)

            if not dn or dn == "":
                raise user_exceptions.UserDoesNotExist
            c.delete(dn)

        if ldap_settings_list.LDAP_LOG_DELETE == True:
            # Log this action to DB
            logToDB(
                user_id=request.user.id,
                actionType="DELETE",
                objectClass="USER",
                affectedObject=data['username']
            )

        # Unbind the connection
        c.unbind()
        return Response(
             data={
                'code': code,
                'code_msg': code_msg,
                'data': data
             }
        )

    @action(detail=False, methods=['post'])
    def changePassword(self, request, pk=None):
        user = request.user
        validateUser(request=request, requestUser=user)
        code = 0
        code_msg = 'ok'
        data = request.data

        ldap_settings_list = SettingsList(**{"search":{
            'LDAP_LOG_UPDATE'
        }})

        # Open LDAP Connection
        try:
            c = openLDAPConnection(user.dn, user.encryptedPassword, request.user)
        except Exception as e:
            print(e)
            raise ldap_exceptions.CouldNotOpenConnection

        # If data request for deletion has user DN
        if 'dn' in data.keys() and data['dn'] != "":
            logger.debug('Updating with dn obtained from front-end')
            logger.debug(data['dn'])
            dn = data['dn']
        # Else, search for username dn
        else:
            logger.debug('Updating with user dn search method')
            userToUpdate = data['username']
            c = self.getUserObject(c, userToUpdate)
            
            user = c.entries
            dn = str(user[0].distinguishedName)
            logger.debug(dn)

        if not dn or dn == "":
            raise user_exceptions.UserDoesNotExist

        if data['password'] != data['passwordConfirm']:
            raise user_exceptions.UserPasswordsDontMatch

        if ldap_settings_list.LDAP_LOG_UPDATE == True:
            # Log this action to DB
            logToDB(
                user_id=request.user.id,
                actionType="UPDATE",
                objectClass="USER",
                affectedObject=data['username'],
                extraMessage="CHANGED_PASSWORD"
            )

        c.extend.microsoft.modify_password(dn, data['password'])

        # Unbind the connection
        c.unbind()
        return Response(
             data={
                'code': code,
                'code_msg': code_msg,
                'data': data
             }
        )

    @action(detail=False, methods=['post'])
    def unlock(self, request, pk=None):
        user = request.user
        validateUser(request=request, requestUser=user)
        code = 0
        code_msg = 'ok'
        data = request.data

        ldap_settings_list = SettingsList(**{"search":{
            'LDAP_LOG_UPDATE'
        }})

        # Open LDAP Connection
        try:
            c = openLDAPConnection(user.dn, user.encryptedPassword, request.user)
        except Exception as e:
            print(e)
            raise ldap_exceptions.CouldNotOpenConnection

        # If data request for deletion has user DN
        if 'dn' in data.keys() and data['dn'] != "":
            logger.debug('Updating with dn obtained from front-end')
            logger.debug(data['dn'])
            dn = data['dn']
        # Else, search for username dn
        else:
            logger.debug('Updating with user dn search method')
            userToUpdate = data['username']
            c = self.getUserObject(c, userToUpdate)
            
            user = c.entries
            dn = str(user[0].distinguishedName)
            logger.debug(dn)

        if not dn or dn == "":
            raise user_exceptions.UserDoesNotExist

        if ldap_settings_list.LDAP_LOG_UPDATE == True:
            # Log this action to DB
            logToDB(
                user_id=request.user.id,
                actionType="UPDATE",
                objectClass="USER",
                affectedObject=data['username'],
                extraMessage="UNLOCK"
            )

        c.extend.microsoft.unlock_account(dn)

        result = c.result
        if result['description'] == 'success':
            response_result = data['username']
        else:
            raise user_exceptions.CouldNotUnlockUser

        # Unbind the connection
        c.unbind()
        return Response(
             data={
                'code': code,
                'code_msg': code_msg,
                'data': response_result
             }
        )

    @action(detail=False, methods=['post'])
    def changePasswordSelf(self, request, pk=None):
        user = request.user
        validateUser(request=request, requestUser=user, requireAdmin=False)
        code = 0
        code_msg = 'ok'
        data = request.data

        ldap_settings_list = SettingsList(**{"search":{
            'LDAP_LOG_UPDATE'
        }})

        if data['username'] != user.username:
            raise PermissionDenied

        # Open LDAP Connection
        try:
            c = openLDAPConnection()
        except Exception as e:
            print(e)
            raise ldap_exceptions.CouldNotOpenConnection

        # If data request for deletion has user DN
        if 'dn' in data.keys() and data['dn'] != "":
            logger.debug('Updating with dn obtained from front-end')
            logger.debug(data['dn'])
            dn = data['dn']
        # Else, search for username dn
        else:
            logger.debug('Updating with user dn search method')
            userToUpdate = user.username
            c = self.getUserObject(c, userToUpdate)
            
            user = c.entries
            dn = str(user[0].distinguishedName)
            logger.debug(dn)

        if not dn or dn == "":
            raise user_exceptions.UserDoesNotExist

        if data['password'] != data['passwordConfirm']:
            raise user_exceptions.UserPasswordsDontMatch

        c.extend.microsoft.modify_password(dn, data['password'])

        if ldap_settings_list.LDAP_LOG_UPDATE == True:
            # Log this action to DB
            logToDB(
                user_id=request.user.id,
                actionType="UPDATE",
                objectClass="USER",
                affectedObject=data['username'],
                extraMessage="CHANGED_PASSWORD"
            )

        # Unbind the connection
        c.unbind()
        return Response(
             data={
                'code': code,
                'code_msg': code_msg,
                'data': data
             }
        )

    @action(detail=False, methods=['put', 'post'])
    def updateSelf(self, request, pk=None):
        user = request.user
        validateUser(request=request, requestUser=user, requireAdmin=False)
        code = 0
        code_msg = 'ok'
        data = request.data

        if data['username'] != user.username:
            raise PermissionDenied

        ######################## Get Latest Settings ###########################
        ldap_settings_list = SettingsList(**{"search":{
            'LDAP_AUTH_USERNAME_IDENTIFIER',
            'LDAP_LOG_UPDATE'
        }})
        authUsernameIdentifier = ldap_settings_list.LDAP_AUTH_USERNAME_IDENTIFIER
        ########################################################################

        excludeKeys = [
            'password', 
            'passwordConfirm',
            'path',
            'permission_list', # This array is parsed and calculated later
            'distinguishedName', # We don't want the front-end generated DN
            'username', # LDAP Uses sAMAccountName
            'whenChanged',
            'whenCreated',
            'lastLogon',
            'badPwdCount',
            'pwdLastSet',
            'is_enabled',
            'sAMAccountType',
            'objectCategory',
            'userAccountControl',
            'objectClass',
            'primaryGroupID'
        ]

        userToUpdate = data['username']
        for key in excludeKeys:
            if key in data:
                del data[key]

        # Open LDAP Connection
        try:
            c = openLDAPConnection()
        except Exception as e:
            print(e)
            raise ldap_exceptions.CouldNotOpenConnection

        # Get basic attributes for this user from AD to compare query and get dn
        attributes = [
            authUsernameIdentifier,
            'distinguishedName',
            'userPrincipalName',
            'userAccountControl',
        ]
        c = self.getUserObject(c, userToUpdate, attributes=ldap3.ALL_ATTRIBUTES)

        user = c.entries
        dn = str(user[0].distinguishedName)

        if data['co'] != "":
            # Set numeric country code (DCC Standard)
            data['countryCode'] = LDAP_COUNTRIES[data['co']]['dccCode']
            # Set ISO Country Code
            data['c'] = LDAP_COUNTRIES[data['co']]['isoCode']

        # We need to check if the attributes exist in the LDAP Object already
        # To know what operation to apply. This is VERY important.
        arguments = dict()
        for key in data:
                try:
                    if key in user[0].entry_attributes and data[key] == "":
                        operation = MODIFY_DELETE
                        c.modify(
                            dn,
                            {key: [( operation ), []]},
                        )
                    elif data[key] != "":
                        operation = MODIFY_REPLACE
                        if isinstance(data[key], list):
                            c.modify(
                                dn,
                                {key: [( operation, data[key])]},
                            )
                        else:
                            c.modify(
                                dn,
                                {key: [( operation, [ data[key] ])]},
                            )
                    else:
                        logger.info("No suitable operation for attribute " + key)
                        pass
                except:
                    print(traceback.format_exc())
                    logger.warn("Unable to update user '" + userToUpdate + "' with attribute '" + key + "'")
                    logger.warn("Attribute Value:" + data[key])
                    logger.warn("Operation Type: " + operation)
                    raise user_exceptions.UserUpdateError

        logger.debug(c.result)

        if ldap_settings_list.LDAP_LOG_UPDATE == True:
            # Log this action to DB
            logToDB(
                user_id=request.user.id,
                actionType="UPDATE",
                objectClass="USER",
                affectedObject=data['username'],
                extraMessage="END_USER_UPDATED"
            )

        # Unbind the connection
        c.unbind()
        return Response(
             data={
                'code': code,
                'code_msg': code_msg,
                'data': data
             }
        )

    @action(detail=False, methods=['get'])
    def me(self, request):
        user = request.user
        validateUser(request=request, requestUser=user, requireAdmin=False)
        data = {}
        code = 0
        data["username"] = request.user.username or ""
        data["first_name"] = request.user.first_name or ""
        data["last_name"] = request.user.last_name or ""
        data["email"] = request.user.email or ""
        data["admin_allowed"] = request.user.is_superuser or False
        return Response(
             data={
                'code': code,
                'code_msg': 'ok',
                'user': data
             }
        )

    @action(detail=False,methods=['post'])
    def fetchme(self, request):
        user = request.user
        validateUser(request=request, requestUser=user, requireAdmin=False)
        code = 0
        code_msg = 'ok'
        data = request.data
        userToSearch = user.username

        ######################## Get Latest Settings ###########################
        ldap_settings_list = SettingsList(**{"search":{
            'LDAP_AUTH_USERNAME_IDENTIFIER',
            'LDAP_AUTH_OBJECT_CLASS',
            'LDAP_AUTH_SEARCH_BASE'
        }})
        authUsernameIdentifier = ldap_settings_list.LDAP_AUTH_USERNAME_IDENTIFIER
        authObjectClass = ldap_settings_list.LDAP_AUTH_OBJECT_CLASS
        authSearchBase = ldap_settings_list.LDAP_AUTH_SEARCH_BASE
        ########################################################################

        # Open LDAP Connection
        try:
            c = openLDAPConnection(user.dn, user.encryptedPassword, request.user)
        except Exception as e:
            print(e)
            raise ldap_exceptions.CouldNotOpenConnection
        attributes = [ 
            'givenName', 
            'sn', 
            'displayName', 
            authUsernameIdentifier, 
            'mail',
            'telephoneNumber',
            'streetAddress',
            'postalCode',
            'l', # Local / City
            'st', # State/Province
            'countryCode', # INT
            'co', # 2 Letter Code for Country
            'c', # Full Country Name
            'wWWHomePage',
            'distinguishedName',
            'userPrincipalName',
            'whenCreated',
            'whenChanged',
            'lastLogon',
            'badPwdCount',
            'pwdLastSet'
        ]

        objectClassFilter = "(objectclass=" + authObjectClass + ")"

        # Add filter for username
        objectClassFilter = ldap_adsi.addSearchFilter(objectClassFilter, authUsernameIdentifier + "=" + userToSearch)
        c.search(
            authSearchBase,
            objectClassFilter,
            attributes=attributes
        )
        user = c.entries

        # For each attribute in user object attributes
        user_dict = {}
        for attr_key in attributes:
            if attr_key in attributes:
                str_key = str(attr_key)
                str_value = str(getattr(user[0],attr_key))
                if str_value == "[]":
                    user_dict[str_key] = ""
                else:
                    user_dict[str_key] = str_value
            if attr_key == authUsernameIdentifier:
                user_dict['username'] = str_value

        # Close / Unbind LDAP Connection
        c.unbind()
        return Response(
             data={
                'code': code,
                'code_msg': code_msg,
                'data': user_dict
             }
        )

    @action(detail=False,methods=['get'])
    def logout(self, request):
        user = request.user
        validateUser(request=request, requestUser=user, requireAdmin=False)
        code = 0
        code_msg = 'ok'

        ldap_settings_list = SettingsList(**{"search":{
            'LDAP_LOG_LOGOUT'
        }})

        if ldap_settings_list.LDAP_LOG_LOGOUT == True:
            # Log this action to DB
            logToDB(
                user_id=request.user.id,
                actionType="LOGOUT",
                objectClass="USER",
            )

        return Response(
             data={
                'code': code,
                'code_msg': code_msg,
             }
        )

    # # def list(self, request, pk=None):
    # #     raise NotFound

    # def create(self, request, pk=None):
    #     raise NotFound

    # def put(self, request, pk=None):
    #     raise NotFound

    # def patch(self, request, pk=None):
    #     raise NotFound
        
    # def retrieve(self, request, pk=None):
    #     raise NotFound

    # # def update(self, request, pk=None):
    # #     raise NotFound

    # def partial_update(self, request, pk=None):
    #     raise NotFound

    # def destroy(self, request, pk=None):
    #     raise NotFound