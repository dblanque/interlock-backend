################################################################################
#################### INTERLOCK IS LICENSED UNDER GNU AGPLv3 ####################
################## ORIGINAL PROJECT CREATED BY DYLAN BLANQUÉ ###################
########################## AND BR CONSULTING S.R.L. ############################
################################################################################
# Module: core.views.user
# Contains the ViewSet for User related operations

#---------------------------------- IMPORTS -----------------------------------#
### Exceptions
from django.core.exceptions import PermissionDenied
from core.exceptions import (
    users as exc_user, 
    ldap as exc_ldap
)

### Models
from core.models import User
from core.models.log import logToDB
from core.models.ldapObject import LDAPObject

### Mixins
from .mixins.user import UserViewMixin
from .mixins.group import GroupViewMixin

### ViewSets
from .base import BaseViewSet

### REST Framework
from rest_framework.response import Response
from rest_framework import viewsets
from rest_framework.exceptions import NotFound
from rest_framework.decorators import action

### Others
from interlock_backend.ldap.connector import LDAPConnector
from interlock_backend.ldap.constants_cache import *
from interlock_backend.settings import DEBUG
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
        validateUser(request=request)
        data = []
        code = 0
        code_msg = 'ok'

        ######################## Get Latest Settings ###########################
        authUsernameIdentifier = LDAP_AUTH_USERNAME_IDENTIFIER
        authObjectClass = LDAP_AUTH_OBJECT_CLASS
        authSearchBase = LDAP_AUTH_SEARCH_BASE
        excludeComputerAccounts = EXCLUDE_COMPUTER_ACCOUNTS
        ########################################################################

        # Open LDAP Connection
        try:
            c = LDAPConnector(user.dn, user.encryptedPassword, request.user).connection
        except Exception as e:
            print(e)
            raise exc_ldap.CouldNotOpenConnection
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
        
        # Exclude Contacts
        objectClassFilter = ldap_adsi.addSearchFilter(objectClassFilter, "!(objectclass=contact)")

        c.search(
            authSearchBase,
            objectClassFilter,
            attributes=attributes
        )
        list = c.entries

        if LDAP_LOG_READ == True:
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
            user_dict['distinguishedName'] = user.entry_dn

            # Check if user is disabled
            user_dict['is_enabled'] = True
            try:
                if ldap_adsi.list_user_perms(user, permissionToSearch="LDAP_UF_ACCOUNT_DISABLE"):
                    user_dict['is_enabled'] = False
            except Exception as e:
                print(e)
                print(f"Could not get user status for DN: {user_dict['distinguishedName']}")

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
        validateUser(request=request)
        code = 0
        code_msg = 'ok'
        data = request.data
        userToSearch = data["username"]

        ######################## Get Latest Settings ###########################
        authUsernameIdentifier = LDAP_AUTH_USERNAME_IDENTIFIER
        authObjectClass = LDAP_AUTH_OBJECT_CLASS
        authSearchBase = LDAP_AUTH_SEARCH_BASE
        excludeComputerAccounts = EXCLUDE_COMPUTER_ACCOUNTS
        ########################################################################

        # Open LDAP Connection
        try:
            c = LDAPConnector(user.dn, user.encryptedPassword, request.user).connection
        except Exception as e:
            print(e)
            raise exc_ldap.CouldNotOpenConnection
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

        if LDAP_LOG_READ == True:
            # Log this action to DB
            logToDB(
                user_id=request.user.id,
                actionType="READ",
                objectClass="USER",
                affectedObject=data['username']
            )

        memberOfObjects = list()
        if 'memberOf' in user_dict:
            memberOf = user_dict.pop('memberOf')
            if isinstance(memberOf, list):
                for g in memberOf:
                    memberOfObjects.append( self.getGroupAttributes(g, c) )
            else:
                g = memberOf
                memberOfObjects.append( self.getGroupAttributes(g, c) )

        ### Also add default Users Group to be available as Selectable PID
        memberOfObjects.append( GroupViewMixin.getGroupByRID(user_dict['primaryGroupID']) )

        if len(memberOfObjects) > 0:
            user_dict['memberOfObjects'] = memberOfObjects
        else:
            c.unbind()
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
        validateUser(request=request)
        code = 0
        code_msg = 'ok'
        data = request.data

        if data['password'] != data['passwordConfirm']:
            exception = exc_user.UserPasswordsDontMatch
            data = {
                "code": "user_passwords_dont_match",
                "user": data['username']
            }
            exception.setDetail(exception, data)
            raise exception

        userToSearch = data["username"]

        ######################## Get Latest Settings ###########################
        authUsernameIdentifier = LDAP_AUTH_USERNAME_IDENTIFIER
        authObjectClass = LDAP_AUTH_OBJECT_CLASS
        authDomain = LDAP_DOMAIN
        authSearchBase = LDAP_AUTH_SEARCH_BASE
        ########################################################################

        # Open LDAP Connection
        try:
            c = LDAPConnector(user.dn, user.encryptedPassword, request.user).connection
        except Exception as e:
            print(e)
            raise exc_ldap.CouldNotOpenConnection

        # TODO Check by authUsernameIdentifier and CN
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
            c.unbind()
            exception = exc_ldap.LDAPObjectExists
            data = {
                "code": "user_exists",
                "user": data['username']
            }
            exception.setDetail(exception, data)
            raise exception

        if data['path'] is not None and data['path'] != "":
            userDN = 'CN='+data['username']+','+data['path']
        else:
            userDN = 'CN='+data['username']+',OU=Users,'+authSearchBase
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
                raise exc_user.UserPermissionError # Return error code to client

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

        arguments['givenName'] = arguments['givenName']
        arguments['sn'] = arguments['sn']

        logger.debug('Creating user in DN Path: ' + userDN)
        try:
            c.add(userDN, authObjectClass, attributes=arguments)
        except Exception as e:
            c.unbind()
            print(e)
            print(f'Could not create User: {userDN}')
            data = {
                "ldap_response": c.result
            }
            raise exc_user.UserCreate(data=data)

        try:
            c.extend.microsoft.modify_password(
                user=userDN, 
                new_password=data['password']
            )
        except Exception as e:
            c.unbind()
            print(e)
            print(f'Could not update password for User DN: {userDN}')
            data = {
                "ldap_response": c.result
            }
            raise exc_user.UserUpdateError(data=data)

        if LDAP_LOG_CREATE == True:
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
        validateUser(request=request)
        code = 0
        code_msg = 'ok'
        data = request.data
        data = data['user']

        ######################## Get Latest Settings ###########################
        authUsernameIdentifier = LDAP_AUTH_USERNAME_IDENTIFIER
        ########################################################################

        excludeKeys = [
            # Added keys for front-end normalization
            'name',
            'type',

            # Samba keys to intentionally exclude
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
            'objectSid',
            'objectRid'
        ]

        userToUpdate = data['username']

        permList = data['permission_list']
        for key in excludeKeys:
            if key in data:
                del data[key]

        # Open LDAP Connection
        try:
            c = LDAPConnector(user.dn, user.encryptedPassword, request.user).connection
        except Exception as e:
            print(e)
            raise exc_ldap.CouldNotOpenConnection

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
        
        ################# START NON-STANDARD ARGUMENT UPDATES ##################
        try:
            newPermINT = ldap_adsi.calc_permissions(permList)
        except:
            print(traceback.format_exc())
            c.unbind()
            raise exc_user.UserPermissionError

        logger.debug("Located in: "+__name__+".update")
        logger.debug("New Permission Integer (cast to String):" + str(newPermINT))
        data['userAccountControl'] = newPermINT

        if 'co' in data and data['co'] != "" and data['co'] != 0:
            try:
                # Set numeric country code (DCC Standard)
                data['countryCode'] = LDAP_COUNTRIES[data['co']]['dccCode']
                # Set ISO Country Code
                data['c'] = LDAP_COUNTRIES[data['co']]['isoCode']
            except Exception as e:
                c.unbind()
                print(data)
                print(e)
                raise exc_user.UserCountryUpdateError

        if 'groupsToAdd' in data and 'groupsToRemove' in data:
            if data['groupsToAdd'] == data['groupsToRemove'] and data['groupsToAdd'] != list():
                c.unbind()
                print(data)
                raise exc_user.BadGroupSelection

        if 'groupsToAdd' in data:
            groupsToAdd = data.pop('groupsToAdd')
            if len(groupsToAdd) > 0:
                c.extend.microsoft.add_members_to_groups(dn, groupsToAdd)
        if 'groupsToRemove' in data:
            groupsToRemove = data.pop('groupsToRemove')
            if len(groupsToRemove) > 0:
                c.extend.microsoft.remove_members_from_groups(dn, groupsToRemove)

        if 'memberOfObjects' in data:
            data.pop('memberOfObjects')
        if 'memberOf' in data:
            data.pop('memberOf')

        ################### START STANDARD ARGUMENT UPDATES ####################
        arguments = dict()
        operation = None
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
                    logger.warn("Unable to update user '" + str(userToUpdate) + "' with attribute '" + str(key) + "'")
                    logger.warn("Attribute Value:" + str(data[key]))
                    if operation is not None:
                        logger.warn("Operation Type: " + str(operation))
                    c.unbind()
                    raise exc_user.UserUpdateError

        logger.debug(c.result)

        if LDAP_LOG_UPDATE == True:
            # Log this action to DB
            logToDB(
                user_id=request.user.id,
                actionType="UPDATE",
                objectClass="USER",
                affectedObject=userToUpdate
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
        validateUser(request=request)
        code = 0
        code_msg = 'ok'
        data = request.data

        ######################## Get Latest Settings ###########################
        authSearchBase = LDAP_AUTH_SEARCH_BASE
        authUsernameIdentifier = LDAP_AUTH_USERNAME_IDENTIFIER
        authObjectClass = LDAP_AUTH_OBJECT_CLASS
        excludeComputerAccounts = EXCLUDE_COMPUTER_ACCOUNTS
        ########################################################################

        userToDisable = data['username']
        # Open LDAP Connection
        try:
            c = LDAPConnector(user.dn, user.encryptedPassword, request.user).connection
        except Exception as e:
            print(e)
            raise exc_ldap.CouldNotOpenConnection

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
            c.unbind()
            raise exc_user.UserPermissionError

        if LDAP_LOG_UPDATE == True:
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
        validateUser(request=request)
        code = 0
        code_msg = 'ok'
        data = request.data

        ######################## Get Latest Settings ###########################
        authSearchBase = LDAP_AUTH_SEARCH_BASE
        authUsernameIdentifier = LDAP_AUTH_USERNAME_IDENTIFIER
        authObjectClass = LDAP_AUTH_OBJECT_CLASS
        excludeComputerAccounts = EXCLUDE_COMPUTER_ACCOUNTS
        ########################################################################

        userToEnable = data['username']
        # Open LDAP Connection
        try:
            c = LDAPConnector(user.dn, user.encryptedPassword, request.user).connection
        except Exception as e:
            print(e)
            raise exc_ldap.CouldNotOpenConnection

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
            c.unbind()
            raise exc_user.UserPermissionError

        if LDAP_LOG_UPDATE == True:
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
        validateUser(request=request)
        code = 0
        code_msg = 'ok'
        data = request.data

        # Open LDAP Connection
        try:
            c = LDAPConnector(user.dn, user.encryptedPassword, request.user).connection
        except Exception as e:
            print(e)
            raise exc_ldap.CouldNotOpenConnection

        userToDelete = data['username']

        # If data request for deletion has user DN
        if 'distinguishedName' in data.keys() and data['distinguishedName'] != "":
            logger.debug('Deleting with distinguishedName obtained from front-end')
            logger.debug(data['distinguishedName'])
            distinguishedName = data['distinguishedName']
            if not distinguishedName or distinguishedName == "":
                c.unbind()
                raise exc_user.UserDoesNotExist
            try:
                c.delete(distinguishedName)
            except Exception as e:
                c.unbind()
                print(e)
                data = {
                    "ldap_response": c.result
                }
                raise exc_ldap.BaseException(data=data)
        # Else, search for username dn
        else:
            logger.debug('Deleting with user dn search method')
            c = self.getUserObject(c, userToDelete)

            user = c.entries
            dn = str(user[0].distinguishedName)
            logger.debug(dn)

            if not dn or dn == "":
                c.unbind()
                raise exc_user.UserDoesNotExist
            try:
                c.delete(dn)
            except Exception as e:
                c.unbind()
                print(e)
                data = {
                    "ldap_response": c.result
                }
                raise exc_ldap.BaseException(data=data)

        if LDAP_LOG_DELETE == True:
            # Log this action to DB
            logToDB(
                user_id=request.user.id,
                actionType="DELETE",
                objectClass="USER",
                affectedObject=userToDelete
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
        validateUser(request=request)
        code = 0
        code_msg = 'ok'
        data = request.data

        # Open LDAP Connection
        try:
            c = LDAPConnector(user.dn, user.encryptedPassword, request.user).connection
        except Exception as e:
            print(e)
            raise exc_ldap.CouldNotOpenConnection

        userToUpdate = data['username']

        # If data request for deletion has user DN
        if 'distinguishedName' in data.keys() and data['distinguishedName'] != "":
            logger.debug('Updating with distinguishedName obtained from front-end')
            logger.debug(data['distinguishedName'])
            dn = data['distinguishedName']
        # Else, search for username dn
        else:
            logger.debug('Updating with user dn search method')
            c = self.getUserObject(c, userToUpdate)
            
            user = c.entries
            dn = str(user[0].distinguishedName)
            logger.debug(dn)

        if dn is None or dn == "":
            c.unbind()
            raise exc_user.UserDoesNotExist

        if data['password'] != data['passwordConfirm']:
            c.unbind()
            raise exc_user.UserPasswordsDontMatch

        if LDAP_LOG_UPDATE == True:
            # Log this action to DB
            logToDB(
                user_id=request.user.id,
                actionType="UPDATE",
                objectClass="USER",
                affectedObject=userToUpdate,
                extraMessage="CHANGED_PASSWORD"
            )

        try:
            # ! ADDS does not handle password changing without ldaps
            # enc_pwd = '"{}"'.format(data['password']).encode('utf-16-le')
            # c.modify(dn, {'unicodePwd': [(MODIFY_REPLACE, [enc_pwd] )]})
            # ldap3.extend.microsoft.modifyPassword.ad_modify_password(conn, user_dn, new_password, old_password=None)
            c.extend.microsoft.modify_password(
                user=dn, 
                new_password=data['password']
            )
        except Exception as e:
            c.unbind()
            print(e)
            print(f'Could not update password for User DN: {dn}')
            data = {
                "ldap_response": c.result
            }
            raise exc_user.UserUpdateError(data=data)

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
        validateUser(request=request)
        code = 0
        code_msg = 'ok'
        data = request.data

        # Open LDAP Connection
        try:
            c = LDAPConnector(user.dn, user.encryptedPassword, request.user).connection
        except Exception as e:
            print(e)
            raise exc_ldap.CouldNotOpenConnection

        # If data request for deletion has user DN
        if 'distinguishedName' in data.keys() and data['distinguishedName'] != "":
            logger.debug('Updating with distinguishedName obtained from front-end')
            logger.debug(data['distinguishedName'])
            distinguishedName = data['distinguishedName']
        # Else, search for username dn
        else:
            logger.debug('Updating with user dn search method')
            userToUpdate = data['username']
            c = self.getUserObject(c, userToUpdate)
            
            user = c.entries
            dn = str(user[0].distinguishedName)
            logger.debug(dn)

        if not dn or dn == "":
            c.unbind()
            raise exc_user.UserDoesNotExist

        if LDAP_LOG_UPDATE == True:
            # Log this action to DB
            logToDB(
                user_id=request.user.id,
                actionType="UPDATE",
                objectClass="USER",
                affectedObject=userToUpdate,
                extraMessage="UNLOCK"
            )

        c.extend.microsoft.unlock_account(dn)

        result = c.result
        if result['description'] == 'success':
            response_result = data['username']
        else:
            c.unbind()
            raise exc_user.CouldNotUnlockUser

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
        validateUser(request=request, requireAdmin=False)
        code = 0
        code_msg = 'ok'
        data = request.data

        if data['username'] != user.username:
            raise PermissionDenied

        # Open LDAP Connection
        try:
            c = LDAPConnector().connection
        except Exception as e:
            print(e)
            raise exc_ldap.CouldNotOpenConnection

        userToUpdate = user.username
        c = self.getUserObject(c, userToUpdate, attributes=[LDAP_AUTH_USERNAME_IDENTIFIER, 'distinguishedName', 'userAccountControl'])
        ldapUser = c.entries

        if 'distinguishedName' in data.keys() and data['distinguishedName'] != "":
            logger.debug('Updating with distinguishedName obtained from front-end')
            logger.debug(data['distinguishedName'])
            distinguishedName = data['distinguishedName']
        else:
            logger.debug('Updating with user dn search method')
            
            distinguishedName = str(ldapUser[0].distinguishedName)
            logger.debug(distinguishedName)

        if ldap_adsi.list_user_perms(ldapUser[0], permissionToSearch="LDAP_UF_PASSWD_CANT_CHANGE"):
            raise PermissionDenied

        if not distinguishedName or distinguishedName == "":
            c.unbind()
            raise exc_user.UserDoesNotExist

        if data['password'] != data['passwordConfirm']:
            c.unbind()
            raise exc_user.UserPasswordsDontMatch

        try:
            c.extend.microsoft.modify_password(
                user=distinguishedName, 
                new_password=data['password']
            )
        except Exception as e:
            c.unbind()
            print(e)
            print(f'Could not update password for User DN: {distinguishedName}')
            data = {
                "ldap_response": c.result
            }
            raise exc_user.UserUpdateError(data=data)

        if LDAP_LOG_UPDATE == True:
            # Log this action to DB
            logToDB(
                user_id=request.user.id,
                actionType="UPDATE",
                objectClass="USER",
                affectedObject=userToUpdate,
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
        validateUser(request=request, requireAdmin=False)
        code = 0
        code_msg = 'ok'
        data = request.data

        if data['username'] != user.username:
            raise PermissionDenied

        ######################## Get Latest Settings ###########################
        authUsernameIdentifier = LDAP_AUTH_USERNAME_IDENTIFIER
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
            c = LDAPConnector().connection
        except Exception as e:
            print(e)
            raise exc_ldap.CouldNotOpenConnection

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
                    c.unbind()
                    raise exc_user.UserUpdateError

        logger.debug(c.result)

        if LDAP_LOG_UPDATE == True:
            # Log this action to DB
            logToDB(
                user_id=request.user.id,
                actionType="UPDATE",
                objectClass="USER",
                affectedObject=userToUpdate,
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
        validateUser(request=request, requireAdmin=False)
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
        validateUser(request=request, requireAdmin=False)
        code = 0
        code_msg = 'ok'
        data = request.data
        userToSearch = user.username

        ######################## Get Latest Settings ###########################
        authUsernameIdentifier = LDAP_AUTH_USERNAME_IDENTIFIER
        authObjectClass = LDAP_AUTH_OBJECT_CLASS
        authSearchBase = LDAP_AUTH_SEARCH_BASE
        ########################################################################

        # Open LDAP Connection
        try:
            c = LDAPConnector(user.dn, user.encryptedPassword, request.user).connection
        except Exception as e:
            print(e)
            raise exc_ldap.CouldNotOpenConnection
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
            'pwdLastSet',
            'userAccountControl'
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

        attributes.remove('userAccountControl')

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

            # Check if user can change password based on perms
            user_dict['can_change_pwd'] = False
            if not ldap_adsi.list_user_perms(user[0], permissionToSearch="LDAP_UF_PASSWD_CANT_CHANGE"):
                user_dict['can_change_pwd'] = True

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
        validateUser(request=request, requireAdmin=False)
        code = 0
        code_msg = 'ok'

        if LDAP_LOG_LOGOUT == True:
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
