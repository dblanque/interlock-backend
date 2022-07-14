from django.core.exceptions import PermissionDenied
from django.db import transaction
from rest_framework.response import Response
from .mixins.user import UserViewMixin
from rest_framework import viewsets
from rest_framework.exceptions import NotFound
from core.exceptions.users import UserExists, UserPermissionError, UserPasswordsDontMatch
from rest_framework.decorators import action
from interlock_backend.ldap_connector import open_connection
from interlock_backend import ldap_settings
from interlock_backend import ldap_adsi
from ldap3 import (
    MODIFY_ADD, 
    MODIFY_DELETE, 
    MODIFY_INCREMENT, 
    MODIFY_REPLACE
)
import traceback
import logging

logger = logging.getLogger(__name__)

# def read_ldap_perms(hex_value):
#     if hex_value

class UserViewSet(viewsets.ViewSet, UserViewMixin):

    def list(self, request):
        user = request.user
        # Check user is_staff
        if user.is_staff == False or not user:
            raise PermissionDenied
        data = []
        code = 0
        code_msg = 'ok'
        # Open LDAP Connection
        c = open_connection()
        attributes = [
            'givenName',
            'sn',
            'displayName',
            ldap_settings.LDAP_AUTH_USERNAME_IDENTIFIER,
            'mail',
            'distinguishedName',
            'userAccountControl'
        ]
        # Have to fix what's below to make it more modular
        if ldap_settings.EXCLUDE_COMPUTER_ACCOUNTS == True:
            objectClassFilter = "(&(objectclass=" + ldap_settings.LDAP_AUTH_OBJECT_CLASS + ")(!(objectclass=computer)))"
        else:
            objectClassFilter = "(objectclass=" + ldap_settings.LDAP_AUTH_OBJECT_CLASS + ")"   
        c.search(
            ldap_settings.LDAP_AUTH_SEARCH_BASE, 
            objectClassFilter, 
            attributes=attributes
        )
        list = c.entries

        # Remove attributes to return as table headers
        valid_attributes = attributes
        remove_attributes = [ 
            'distinguishedName', 
            'userAccountControl', 
            'displayName' 
        ]
        for attr in remove_attributes:
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
                if attr_key == ldap_settings.LDAP_AUTH_USERNAME_IDENTIFIER:
                    user_dict['username'] = str_value

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
        # Check user is_staff
        if user.is_staff == False or not user:
            raise PermissionDenied
        code = 0
        code_msg = 'ok'
        data = request.data
        userToSearch = data["username"]
        # Open LDAP Connection
        c = open_connection()
        attributes = [ 
            'givenName', 
            'sn', 
            'displayName', 
            ldap_settings.LDAP_AUTH_USERNAME_IDENTIFIER, 
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
            'sAMAccountType',
        ]

        objectClassFilter = "(objectclass=" + ldap_settings.LDAP_AUTH_OBJECT_CLASS + ")"

        # Exclude Computer Accounts if settings allow it
        if ldap_settings.EXCLUDE_COMPUTER_ACCOUNTS == True:
            objectClassFilter = ldap_adsi.add_search_filter(objectClassFilter, "!(objectclass=computer)")
        
        # Add filter for username
        objectClassFilter = ldap_adsi.add_search_filter(objectClassFilter, ldap_settings.LDAP_AUTH_USERNAME_IDENTIFIER + "=" + userToSearch)
        c.search(
            ldap_settings.LDAP_AUTH_SEARCH_BASE,
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
            if attr_key == ldap_settings.LDAP_AUTH_USERNAME_IDENTIFIER:
                user_dict['username'] = str_value

        # Check if user is disabled
        if ldap_adsi.list_user_perms(user[0], permissionToSearch="LDAP_UF_ACCOUNT_DISABLE", isObject=False) == True:
            user_dict['is_enabled'] = False
        else:
            user_dict['is_enabled'] = True

        # Check if user is disabled
        userPermissions = ldap_adsi.list_user_perms(user[0], permissionToSearch=None, isObject=False)
        user_dict['permission_list'] = userPermissions

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
        # Check user is_staff
        if user.is_staff == False or not user:
            raise PermissionDenied
        code = 0
        code_msg = 'ok'
        data = request.data

        if data['password'] != data['passwordConfirm']:
            raise UserPasswordsDontMatch

        userToSearch = data["username"]
        # Open LDAP Connection
        c = open_connection()

        attributes = [
            ldap_settings.LDAP_AUTH_USERNAME_IDENTIFIER,
            'distinguishedName',
            'userPrincipalName',
        ]
        objectClassFilter = "(objectclass=" + ldap_settings.LDAP_AUTH_OBJECT_CLASS + ")"

        # Exclude Computer Accounts if settings allow it
        if ldap_settings.EXCLUDE_COMPUTER_ACCOUNTS == True:
            objectClassFilter = ldap_adsi.add_search_filter(objectClassFilter, "!(objectclass=computer)")

        # Add filter for username
        objectClassFilter = ldap_adsi.add_search_filter(objectClassFilter, ldap_settings.LDAP_AUTH_USERNAME_IDENTIFIER + "=" + userToSearch)

        c.search(
            ldap_settings.LDAP_AUTH_SEARCH_BASE, 
            objectClassFilter, 
            attributes=attributes
        )
        user = c.entries
        userDN = 'CN='+data['username']+','+data['path'] or 'CN='+data['username']+',OU=Users,'+ldap_settings.LDAP_AUTH_SEARCH_BASE
        userPermissions = 0

        # Add permissions selected in user creation
        for perm in data['permission_list']:
            permValue = int(ldap_adsi.LDAP_PERMS[perm]['value'])
            try:
                userPermissions += permValue
                logger.debug("Permission Value added (cast to string): " + str(permValue))
            except Exception as error:
                # If there's an error unbind the connection and print traceback
                c.unbind()
                print(traceback.format_exc())
                raise UserPermissionError # Return error code to client

        # Add Normal Account permission to list
        userPermissions += ldap_adsi.LDAP_PERMS['LDAP_UF_NORMAL_ACCOUNT']['value']
        logger.debug("Final User Permissions Value: " + str(userPermissions))

        arguments = dict()
        arguments['userAccountControl'] = userPermissions

        excludeKeys = ['password', 'passwordConfirm', 'path', 'permission_list', 'distinguishedName', 'username']
        for key in data:
            if key not in excludeKeys:
                arguments[key] = data[key]
                print(key)
                print(data[key])

        arguments['sAMAccountName'] = str(arguments['sAMAccountName']).lower()
        arguments['objectClass'] = ['top', 'person', 'organizationalPerson', 'user']
        arguments['userPrincipalName'] = data['username'] + '@' + ldap_settings.LDAP_DOMAIN
        # If user exists, return error
        if user != []:
            raise UserExists
        # Else, create the user and set its password
        else:
            logger.debug('Creating user in DN Path: ' + userDN)
            c.add(userDN, ldap_settings.LDAP_AUTH_OBJECT_CLASS, attributes=arguments)
            # TODO - Test if password changes correctly?
            c.extend.microsoft.modify_password(userDN, data['password'])
        # Unbind the connection
        c.unbind()
        return Response(
             data={
                'code': code,
                'code_msg': code_msg
             }
        )

    # TODO
    @action(detail=False,methods=['post'])
    def edit(self, request):
        user = request.user
        # Check user is_staff
        if user.is_staff == False or not user:
            raise PermissionDenied
        code = 0
        code_msg = 'ok'
        data = request.data

        userToEdit = data['username']
        # Open LDAP Connection
        c = open_connection()

        # Unbind the connection
        c.unbind()
        return Response(
             data={
                'code': code,
                'code_msg': code_msg
             }
        )

    @action(detail=False,methods=['post'])
    def disable(self, request):
        user = request.user
        # Check user is_staff
        if user.is_staff == False or not user:
            raise PermissionDenied
        code = 0
        code_msg = 'ok'
        data = request.data

        userToEnable = data['username']
        # Open LDAP Connection
        c = open_connection()

        attributes = [
            ldap_settings.LDAP_AUTH_USERNAME_IDENTIFIER,
            'distinguishedName',
            'userPrincipalName',
            'userAccountControl',
        ]
        objectClassFilter = "(objectclass=" + ldap_settings.LDAP_AUTH_OBJECT_CLASS + ")"

        # Exclude Computer Accounts if settings allow it
        if ldap_settings.EXCLUDE_COMPUTER_ACCOUNTS == True:
            objectClassFilter = ldap_adsi.add_search_filter(objectClassFilter, "!(objectclass=computer)")

        # Add filter for username
        objectClassFilter = ldap_adsi.add_search_filter(
            objectClassFilter, 
            ldap_settings.LDAP_AUTH_USERNAME_IDENTIFIER + "=" + userToEnable
            )

        c.search(
            ldap_settings.LDAP_AUTH_SEARCH_BASE, 
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
            raise UserPermissionError

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

    @action(detail=False,methods=['post'])
    def enable(self, request):
        user = request.user
        # Check user is_staff
        if user.is_staff == False or not user:
            raise PermissionDenied
        code = 0
        code_msg = 'ok'
        data = request.data

        userToEnable = data['username']
        # Open LDAP Connection
        c = open_connection()

        attributes = [
            ldap_settings.LDAP_AUTH_USERNAME_IDENTIFIER,
            'distinguishedName',
            'userPrincipalName',
            'userAccountControl'
        ]
        objectClassFilter = "(objectclass=" + ldap_settings.LDAP_AUTH_OBJECT_CLASS + ")"

        # Exclude Computer Accounts if settings allow it
        if ldap_settings.EXCLUDE_COMPUTER_ACCOUNTS == True:
            objectClassFilter = ldap_adsi.add_search_filter(objectClassFilter, "!(objectclass=computer)")

        # Add filter for username
        objectClassFilter = ldap_adsi.add_search_filter(
            objectClassFilter, 
            ldap_settings.LDAP_AUTH_USERNAME_IDENTIFIER + "=" + userToEnable
            )

        c.search(
            ldap_settings.LDAP_AUTH_SEARCH_BASE, 
            objectClassFilter, 
            attributes=attributes
        )

        user = c.entries
        dn = str(user[0].distinguishedName)
        print(dn)
        permList = ldap_adsi.list_user_perms(user[0], isObject=False)
        
        try:
            newPermINT = ldap_adsi.calc_permissions(permList, removePerm='LDAP_UF_ACCOUNT_DISABLE')
        except:
            print(traceback.format_exc())
            raise UserPermissionError

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

    def create(self, request, pk=None):
        raise NotFound

    def put(self, request, pk=None):
        raise NotFound

    def patch(self, request, pk=None):
        raise NotFound
        
    def retrieve(self, request, pk=None):
        raise NotFound

    def update(self, request, pk=None):
        raise NotFound

    def partial_update(self, request, pk=None):
        raise NotFound

    def destroy(self, request, pk=None):
        raise NotFound

    def delete(self, request, pk=None):
        raise NotFound

    @action(detail=False, methods=['get'])
    @transaction.atomic
    def me(self, request):
        user = request.user
        if user.is_staff == False or not user:
            raise PermissionDenied
        data = {}
        code = 0
        data["username"] = request.user.username or ""
        data["first_name"] = request.user.first_name or ""
        data["last_name"] = request.user.last_name or ""
        data["email"] = request.user.email or ""
        return Response(
             data={
                'code': code,
                'code_msg': 'ok',
                'user': data
             }
        )