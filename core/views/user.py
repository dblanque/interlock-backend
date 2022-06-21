from django.core.exceptions import PermissionDenied
from django.db import transaction
from rest_framework.response import Response
from .mixins.user import UserViewMixin
from rest_framework import viewsets
from rest_framework.exceptions import NotFound
from rest_framework.decorators import action
from interlock_backend.ldap_connector import open_connection
from interlock_backend import ldap_settings
from interlock_backend import ldap_adsi

# def read_ldap_perms(hex_value):
#     if hex_value

class UserViewSet(viewsets.ViewSet, UserViewMixin):

    # def list(self, request, pk=None):
    #     raise NotFound

    def list(self, request):
        user = request.user
        # Check user is_staff
        if user.is_staff == False or not user:
            raise PermissionDenied
        # Open LDAP Connection
        c = open_connection()
        attributes = [ 'sAMAccountName', 'givenName', 'sn', 'displayName', 'mail', 'distinguishedName', 'userAccountControl' ]
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
        # Close / Unbind LDAP Connection
        data = []
        code = 0
        code_msg = 'ok'

        valid_attributes = attributes
        # Remove attributes to return as table headers
        remove_attributes = [ 'distinguishedName' ]
        for attr in remove_attributes:
            valid_attributes.remove(str(attr))

        for user in list:
            
            if str(user.sAMAccountName) == 'jblanque':
                userperm = ldap_adsi.convert_to_bin(user.userAccountControl)
                i = 0
                for n in range(0, 32):
                    i += 1
                    if userperm[n] == "1":
                        print(n)
                        # perm_binary = ldap_adsi.LDAP_PERMS[perm_name]
                        # print(perm_binary)
            # Uncomment line below to see all attributes in user object
            # print(dir(user))
            uac_as_int = int(str(user.userAccountControl))
            uac_as_hex = hex(uac_as_int)
            disabled = 0

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
                    # print(str_key + " is " + str_value)
            data.append(user_dict)

        # print(data)
        c.unbind()
        return Response(
             data={
                'code': code,
                'code_msg': code_msg,
                'users': data,
                'headers': valid_attributes
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