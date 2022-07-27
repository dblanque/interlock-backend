from .base import BaseViewSet
from .mixins.group import GroupViewMixin
from core.exceptions import ldap as ldap_exceptions
from rest_framework.response import Response
from rest_framework.decorators import action
from interlock_backend.ldap import adsi as ldap_adsi
from interlock_backend.ldap.encrypt import validateUser
from interlock_backend.ldap.connector import openLDAPConnection
from interlock_backend.ldap.adsi import addSearchFilter
from interlock_backend.ldap.settings_func import SettingsList
from interlock_backend.ldap.groupTypes import LDAP_GROUP_TYPES
from ldap3 import ALL_ATTRIBUTES

class GroupsViewSet(BaseViewSet, GroupViewMixin):

    def list(self, request):
        group = request.user
        validateUser(request=request, requestUser=group)
        data = []
        code = 0
        code_msg = 'ok'

        ######################## Get Latest Settings ###########################
        ldap_settings_list = SettingsList()
        authUsernameIdentifier = ldap_settings_list.LDAP_AUTH_USERNAME_IDENTIFIER
        groupObjectClass = 'group'
        authSearchBase = ldap_settings_list.LDAP_AUTH_SEARCH_BASE
        ########################################################################

        # Open LDAP Connection
        try:
            c = openLDAPConnection(group.dn, group.encryptedPassword)
        except Exception as e:
            print(e)
            raise ldap_exceptions.CouldNotOpenConnection
        attributes = [
            'cn',
            'displayName',
            authUsernameIdentifier,
            'mail',
            'member',
            'distinguishedName'
        ]

        objectClassFilter = ""
        objectClassFilter = addSearchFilter(objectClassFilter, "objectclass=" + groupObjectClass)

        c.search(
            authSearchBase, 
            objectClassFilter,
            attributes=attributes
        )
        list = c.entries

        # Remove attributes to return as table headers
        valid_attributes = attributes
        remove_attributes = [
            'distinguishedName',
            'member'
        ]

        for attr in remove_attributes:
            if attr in valid_attributes:
                valid_attributes.remove(str(attr))

        for group in list:
            # For each attribute in user object attributes
            group_dict = {}
            for attr_key in dir(group):
                if attr_key in valid_attributes:
                    str_key = str(attr_key)
                    str_value = str(getattr(group,attr_key))
                    if str_value == "[]":
                        group_dict[str_key] = ""
                    else:
                        group_dict[str_key] = str_value

            # Add entry DN to response dictionary
            group_dict['dn'] = group.entry_dn

            data.append(group_dict)

        # Close / Unbind LDAP Connection
        c.unbind()
        return Response(
             data={
                'code': code,
                'code_msg': code_msg,
                'groups': data,
                'headers': valid_attributes
             }
        )

    @action(detail=False,methods=['post'])
    def fetch(self, request):
        group = request.user
        validateUser(request=request, requestUser=group)
        data = []
        code = 0
        code_msg = 'ok'

        groupDnSearch = request.data['group']

        ######################## Get Latest Settings ###########################
        ldap_settings_list = SettingsList()
        authUsernameIdentifier = ldap_settings_list.LDAP_AUTH_USERNAME_IDENTIFIER
        groupObjectClass = 'group'
        authSearchBase = ldap_settings_list.LDAP_AUTH_SEARCH_BASE
        ########################################################################

        # Open LDAP Connection
        try:
            c = openLDAPConnection(group.dn, group.encryptedPassword)
        except Exception as e:
            print(e)
            raise ldap_exceptions.CouldNotOpenConnection
        attributes = [
            'cn',
            'displayName',
            authUsernameIdentifier,
            'mail',
            'member',
            'distinguishedName',
            'groupType'
        ]

        objectClassFilter = ""
        objectClassFilter = addSearchFilter(objectClassFilter, "objectclass=" + groupObjectClass)
        objectClassFilter = addSearchFilter(objectClassFilter, "distinguishedName=" + groupDnSearch)

        c.search(
            authSearchBase, 
            objectClassFilter,
            attributes=attributes
        )
        group = c.entries

        # Remove attributes to return as table headers
        valid_attributes = attributes
        remove_attributes = [
            'distinguishedName',
            # 'member'
        ]

        for attr in remove_attributes:
            if attr in valid_attributes:
                valid_attributes.remove(str(attr))

        # For each attribute in user object attributes
        group_dict = {}
        for attr_key in dir(group[0]):
            if attr_key in valid_attributes:
                str_key = str(attr_key)
                str_value = str(getattr(group[0],attr_key))
                if str_value == "[]":
                    group_dict[str_key] = ""
                else:
                    group_dict[str_key] = str_value

            # Add entry DN to response dictionary
            group_dict['dn'] = group[0].entry_dn

        # Close / Unbind LDAP Connection
        c.unbind()
        return Response(
             data={
                'code': code,
                'code_msg': code_msg,
                'data': group_dict,
                'headers': valid_attributes
             }
        )