from email.headerregistry import Group
from .base import BaseViewSet
from .mixins.group import GroupViewMixin
from core.exceptions import ldap as ldap_exceptions
from core.models import Log
from rest_framework.response import Response
from rest_framework.decorators import action
from interlock_backend.ldap import adsi as ldap_adsi
from interlock_backend.ldap.encrypt import validateUser
from interlock_backend.ldap.connector import openLDAPConnection
from interlock_backend.ldap.adsi import addSearchFilter, getLDAPObject
from interlock_backend.ldap.settings_func import SettingsList
from interlock_backend.ldap.groupTypes import LDAP_GROUP_TYPES
from ldap3 import ALL_ATTRIBUTES

class GroupsViewSet(BaseViewSet, GroupViewMixin):

    def list(self, request):
        user = request.user
        validateUser(request=request, requestUser=user)
        data = []
        code = 0
        code_msg = 'ok'

        ######################## Get Latest Settings ###########################
        ldap_settings_list = SettingsList()
        groupObjectClass = 'group'
        authSearchBase = ldap_settings_list.LDAP_AUTH_SEARCH_BASE
        ########################################################################

        # Open LDAP Connection
        try:
            c = openLDAPConnection(user.dn, user.encryptedPassword, request.user)
        except Exception as e:
            print(e)
            raise ldap_exceptions.CouldNotOpenConnection
        attributes = [
            'cn',
            'distinguishedName',
            'groupType',
            'member'
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
            # For each attribute in group object attributes
            group_dict = {}
            for attr_key in dir(group):
                # Parse Group Type
                if attr_key == 'groupType':
                    groupVal = int(str(getattr(group, attr_key)))
                    group_dict[attr_key] = self.getGroupType(groupTypeInt=groupVal)
                # Do the standard for every other key
                elif attr_key in valid_attributes:
                    str_key = str(attr_key)
                    str_value = str(getattr(group, attr_key))
                    if str_value == "[]":
                        group_dict[str_key] = ""
                    else:
                        group_dict[str_key] = str_value

            # Check if group has Members
            if str(getattr(group, 'member')) == "[]" or getattr(group, 'member') is None:
                group_dict['hasMembers'] = False
            else:
                group_dict['hasMembers'] = True

            # Add entry DN to response dictionary
            group_dict['dn'] = group.entry_dn

            data.append(group_dict)

        valid_attributes.append('hasMembers')

        # Log this action to DB
        logAction = Log(
            user_id=request.user.id,
            actionType="READ",
            objectClass="GROUP",
            affectedObject="ALL"
        )
        logAction.save()

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
        user = request.user
        validateUser(request=request, requestUser=user)
        data = []
        code = 0
        code_msg = 'ok'

        groupDnSearch = request.data['group']

        ######################## Get Latest Settings ###########################
        ldap_settings_list = SettingsList()
        groupObjectClass = 'group'
        authSearchBase = ldap_settings_list.LDAP_AUTH_SEARCH_BASE
        authUsernameIdentifier = ldap_settings_list.LDAP_AUTH_USERNAME_IDENTIFIER
        ########################################################################

        # Open LDAP Connection
        try:
            c = openLDAPConnection(user.dn, user.encryptedPassword, request.user)
        except Exception as e:
            print(e)
            raise ldap_exceptions.CouldNotOpenConnection
        attributes = [
            'cn',
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

        # For each attribute in group object attributes
        group_dict = {}
        for attr_key in dir(group[0]):
            if attr_key in valid_attributes:
                str_key = str(attr_key)
                str_value = str(getattr(group[0],attr_key))
                if str_value == "[]":
                    group_dict[str_key] = ""
                # Parse Group Type
                elif str_key == 'groupType':
                    groupVal = int(str(getattr(group[0], str_key)))
                    group_dict[str_key] = self.getGroupType(groupTypeInt=groupVal)
                elif str_key == 'member':
                    memberArray = []
                    memberAttributes = [
                        'cn',
                        'distinguishedName',
                        authUsernameIdentifier,
                        'givenName',
                        'sn',
                        'objectCategory'
                    ]
                    for u in getattr(group[0], str_key):
                        c = ldap_adsi.getLDAPObject(c, u, attributes=memberAttributes, objectClassFilter=addSearchFilter("", "distinguishedName="+u))
                        result = c.entries
                        memberObject = {}
                        for attr in memberAttributes:
                            if attr in result[0]:
                                attrValue = str(result[0][attr])
                                if attr == 'objectCategory':
                                    memberObject[attr] = attrValue.split(',')[0].split('=')[-1].lower()
                                elif attr == authUsernameIdentifier:
                                    memberObject['username'] = attrValue.split(',')[0].split('=')[-1].lower()
                                elif attrValue == "[]":
                                    memberObject[attr] = ""
                                else:
                                    memberObject[attr] = attrValue
                        memberArray.append(memberObject)
                    group_dict[str_key] = memberArray
                # Do the standard for every other key
                else:
                    group_dict[str_key] = str_value

            # Add entry DN to response dictionary
            group_dict['dn'] = group[0].entry_dn

        # Log this action to DB
        logAction = Log(
            user_id=request.user.id,
            actionType="READ",
            objectClass="GROUP",
            affectedObject=group_dict['cn']
        )
        logAction.save()

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
