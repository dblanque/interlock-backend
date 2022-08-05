################################## IMPORTS #####################################
### Exceptions
from ast import arguments
from copy import deepcopy
from core.exceptions import ldap as exc_ldap
from core.exceptions import groups as exc_groups

### Models
from core.models.log import logToDB
from core.models.ldapObject import LDAPObject

### Mixins
from .mixins.group import GroupViewMixin
from core.views.mixins.user import UserViewMixin

### ViewSets
from .base import BaseViewSet

### REST Framework
from rest_framework.response import Response
from rest_framework.decorators import action

### Others
from interlock_backend.ldap.encrypt import validateUser
from interlock_backend.ldap.connector import LDAPConnector
from interlock_backend.ldap.adsi import addSearchFilter
from interlock_backend.ldap.settings_func import SettingsList
from interlock_backend.ldap.securityIdentifier import SID
from interlock_backend.ldap.constants import LDAP_GROUP_TYPES, LDAP_GROUP_SCOPES
import logging
################################################################################

logger = logging.getLogger(__name__)

class GroupsViewSet(BaseViewSet, GroupViewMixin):

    def list(self, request):
        user = request.user
        validateUser(request=request, requestUser=user)
        data = []
        code = 0
        code_msg = 'ok'

        ######################## Get Latest Settings ###########################
        ldap_settings_list = SettingsList(**{"search":{
            'LDAP_AUTH_SEARCH_BASE',
            'LDAP_LOG_READ'
        }})
        groupObjectClass = 'group'
        authSearchBase = ldap_settings_list.LDAP_AUTH_SEARCH_BASE
        ########################################################################

        # Open LDAP Connection
        try:
            c = LDAPConnector(user.dn, user.encryptedPassword, request.user).connection
        except Exception as e:
            print(e)
            raise exc_ldap.CouldNotOpenConnection
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
            group_dict['distinguishedName'] = group.entry_dn

            data.append(group_dict)

        valid_attributes.append('hasMembers')

        if ldap_settings_list.LDAP_LOG_READ == True:
            # Log this action to DB
            logToDB(
                user_id=request.user.id,
                actionType="READ",
                objectClass="GROUP",
                affectedObject="ALL"
            )

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
        ldap_settings_list = SettingsList(**{"search":{
            'LDAP_AUTH_SEARCH_BASE',
            'LDAP_AUTH_USERNAME_IDENTIFIER',
            'LDAP_LOG_READ'
        }})
        groupObjectClass = 'group'
        authSearchBase = ldap_settings_list.LDAP_AUTH_SEARCH_BASE
        authUsernameIdentifier = ldap_settings_list.LDAP_AUTH_USERNAME_IDENTIFIER
        ########################################################################

        # Open LDAP Connection
        try:
            c = LDAPConnector(user.dn, user.encryptedPassword, request.user).connection
        except Exception as e:
            print(e)
            raise exc_ldap.CouldNotOpenConnection
        attributes = [
            'cn',
            'mail',
            'member',
            'distinguishedName',
            'groupType',
            'objectSid'
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
                realValue = getattr(group[0],attr_key)
                str_value = str(realValue)
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
                        'objectCategory',
                        'objectClass'
                    ]
                    # Fetch members
                    for u in getattr(group[0], str_key):
                        args = {
                            "connection": c,
                            "dn": u,
                            "ldapAttributes": memberAttributes
                        }
                        memberObject = LDAPObject(**args)
                        c = memberObject.__getConnection__()
                        memberArray.append(memberObject.attributes)
                    group_dict[str_key] = memberArray
                # Do the standard for every other key
                elif str_key == 'objectSid':
                    sid = SID(realValue)
                    sid = sid.__str__()
                    rid = sid.split("-")[-1]
                    group_dict[str_key] = sid
                    group_dict['objectRid'] = rid
                else:
                    group_dict[str_key] = str_value

            # Add entry DN to response dictionary
            group_dict['distinguishedName'] = group[0].entry_dn

        if ldap_settings_list.LDAP_LOG_READ == True:
            # Log this action to DB
            logToDB(
                user_id=request.user.id,
                actionType="READ",
                objectClass="GROUP",
                affectedObject=group_dict['cn']
            )

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

    @action(detail=False,methods=['post'])
    def insert(self, request):
        user = request.user
        validateUser(request=request, requestUser=user)
        code = 0
        code_msg = 'ok'
        data = request.data

        ######################## Get Latest Settings ###########################
        ldap_settings_list = SettingsList(**{"search":{
            'LDAP_DOMAIN',
            'LDAP_AUTH_SEARCH_BASE',
            'LDAP_LOG_CREATE'
        }})
        authDomain = ldap_settings_list.LDAP_DOMAIN
        authSearchBase = ldap_settings_list.LDAP_AUTH_SEARCH_BASE
        ########################################################################

        # Open LDAP Connection
        try:
            c = LDAPConnector(user.dn, user.encryptedPassword, request.user).connection
        except Exception as e:
            c.unbind()
            print(e)
            raise exc_ldap.CouldNotOpenConnection

        groupToCreate = data['group']
        
        if groupToCreate['path'] is not None and groupToCreate['path'] != "":
            distinguishedName = "cn=" + groupToCreate['cn'] + "," + groupToCreate['path']
        else:
            distinguishedName = 'CN='+groupToCreate['cn']+',OU=Users,'+authSearchBase

        groupToCreate['sAMAccountName'] = str(groupToCreate['cn']).lower()
        # Send LDAP Query for user being created to see if it exists
        attributes = [
            'cn',
            'distinguishedName',
            'userPrincipalName',
        ]
        ldapFilter = addSearchFilter("", "cn="+groupToCreate['cn'])
        args = {
            "connection": c,
            "ldapFilter": ldapFilter,
            "ldapAttributes": attributes,
            "hideErrors": True
        }

        # !!! CHECK IF GROUP EXISTS !!! #
        try:
            groupExists = LDAPObject(**args).attributes
            groupExists = len(groupExists) > 0
        except:
            groupExists = False

        # If group exists, return error
        if groupExists == True:
            exception = exc_groups.GroupExists
            data = {
                "code": exception.default_code,
                "group": groupToCreate['cn']
            }
            exception.setDetail(exception, data)
            c.unbind()
            raise exception

        # Set group Type
        if 'groupType' not in groupToCreate or 'groupScope' not in groupToCreate:
            exception = exc_groups.GroupScopeOrTypeMissing
            data = {
                "code": exception.default_code,
                "group": groupToCreate['cn']
            }
            exception.setDetail(exception, data)
            c.unbind()
            raise exception

        sum = LDAP_GROUP_TYPES[int(groupToCreate['groupType'])]
        sum += LDAP_GROUP_SCOPES[int(groupToCreate['groupScope'])]
        groupToCreate['groupType'] = sum
        groupToCreate.pop('groupScope')

        excludeKeys = [
            'member', 
            'path'
        ]

        group_dict = deepcopy(groupToCreate)
        for key in groupToCreate:
            if key in excludeKeys:
                logger.debug("Removing key from dictionary: " + key)
                group_dict.pop(key)

        group_dict['cn'] = group_dict['cn'].capitalize()
        if 'membersToAdd' in group_dict:
            membersToAdd = group_dict.pop('membersToAdd')

        logger.debug('Creating group in DN Path: ' + groupToCreate['path'])
        try:
            c.add(distinguishedName, 'group', attributes=group_dict)
        except Exception as e:
            c.unbind()
            print(e)
            raise exc_groups.GroupCreate

        if len(membersToAdd) > 0:
            try:
                c.extend.microsoft.add_members_to_groups(membersToAdd, distinguishedName)
            except Exception as e:
                c.delete(distinguishedName)
                c.unbind()
                print(e)
                raise exc_groups.GroupMembersAdd

        if ldap_settings_list.LDAP_LOG_CREATE == True:
            # Log this action to DB
            logToDB(
                user_id=request.user.id,
                actionType="CREATE",
                objectClass="GROUP",
                affectedObject=group_dict['cn']
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
    def delete(self, request, pk=None):
        user = request.user
        validateUser(request=request, requestUser=user)
        code = 0
        code_msg = 'ok'
        data = request.data

        ldap_settings_list = SettingsList(**{"search":{
            'LDAP_LOG_DELETE'
        }})

        if 'cn' not in data:
            print(data)
            raise exc_groups.GroupDoesNotExist

        if 'distinguishedName' in data:
            distinguishedName = data['distinguishedName']
        else:
            print(data)
            raise exc_groups.GroupDoesNotExist

        # Open LDAP Connection
        try:
            c = LDAPConnector(user.dn, user.encryptedPassword, request.user).connection
        except Exception as e:
            print(e)
            raise exc_ldap.CouldNotOpenConnection

        try:
            c.delete(distinguishedName)
        except:
            c.unbind()
            raise exc_groups.GroupDelete

        if ldap_settings_list.LDAP_LOG_DELETE == True:
            # Log this action to DB
            logToDB(
                user_id=request.user.id,
                actionType="DELETE",
                objectClass="GROUP",
                affectedObject=data['cn']
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
