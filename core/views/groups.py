################################################################################
#################### INTERLOCK IS LICENSED UNDER GNU AGPLv3 ####################
################## ORIGINAL PROJECT CREATED BY DYLAN BLANQUÉ ###################
########################## AND BR CONSULTING S.R.L. ############################
################################################################################
# Module: core.views.groups
# Contains the ViewSet for Group related operations

#---------------------------------- IMPORTS -----------------------------------#
### Exceptions
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
from ldap3 import (
    MODIFY_ADD,
    MODIFY_DELETE,
    MODIFY_INCREMENT,
    MODIFY_REPLACE
)
from interlock_backend.ldap.encrypt import validateUser
from interlock_backend.ldap.connector import LDAPConnector
from interlock_backend.ldap.adsi import addSearchFilter
from interlock_backend.ldap.securityIdentifier import SID
from interlock_backend.ldap.constants import LDAP_GROUP_TYPE_MAPPING, LDAP_GROUP_SCOPE_MAPPING
from interlock_backend.ldap.constants_cache import *
import logging
import traceback
################################################################################

logger = logging.getLogger(__name__)

class GroupsViewSet(BaseViewSet, GroupViewMixin):

    def list(self, request):
        user = request.user
        validateUser(request=request)
        data = []
        code = 0
        code_msg = 'ok'

        ######################## Get Latest Settings ###########################
        groupObjectClass = 'group'
        authSearchBase = LDAP_AUTH_SEARCH_BASE
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

        if LDAP_LOG_READ == True:
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
        validateUser(request=request)
        data = []
        code = 0
        code_msg = 'ok'

        groupDnSearch = request.data['group']

        ######################## Get Latest Settings ###########################
        groupObjectClass = 'group'
        authSearchBase = LDAP_AUTH_SEARCH_BASE
        authUsernameIdentifier = LDAP_AUTH_USERNAME_IDENTIFIER
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
                    group_dict['objectRid'] = int(rid)
                else:
                    group_dict[str_key] = str_value

                if group_dict[str_key] == "":
                    del group_dict[str_key]

            # Add entry DN to response dictionary
            group_dict['distinguishedName'] = str(group[0].entry_dn)

        if LDAP_LOG_READ == True:
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
        validateUser(request=request)
        code = 0
        code_msg = 'ok'
        data = request.data

        ######################## Get Latest Settings ###########################
        authUsernameIdentifier = LDAP_AUTH_USERNAME_IDENTIFIER
        authDomain = LDAP_DOMAIN
        authSearchBase = LDAP_AUTH_SEARCH_BASE
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
        
        #Make sure Group doesn't exist check with CN and authUserField
        ldapFilter = addSearchFilter("", "cn="+groupToCreate['cn'])
        ldapFilter = addSearchFilter(ldapFilter, authUsernameIdentifier+"="+groupToCreate['cn'], "|")
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
            c.unbind()
            data = {
                "group": groupToCreate['cn']
            }
            raise exc_ldap.LDAPObjectExists(data=data)

        # Set group Type
        if 'groupType' not in groupToCreate or 'groupScope' not in groupToCreate:
            c.unbind()
            data = {
                "group": groupToCreate['cn']
            }
            raise exc_groups.GroupScopeOrTypeMissing(data=data)

        sum = LDAP_GROUP_TYPE_MAPPING[int(groupToCreate['groupType'])]
        sum += LDAP_GROUP_SCOPE_MAPPING[int(groupToCreate['groupScope'])]
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
        else:
            membersToAdd = list()

        logger.debug('Creating group in DN Path: ' + groupToCreate['path'])
        try:
            c.add(distinguishedName, 'group', attributes=group_dict)
        except Exception as e:
            c.unbind()
            print(e)
            data = {
                "ldap_response": c.result
            }
            raise exc_groups.GroupCreate(data=data)

        if len(membersToAdd) > 0:
            try:
                c.extend.microsoft.add_members_to_groups(membersToAdd, distinguishedName)
            except Exception as e:
                try:
                    c.delete(distinguishedName)
                    data = {
                        "ldap_response": c.result
                    }
                    raise exc_groups.GroupMembersAdd
                except Exception as e:
                    c.unbind()
                c.unbind()
                print(e)
                data = {
                    "ldap_response": c.result
                }
                raise exc_groups.GroupMembersAdd

        if LDAP_LOG_CREATE == True:
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

    def update(self, request, pk=None):
        user = request.user
        validateUser(request=request)
        code = 0
        code_msg = 'ok'
        data = request.data

        # Open LDAP Connection
        try:
            c = LDAPConnector(user.dn, user.encryptedPassword, request.user).connection
        except Exception as e:
            c.unbind()
            print(e)
            raise exc_ldap.CouldNotOpenConnection

        groupToUpdate = data['group']

        if 'distinguishedName' not in groupToUpdate:
            raise exc_groups.GroupDistinguishedNameMissing
        else:
            distinguishedName = groupToUpdate['distinguishedName']

        groupToUpdate['sAMAccountName'] = str(groupToUpdate['cn']).lower()
        # Send LDAP Query for user being created to see if it exists
        attributes = list(groupToUpdate.keys())
        args = {
            "connection": c,
            "dn": distinguishedName,
            "ldapAttributes": attributes,
            "hideErrors": True
        }

        # !!! CHECK IF GROUP EXISTS !!! #
        # We also need to fetch the existing LDAP group object to know what
        # kind of operation to apply when updating attributes
        try:
            groupEntryInServer = LDAPObject(**args).attributes
            groupEntryInServer_cond = len(groupEntryInServer) > 0
        except:
            groupEntryInServer_cond = False

        # If group exists, return error
        if groupEntryInServer_cond == False:
            c.unbind()
            data = {
                "group": groupToUpdate['cn']
            }
            raise exc_groups.GroupDoesNotExist(data=data)

        # Set group Type
        if 'groupType' not in groupToUpdate or 'groupScope' not in groupToUpdate:
            c.unbind()
            data = {
                "group": groupToUpdate['cn']
            }
            raise exc_groups.GroupScopeOrTypeMissing(data=data)

        castGroupType = int(groupToUpdate['groupType'])
        castGroupScope = int(groupToUpdate['groupScope'])
        sum = LDAP_GROUP_TYPE_MAPPING[castGroupType]
        sum += LDAP_GROUP_SCOPE_MAPPING[castGroupScope]
        groupToUpdate['groupType'] = sum
        groupToUpdate.pop('groupScope')

        excludeKeys = [
            'cn',
            'member', 
            'path',
            'distinguishedName',
            'objectSid',
            'objectRid'
        ]

        group_dict = deepcopy(groupToUpdate)
        for key in groupToUpdate:
            if key in excludeKeys:
                logger.debug("Removing key from dictionary: " + key)
                group_dict.pop(key)

        if 'membersToAdd' in data and 'membersToRemove' in data:
            if data['membersToAdd'] == data['membersToRemove'] and data['membersToAdd'] != list():
                c.unbind()
                print(data)
                raise exc_groups.BadMemberSelection

        if 'membersToAdd' in group_dict:
            membersToAdd = group_dict.pop('membersToAdd')
        else:
            membersToAdd = None
        if 'membersToRemove' in group_dict:
            membersToRemove = group_dict.pop('membersToRemove')
        else:
            membersToRemove = None

        # We need to check if the attributes exist in the LDAP Object already
        # To know what operation to apply. This is VERY important.
        arguments = dict()
        operation = None
        for key in group_dict:
                try:
                    if key in groupEntryInServer and group_dict[key] == "" and key != 'groupType':
                        operation = MODIFY_DELETE
                        c.modify(
                            distinguishedName,
                            {key: [( operation ), []]},
                        )
                    elif group_dict[key] != "":
                        operation = MODIFY_REPLACE
                        if key == 'groupType':
                            previousGroupTypes = self.getGroupType(groupTypeInt=int(groupEntryInServer[key]))
                            # If we're trying to go from Group Global to Domain Local Scope or viceversa
                            # We need to make it universal first, otherwise the LDAP server denies the update request
                            # Sucks but we have to do this :/
                            if ('GROUP_GLOBAL' in previousGroupTypes and castGroupScope == 1) or ('GROUP_DOMAIN_LOCAL' in previousGroupTypes and castGroupScope == 0):
                                passthroughSum = LDAP_GROUP_TYPE_MAPPING[castGroupType]
                                passthroughSum += LDAP_GROUP_SCOPE_MAPPING[2]
                                print(passthroughSum)
                                print(group_dict[key])
                                # Change to Universal Scope
                                c.modify(
                                    distinguishedName,
                                    {key: [( operation, [ passthroughSum ])]},
                                )
                                # Change to Target Scope (Global or Domain Local)
                                c.modify(
                                    distinguishedName,
                                    {key: [( operation, [ group_dict[key] ])]},
                                )
                            else:
                                c.modify(
                                    distinguishedName,
                                    {key: [( operation, [ group_dict[key] ])]},
                                )
                        else:
                            if isinstance(group_dict[key], list):
                                c.modify(
                                    distinguishedName,
                                    {key: [( operation, group_dict[key])]},
                                )
                            else:
                                c.modify(
                                    distinguishedName,
                                    {key: [( operation, [ group_dict[key] ])]},
                                )
                    else:
                        logger.info("No suitable operation for attribute " + key)
                        pass
                except:
                    print(traceback.format_exc())
                    logger.warn("Unable to update group '" + str(groupToUpdate['cn']) + "' with attribute '" + str(key) + "'")
                    logger.warn("Attribute Value:" + str(group_dict[key]))
                    if operation is not None:
                        logger.warn("Operation Type: " + str(operation))
                    c.unbind()
                    raise exc_groups.GroupUpdate

        logger.debug(c.result)

        if membersToAdd is not None:
            if len(membersToAdd) > 0:
                try:
                    c.extend.microsoft.add_members_to_groups(membersToAdd, distinguishedName)
                except Exception as e:
                    c.unbind()
                    print(e)
                    raise exc_groups.GroupMembersAdd

        if membersToRemove is not None:
            if len(membersToRemove) > 0:
                try:
                    c.extend.microsoft.remove_members_from_groups(membersToRemove, distinguishedName)
                except Exception as e:
                    c.unbind()
                    print(e)
                    raise exc_groups.GroupMembersRemove

        if LDAP_LOG_UPDATE == True:
            # Log this action to DB
            logToDB(
                user_id=request.user.id,
                actionType="UPDATE",
                objectClass="GROUP",
                affectedObject=groupToUpdate['cn']
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
        validateUser(request=request)
        code = 0
        code_msg = 'ok'
        data = request.data
        groupToDelete = data['group']

        if 'cn' not in groupToDelete:
            print(groupToDelete)
            raise exc_groups.GroupDoesNotExist

        if 'distinguishedName' in groupToDelete:
            distinguishedName = groupToDelete['distinguishedName']
        else:
            print(groupToDelete)
            raise exc_groups.GroupDoesNotExist

        if str(groupToDelete['cn']).startswith("Domain "):
            print(groupToDelete)
            raise exc_groups.GroupBuiltinProtect

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
            data = {
                "ldap_response": c.result
            }
            raise exc_groups.GroupDelete(data=data)

        if LDAP_LOG_DELETE == True:
            # Log this action to DB
            logToDB(
                user_id=request.user.id,
                actionType="DELETE",
                objectClass="GROUP",
                affectedObject=groupToDelete['cn']
            )

        # Unbind the connection
        c.unbind()
        return Response(
             data={
                'code': code,
                'code_msg': code_msg,
                'data': groupToDelete
             }
        )
