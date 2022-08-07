################################## IMPORTS #####################################
### Exceptions
from django.core.exceptions import PermissionDenied
from core.exceptions import (
    ldap as exc_ldap,
    dirtree as exc_dirtree,
    organizational_unit as exc_ou
)

### ViewSets
from .base import BaseViewSet

### Models
from core.models.log import logToDB
from core.models.ldapTree import LDAPTree

### Mixins
from .mixins.organizational_unit import OrganizationalUnitMixin

### REST Framework
from rest_framework.response import Response
from rest_framework.exceptions import NotFound
from rest_framework import viewsets
from rest_framework.decorators import action

### Others
from time import perf_counter
from interlock_backend.ldap.connector import LDAPConnector
from interlock_backend.ldap.adsi import buildFilterFromDict
from interlock_backend.ldap.encrypt import validateUser
from interlock_backend.ldap.settings_func import SettingsList
import logging
################################################################################

logger = logging.getLogger(__name__)

class OrganizationalUnitViewSet(BaseViewSet, OrganizationalUnitMixin):

    def list(self, request):
        user = request.user
        validateUser(request=request, requestUser=user)
        data = request.data
        code = 0
        code_msg = 'ok'

        ldap_settings_list = SettingsList(**{"search":{
            'LDAP_LOG_READ',
            'LDAP_DIRTREE_OU_FILTER'
        }})

        # Open LDAP Connection
        try:
            c = LDAPConnector(user.dn, user.encryptedPassword, request.user).connection
        except Exception as e:
            print(e)
            raise exc_ldap.CouldNotOpenConnection

        attributesToSearch = [
            # User Attrs
            'objectClass',
            'objectCategory',
            'sAMAccountName',

            # Group Attrs
            'cn',
            'member',
            'distinguishedName',
            'groupType',
            'objectSid'
        ]

        # Read-only end-point, build filters from default dictionary
        filterDict = ldap_settings_list.LDAP_DIRTREE_OU_FILTER
        ldapFilter = buildFilterFromDict(filterDict)

        try:
            debugTimerStart = perf_counter()
            dirList = LDAPTree(**{
                "connection": c,
                "recursive": True,
                "ldapFilter": ldapFilter,
                "ldapAttributes": attributesToSearch,
            })
            debugTimerEnd = perf_counter()
            logger.info("Dirtree Fetch Time Elapsed: " + str(round(debugTimerEnd - debugTimerStart, 3)))
        except Exception as e:
            print(e)
            raise exc_ldap.CouldNotFetchDirtree

        if ldap_settings_list.LDAP_LOG_READ == True:
            # Log this action to DB
            logToDB(
                user_id=request.user.id,
                actionType="READ",
                objectClass="OU",
                affectedObject="ALL - List Query"
            )

        # Close / Unbind LDAP Connection
        c.unbind()
        return Response(
                data={
                'code': code,
                'code_msg': code_msg,
                'ou_list': dirList.children,
                }
        )

    @action(detail=False,methods=['post'])
    def dirtree(self, request):
        user = request.user
        validateUser(request=request, requestUser=user)
        data = request.data
        code = 0
        code_msg = 'ok'

        ldap_settings_list = SettingsList(**{"search":{
            'LDAP_LOG_READ'
        }})
        try:
            ldapFilter = self.processFilter(data)
        except Exception as e:
            print(e)
            raise exc_dirtree.DirtreeFilterBad

        # Open LDAP Connection
        try:
            c = LDAPConnector(user.dn, user.encryptedPassword, request.user).connection
        except Exception as e:
            print(e)
            raise exc_ldap.CouldNotOpenConnection

        attributesToSearch = [
            # User Attrs
            'objectClass',
            'objectCategory',
            'sAMAccountName',

            # Group Attrs
            'cn',
            'member',
            'distinguishedName',
            'groupType',
            'objectSid'
        ]

        # Should have:
        # Filter by Object DN
        # Filter by Attribute
        try:
            debugTimerStart = perf_counter()
            dirList = LDAPTree(**{
                "connection": c,
                "recursive": True,
                "ldapFilter": ldapFilter,
                "ldapAttributes": attributesToSearch,
            })
            debugTimerEnd = perf_counter()
            logger.info("Dirtree Fetch Time Elapsed: " + str(round(debugTimerEnd - debugTimerStart, 3)))
        except Exception as e:
            print(e)
            c.unbind()
            raise exc_ldap.CouldNotFetchDirtree

        if ldap_settings_list.LDAP_LOG_READ == True:
            # Log this action to DB
            logToDB(
                user_id=request.user.id,
                actionType="READ",
                objectClass="LDAP",
                affectedObject="ALL - Full Dirtree Query"
            )

        # Close / Unbind LDAP Connection
        c.unbind()
        return Response(
                data={
                'code': code,
                'code_msg': code_msg,
                'ou_list': dirList.children,
                }
        )

    @action(detail=False,methods=['post'])
    def move(self, request):
        user = request.user
        validateUser(request=request, requestUser=user)
        data = request.data
        code = 0
        code_msg = 'ok'

        # Full DN to Move
        # Target DN

        # Relative DN cannot be same as Full DN

        # If relative DN changes, CN cannot change
        # Else

        # Open LDAP Connection
        try:
            c = LDAPConnector(user.dn, user.encryptedPassword, request.user).connection
        except Exception as e:
            print(e)
            raise exc_ldap.CouldNotOpenConnection

        # Close / Unbind LDAP Connection
        c.unbind()
        return Response(
                data={
                'code': code,
                'code_msg': code_msg,
                # 'user': username,
                }
        )

    @action(detail=False,methods=['post'])
    def insert(self, request):
        user = request.user
        validateUser(request=request, requestUser=user)
        data = request.data
        code = 0
        code_msg = 'ok'

        ldap_settings_list = SettingsList(**{"search":{
            'LDAP_LOG_CREATE'
        }})

        ou = data['ou']

        if 'name' not in ou or 'distinguishedName' not in ou or 'ou' not in ou:
            raise exc_ou.MissingField

        ouName = ou.pop('name')
        ouMain = ou.pop('ou')
        ouPath = ou.pop('path')
        ouDistinguishedName = "OU=" + ouName + "," + ouPath

        attributes = {
            "name": ouName,
            "ou": ouMain
        }

        # Open LDAP Connection
        try:
            c = LDAPConnector(user.dn, user.encryptedPassword, request.user).connection
        except Exception as e:
            print(e)
            raise exc_ldap.CouldNotOpenConnection

        try:
            c.add(ouDistinguishedName, "organizationalUnit", attributes=attributes)
        except Exception as e:
            c.unbind()
            print(e)
            raise exc_ou.OUCreate

        if ldap_settings_list.LDAP_LOG_CREATE == True:
            # Log this action to DB
            logToDB(
                user_id=request.user.id,
                actionType="CREATE",
                objectClass="LDAP",
                affectedObject=ouName
            )

        # Close / Unbind LDAP Connection
        c.unbind()
        return Response(
                data={
                'code': code,
                'code_msg': code_msg,
                # 'user': username,
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
            c = LDAPConnector(user.dn, user.encryptedPassword, request.user).connection
        except Exception as e:
            print(e)
            raise exc_ldap.CouldNotOpenConnection

        objectToDelete = data['distinguishedName']

        if not objectToDelete or objectToDelete == "":
            c.unbind()
            raise exc_ldap.LDAPObjectDoesNotExist
        c.delete(objectToDelete)

        if ldap_settings_list.LDAP_LOG_DELETE == True:
            # Log this action to DB
            logToDB(
                user_id=request.user.id,
                actionType="DELETE",
                objectClass="USER",
                affectedObject=objectToDelete
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
