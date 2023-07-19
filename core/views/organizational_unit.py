################################################################################
#################### INTERLOCK IS LICENSED UNDER GNU AGPLv3 ####################
################## ORIGINAL PROJECT CREATED BY DYLAN BLANQUÉ ###################
########################## AND BR CONSULTING S.R.L. ############################
################################################################################
# Module: core.views.organizational_unit
# Contains the ViewSet for Directory Tree and Organizational Unit
# related operations

#---------------------------------- IMPORTS -----------------------------------#
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
from interlock_backend.ldap.adsi import search_filter_from_dict
from interlock_backend.ldap.encrypt import validate_request_user
from interlock_backend.ldap.constants_cache import *
from ldap3.utils.dn import safe_rdn
import logging
################################################################################

logger = logging.getLogger(__name__)

class OrganizationalUnitViewSet(BaseViewSet, OrganizationalUnitMixin):

    def list(self, request):
        user = request.user
        validate_request_user(request=request)
        data = request.data
        code = 0
        code_msg = 'ok'

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
            LDAP_OU_FIELD,

            # Group Attrs
            'cn',
            'member',
            'distinguishedName',
            'groupType',
            'objectSid'
        ]

        # Read-only end-point, build filters from default dictionary
        filterDict = LDAP_DIRTREE_OU_FILTER
        ldapFilter = search_filter_from_dict(filterDict)

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

        if LDAP_LOG_READ == True:
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
                'ldapObjectList': dirList.children,
                }
        )

    @action(detail=False,methods=['post'])
    def dirtree(self, request):
        user = request.user
        validate_request_user(request=request)
        data = request.data
        code = 0
        code_msg = 'ok'

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
            LDAP_OU_FIELD,

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

        if LDAP_LOG_READ == True:
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
                'ldapObjectList': dirList.children,
                }
        )

    @action(detail=False,methods=['post'])
    def move(self, request):
        user = request.user
        validate_request_user(request=request)
        data = request.data
        code = 0
        code_msg = 'ok'

        ldapObject = data['ldapObject']
        newPath = ldapObject['destination']
        distinguishedName = ldapObject['distinguishedName']
        
        if 'name' in ldapObject:
            objectName = ldapObject['name']
        else:
            objectName = distinguishedName

        relativeDistinguishedName = distinguishedName.split(",")[0]

        if relativeDistinguishedName == distinguishedName:
            raise exc_dirtree.DirtreeDistinguishedNameConflict

        # Open LDAP Connection
        try:
            c = LDAPConnector(user.dn, user.encryptedPassword, request.user).connection
        except Exception as e:
            print(e)
            raise exc_ldap.CouldNotOpenConnection
    
        try:
            c.modify_dn(distinguishedName, relativeDistinguishedName, new_superior=newPath)
        except Exception as e:
            print(e)
            data = {
                "ldap_response": c.result,
                "ldapObject": objectName,
            }
            if c.result.description == "entryAlreadyExists":
                data[''] = 409
            c.unbind()
            raise exc_dirtree.DirtreeMove(data=data)

        if LDAP_LOG_UPDATE == True:
            # Log this action to DB
            logToDB(
                user_id=request.user.id,
                actionType="UPDATE",
                objectClass="LDAP",
                affectedObject=objectName,
                extraMessage="MOVE"
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

    @action(detail=False,methods=['post'])
    def rename(self, request):
        user = request.user
        validate_request_user(request=request)
        data = request.data
        code = 0
        code_msg = 'ok'

        ldapObject = data['ldapObject']
        distinguishedName = ldapObject['distinguishedName']
        
        if 'name' in ldapObject:
            objectName = ldapObject['name']
        else:
            objectName = distinguishedName

        relativeDistinguishedName = distinguishedName.split(",")[0]
        newRDN = ldapObject['newRDN']

        if relativeDistinguishedName == newRDN:
            raise exc_dirtree.DirtreeDistinguishedNameConflict

        newRDN = str(distinguishedName).split("=")[0].lower() + "=" + newRDN

        # Open LDAP Connection
        try:
            c = LDAPConnector(user.dn, user.encryptedPassword, request.user).connection
        except Exception as e:
            print(e)
            raise exc_ldap.CouldNotOpenConnection

        try:
            c.modify_dn(distinguishedName, newRDN)
        except Exception as e:
            print(e)
            data = {
                "ldap_response": c.result,
                "ldapObject": objectName,
            }
            if c.result.description == "entryAlreadyExists":
                data['code'] = 409
            c.unbind()
            raise exc_dirtree.DirtreeMove(data=data)

        if LDAP_LOG_UPDATE == True:
            if objectName != ldapObject['name']:
                affectedObject = "%s -> %s" % (objectName, ldapObject['name'])
            else:
                affectedObject = objectName
            # Log this action to DB
            logToDB(
                user_id=request.user.id,
                actionType="UPDATE",
                objectClass="LDAP",
                affectedObject=affectedObject,
                extraMessage="RENAME"
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

    @action(detail=False,methods=['post'])
    def insert(self, request):
        user = request.user
        validate_request_user(request=request)
        data = request.data
        code = 0
        code_msg = 'ok'

        ldapObject = data['ldapObject']

        fields = [
            'name',
            'path',
            'type'
        ]
        for f in fields:
            if f not in ldapObject:
                print(f + "not in LDAP Object")
                print(data)
                raise exc_ou.MissingField

        objectName = ldapObject['name']
        objectPath = ldapObject['path']
        objectType = ldapObject['type']

        attributes = {
            "name": objectName
        }

        if objectType == 'ou' or objectType is None:
            objectDistinguishedName = "OU=" + objectName + "," + objectPath
            objectMain = ldapObject['ou']
            objectType = "organizationalUnit"
            attributes["ou"] = objectMain
        else:
            objectDistinguishedName = "CN=" + objectName + "," + objectPath

        # Open LDAP Connection
        try:
            c = LDAPConnector(user.dn, user.encryptedPassword, request.user).connection
        except Exception as e:
            print(e)
            raise exc_ldap.CouldNotOpenConnection

        try:
            c.add(objectDistinguishedName, objectType, attributes=attributes)
        except Exception as e:
            print(f'Could not Add LDAP Object: {objectDistinguishedName}')
            print(ldapObject)
            print(e)
            data = {
                "ldap_response": c.result,
                "ldapObject": objectName,
            }
            if c.result.description == "entryAlreadyExists":
                data["code"] = 409
            c.unbind()
            raise exc_ou.OUCreate(data=data)

        if LDAP_LOG_CREATE == True:
            # Log this action to DB
            logToDB(
                user_id=request.user.id,
                actionType="CREATE",
                objectClass="OU",
                affectedObject=objectName
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
        validate_request_user(request=request)
        code = 0
        code_msg = 'ok'
        data = request.data

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
        try:
            c.delete(objectToDelete)
        except Exception as e:
            c.unbind()
            print(e)
            print(f'Could not delete LDAP Object: {objectToDelete}')
            data = {
                "ldap_response": c.result
            }
            raise exc_ldap.BaseException(data=data)

        if LDAP_LOG_DELETE == True:
            # Log this action to DB
            logToDB(
                user_id=request.user.id,
                actionType="DELETE",
                objectClass="LDAP",
                affectedObject=data['name']
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
