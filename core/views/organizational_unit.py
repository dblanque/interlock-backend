import json
from time import perf_counter
from django.core.exceptions import PermissionDenied
from django.db import connection, transaction
from ldap3 import LEVEL
from rest_framework.response import Response
from rest_framework import viewsets
from .mixins.organizational_unit import OrganizationalUnitMixin
from core.models.log import logToDB
from rest_framework.exceptions import NotFound
from core.exceptions.ldap import CouldNotOpenConnection, CouldNotFetchDirtree
from rest_framework.decorators import action
from interlock_backend.ldap.connector import openLDAPConnection
from interlock_backend.ldap.adsi import addSearchFilter, buildFilterFromDict
from core.models.ldapTree import LDAPTree
from interlock_backend.ldap.encrypt import validateUser
from interlock_backend.ldap.settings_func import SettingsList
import logging

logger = logging.getLogger(__name__)

class OrganizationalUnitViewSet(viewsets.ViewSet, OrganizationalUnitMixin):

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
            c = openLDAPConnection(user.dn, user.encryptedPassword, request.user)
        except Exception as e:
            print(e)
            raise CouldNotOpenConnection

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
            raise CouldNotFetchDirtree

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
            'LDAP_LOG_READ',
            'LDAP_DIRTREE_OU_FILTER',
            'LDAP_DIRTREE_CN_FILTER'
        }})
        ldapFilter = ""

        if 'iexact' in data['filter']:
            logger.debug("Dirtree fetching with Filter iexact")
            if len(data['filter']['iexact']) > 0:
                for f in data['filter']['iexact']:
                    fVal = data['filter']['iexact'][f]
                    if isinstance(fVal, dict):
                        fType = fVal.pop('attr')
                        fExclude = fVal.pop('exclude')
                        ldapFilter = addSearchFilter(ldapFilter, fType + "=" + f, negate=fExclude)
                    else:
                        fType = fVal
                        ldapFilter = addSearchFilter(ldapFilter, fType + "=" + f)
        else:
            logger.debug("Dirtree fetching with Standard Exclusion Filter")
            filterDict = {**ldap_settings_list.LDAP_DIRTREE_CN_FILTER, **ldap_settings_list.LDAP_DIRTREE_OU_FILTER}
            if 'filter' in data:
                if len(data['filter']) > 0:
                    for i in data['filter']:
                        if i in filterDict:
                            del filterDict[i]

            ldapFilter = buildFilterFromDict(filterDict)

            # Where f is Filter Value, fType is the filter Type (not a Jaguar)
            # Example: objectClass=computer
            # f = computer
            # fType = objectClass
            if 'filter' in data:
                if len(data['filter']) > 0:
                    for f in data['filter']:
                        fType = data['filter'][f]
                        ldapFilter = addSearchFilter(ldapFilter, fType + "=" + f, negate=True)

        logger.debug("LDAP Filter for Dirtree: ")
        logger.debug(ldapFilter)

        # Open LDAP Connection
        try:
            c = openLDAPConnection(user.dn, user.encryptedPassword, request.user)
        except Exception as e:
            print(e)
            raise CouldNotOpenConnection

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
            raise CouldNotFetchDirtree

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
            c = openLDAPConnection(user.dn, user.encryptedPassword, request.user)
        except Exception as e:
            print(e)
            raise CouldNotOpenConnection

        # Close / Unbind LDAP Connection
        c.unbind()
        return Response(
                data={
                'code': code,
                'code_msg': code_msg,
                # 'user': username,
                }
        )

    # def list(self, request, pk=None):
    #     raise NotFound

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
