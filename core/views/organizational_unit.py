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
from interlock_backend.ldap.dirtree import getFullDirectoryTree
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

        ldap_settings_list = SettingsList(**{"search":{'LDAP_LOG_READ'}})

        # Open LDAP Connection
        try:
            c = openLDAPConnection(user.dn, user.encryptedPassword, request.user)
        except Exception as e:
            print(e)
            raise CouldNotOpenConnection

        debugTimerStart = perf_counter()
        result = getFullDirectoryTree(connection=c, getCNs=False)
        debugTimerEnd = perf_counter()
        logger.debug("Dirtree Fetch Time Elapsed: " + str(round(debugTimerEnd - debugTimerStart, 3)))
        dirList = result[0]
        c = result[1]

        if ldap_settings_list.LDAP_LOG_READ == True:
            # Log this action to DB
            logToDB(
                user_id=request.user.id,
                actionType="READ",
                objectClass="OU",
                affectedObject="ALL"
            )

        # Close / Unbind LDAP Connection
        c.unbind()
        return Response(
                data={
                'code': code,
                'code_msg': code_msg,
                'ou_list': dirList,
                }
        )

    @action(detail=False,methods=['post'])
    def filter(self, request):
        user = request.user
        validateUser(request=request, requestUser=user)
        data = request.data
        code = 0
        code_msg = 'ok'

        ldap_settings_list = SettingsList(**{"search":{
            'LDAP_LOG_READ'
        }})

        # Check if iexact filter is in data json
        if 'iexact' in data:
            exactFilter = data['iexact']
        else:
            exactFilter = {}

        # Check if standard dirtree filter is in data json
        if 'filter' in data:
            objectFilters = data['filter']
        else:
            objectFilters = {}

        # Get defaults and initialize vars
        defaultOUFilters = ldap_settings_list.LDAP_DIRTREE_OU_FILTER
        searchFilterOU = ""

        # If objectFilters is not empty use iexact or defaults
        if not bool(objectFilters):
            if not bool(exactFilter) and 'ouFilter' in exactFilter:
                searchFilterOU = buildFilterFromDict(exactFilter['ouFilter'])
            else:
                searchFilterOU = buildFilterFromDict(defaultOUFilters)
        else:
            # For Filter, Filter Type in...
            # ( F-Type in this case is Filter Type, not a Jaguar :D )
            for f, fType in defaultOUFilters.items():
                if f not in objectFilters:
                    searchFilterOU = addSearchFilter(searchFilterOU, fType + "=" + f, '|')

            # Build Negations in defaultOUFilters (They have to be in the outer part of the string)
            for f, fType in defaultOUFilters.items():
                if f in objectFilters:
                    searchFilterOU = addSearchFilter(searchFilterOU, fType + "=" + f, '&', negate=True)

        logger.debug("OU Object Search Filter: " + searchFilterOU)

        # Open LDAP Connection
        try:
            c = openLDAPConnection(user.dn, user.encryptedPassword, request.user)
        except Exception as e:
            print(e)
            raise CouldNotOpenConnection

        debugTimerStart = perf_counter()
        result = getFullDirectoryTree(connection=c, getCNs=False)
        debugTimerEnd = perf_counter()
        logger.debug("Dirtree Fetch Time Elapsed: " + str(round(debugTimerEnd - debugTimerStart, 3)))
        dirList = result[0]
        c = result[1]

        if ldap_settings_list.LDAP_LOG_READ == True:
            # Log this action to DB
            logToDB(
                user_id=request.user.id,
                actionType="READ",
                objectClass="OU",
                affectedObject="ALL"
            )

        # Close / Unbind LDAP Connection
        c.unbind()
        return Response(
                data={
                'code': code,
                'code_msg': code_msg,
                'ou_list': dirList,
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

        # Check if iexact filter is in data json
        if 'iexact' in data:
            exactFilter = data['iexact']
        else:
            exactFilter = {}

        # Check if standard dirtree filter is in data json
        if 'filter' in data:
            objectFilters = data['filter']
        else:
            objectFilters = {}

        # Get defaults and initialize vars
        defaultOUFilters = ldap_settings_list.LDAP_DIRTREE_OU_FILTER
        defaultCNFilters = ldap_settings_list.LDAP_DIRTREE_CN_FILTER
        searchFilterOU = ""
        searchFilterCN = ""

        # If objectFilters is not empty use iexact or defaults
        if not bool(objectFilters):
            if not bool(exactFilter) and 'ouFilter' in exactFilter:
                searchFilterOU = buildFilterFromDict(exactFilter['ouFilter'])
            else:
                searchFilterOU = buildFilterFromDict(defaultOUFilters)

            if not bool(exactFilter) and 'cnFilter' in exactFilter:
                searchFilterCN = buildFilterFromDict(exactFilter['cnFilter'])
            else:
                searchFilterCN = buildFilterFromDict(defaultCNFilters)
        else:
            # For Filter, Filter Type in...
            # ( F-Type in this case is Filter Type, not a Jaguar :D )
            for f, fType in defaultOUFilters.items():
                if f not in objectFilters:
                    searchFilterOU = addSearchFilter(searchFilterOU, fType + "=" + f, '|')

            # Build Negations in defaultOUFilters (They have to be in the outer part of the string)
            for f, fType in defaultOUFilters.items():
                if f in objectFilters:
                    searchFilterOU = addSearchFilter(searchFilterOU, fType + "=" + f, '&', negate=True)

            # Same but for CN Filters
            for f, fType in defaultCNFilters.items():
                if f not in objectFilters:
                    searchFilterCN = addSearchFilter(searchFilterCN, fType + "=" + f, '|')

            # Build Negations in defaultCNFilters
            for f, fType in defaultCNFilters.items():
                if f in objectFilters:
                    searchFilterCN = addSearchFilter(searchFilterCN, fType + "=" + f, '&', negate=True)

        if 'builtinDomain' in objectFilters:
            disableBuiltIn = True
        else:
            disableBuiltIn = False

        if 'organizationalUnit' in objectFilters:
            enableOuFilter = True
        else:
            enableOuFilter = False

        logger.debug("OU Object Search Filter: " + searchFilterOU)
        logger.debug("CN Object Search Filter: " + searchFilterCN)

        # Open LDAP Connection
        try:
            c = openLDAPConnection(user.dn, user.encryptedPassword, request.user)
        except Exception as e:
            print(e)
            raise CouldNotOpenConnection

        # Should have:
        # Filter by Object DN
        # Filter by Attribute
        try:
            debugTimerStart = perf_counter()
            result = getFullDirectoryTree(
                connection=c,
                ouFilter=searchFilterOU,
                cnFilter=searchFilterCN,
                disableBuiltIn=disableBuiltIn,
                getOUs=enableOuFilter
            )
            debugTimerEnd = perf_counter()
            logger.debug("Dirtree Fetch Time Elapsed: " + str(round(debugTimerEnd - debugTimerStart, 3)))
            dirList = result[0]
            c = result[1]
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
                'ou_list': dirList,
                }
        )

    @action(detail=False,methods=['post'])
    def move(self, request):
        user = request.user
        validateUser(request=request, requestUser=user)
        data = request.data
        code = 0
        code_msg = 'ok'

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
