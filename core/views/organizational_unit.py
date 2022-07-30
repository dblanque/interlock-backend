from django.core.exceptions import PermissionDenied
from django.db import transaction
from ldap3 import LEVEL
from rest_framework.response import Response
from rest_framework import viewsets
from .mixins.organizational_unit import OrganizationalUnitMixin
from core.models import Log
from rest_framework.exceptions import NotFound
from core.exceptions.ldap import CouldNotOpenConnection, CouldNotFetchDirtree
from rest_framework.decorators import action
from interlock_backend.ldap.connector import openLDAPConnection
from interlock_backend.ldap.adsi import addSearchFilter
from interlock_backend.ldap.dirtree import getFullDirectoryTree
from interlock_backend.ldap.encrypt import validateUser
from interlock_backend.ldap.settings_func import SettingsList

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

        dirList = getFullDirectoryTree(getCNs=False)

        if ldap_settings_list.LDAP_LOG_READ == True:
            # Log this action to DB
            logAction = Log(
                user_id=request.user.id,
                actionType="READ",
                objectClass="OU",
                affectedObject="ALL"
            )
            logAction.save()

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

        ldap_settings_list = SettingsList(**{"search":{'LDAP_LOG_READ'}})

        objectFilters = data['filter']
        defaultOUFilters = {
            "organizationalUnit" : "objectCategory",
            "top" : "objectCategory",
            "container" : "objectCategory",
            "builtinDomain" : "objectCategory"
        }
        defaultCNFilters = {
            "user" : "objectClass",
            "person" : "objectClass",
            "group" : "objectClass",
            "organizationalPerson" : "objectClass",
            "computer" : "objectClass"
        }
        searchFilterOU = ""
        searchFilterCN = ""

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
            dirList = getFullDirectoryTree()
        except Exception as e:
            print(e)
            raise CouldNotFetchDirtree

        if ldap_settings_list.LDAP_LOG_READ == True:
            # Log this action to DB
            logAction = Log(
                user_id=request.user.id,
                actionType="READ",
                objectClass="LDAP",
                affectedObject="ALL"
            )
            logAction.save()

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
