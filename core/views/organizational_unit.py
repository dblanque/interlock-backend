from django.core.exceptions import PermissionDenied
from django.db import transaction
from ldap3 import LEVEL
from rest_framework.response import Response
from rest_framework import viewsets
from .mixins.organizational_unit import OrganizationalUnitMixin
from rest_framework.exceptions import NotFound
from core.exceptions.ldap import CouldNotOpenConnection
from rest_framework.decorators import action
from interlock_backend.ldap.connector import (
    openLDAPConnection,
    getFullDirectoryTree,
    buildFilterFromDict
)
from interlock_backend.ldap.encrypt import validateUser

class OrganizationalUnitViewSet(viewsets.ViewSet, OrganizationalUnitMixin):

    def list(self, request):
        user = request.user
        validateUser(request=request, requestUser=user)
        data = request.data
        code = 0
        code_msg = 'ok'

        # Open LDAP Connection
        try:
            c = openLDAPConnection(user.dn, user.encryptedPassword)
        except Exception as e:
            print(e)
            raise CouldNotOpenConnection

        dirList = getFullDirectoryTree(getCNs=False)

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

        # objectFilters = data['filter']
        # if objectFilters != {} and objectFilters is not None:
        #     queryFilter = buildFilterFromDict(objectFilters)

        # Open LDAP Connection
        try:
            c = openLDAPConnection(user.dn, user.encryptedPassword)
        except Exception as e:
            print(e)
            raise CouldNotOpenConnection

        dirList = getFullDirectoryTree()

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
            c = openLDAPConnection(user.dn, user.encryptedPassword)
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
