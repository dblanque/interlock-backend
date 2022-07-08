from django.core.exceptions import PermissionDenied
from django.db import transaction
from rest_framework.response import Response
from rest_framework import viewsets
from .mixins.organizational_unit import OrganizationalUnitMixin
from rest_framework.exceptions import NotFound
from core.exceptions.users import UserExists, UserPermissionError, UserPasswordsDontMatch
from rest_framework.decorators import action
from interlock_backend.ldap_connector import open_connection
from interlock_backend import ldap_settings
from interlock_backend import ldap_adsi
import traceback
import logging

class OrganizationalUnitViewSet(viewsets.ViewSet, OrganizationalUnitMixin):
    
    @action(detail=False, methods=['get'])
    def fetchall(self, request, pk=None):
        user = request.user
        # Check user is_staff
        if user.is_staff == False or not user:
            raise PermissionDenied
        data = []
        code = 0
        code_msg = 'ok'
        # Open LDAP Connection
        c = open_connection()

        # Search for all Organizational Units
        c.search(search_base=ldap_settings.LDAP_AUTH_SEARCH_BASE,
                search_filter='(objectClass=OrganizationalUnit)')
        list = c.entries

        for ou in list:
            print(ou)

        # Close / Unbind LDAP Connection
        c.unbind()
        return Response(
                data={
                'code': code,
                'code_msg': code_msg,
                'ou_list': list,
                }
        )

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
