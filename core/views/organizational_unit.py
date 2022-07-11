from attr import attributes
from django.core.exceptions import PermissionDenied
from django.db import transaction
from ldap3 import LEVEL
from rest_framework.response import Response
from rest_framework import viewsets
from .mixins.organizational_unit import OrganizationalUnitMixin
from rest_framework.exceptions import NotFound
from core.exceptions.users import UserExists, UserPermissionError, UserPasswordsDontMatch
from rest_framework.decorators import action
from interlock_backend.ldap_connector import (
    open_connection,
    get_full_directory_tree
)
from interlock_backend import ldap_settings
from interlock_backend import ldap_adsi
import traceback
import logging
import json

class OrganizationalUnitViewSet(viewsets.ViewSet, OrganizationalUnitMixin):
    
    def list(self, request):
        user = request.user
        # Check user is_staff
        if user.is_staff == False or not user:
            raise PermissionDenied
        data = []
        code = 0
        code_msg = 'ok'

        # Open LDAP Connection
        c = open_connection()

        list = get_full_directory_tree()

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
