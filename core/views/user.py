from django.core.exceptions import PermissionDenied
from django.db import transaction
from rest_framework.response import Response
from .mixins.user import UserViewMixin
from rest_framework import viewsets
from rest_framework.exceptions import NotFound
from rest_framework.decorators import action
from interlock_backend import ldap_settings
from django_python3_ldap import ldap
from ldap3 import Server, Connection, ALL
class UserViewSet(viewsets.ViewSet, UserViewMixin):

    # def list(self, request, pk=None):
    #     raise NotFound

    def list(self, request):
        user = request.user
        print(request)
        if user.is_staff == False or not user:
            raise PermissionDenied
        data = {}
        code = 0
        return Response(
             data={
                'code': code,
                'code_msg': 'ok',
                'user': data
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

    @action(detail=False, methods=['get'])
    @transaction.atomic
    def me(self, request):
        user = request.user
        if user.is_staff == False or not user:
            raise PermissionDenied
        data = {}
        code = 0
        data["username"] = request.user.username or ""
        data["first_name"] = request.user.first_name or ""
        data["last_name"] = request.user.last_name or ""
        data["email"] = request.user.email or ""
        return Response(
             data={
                'code': code,
                'code_msg': 'ok',
                'user': data
             }
        )