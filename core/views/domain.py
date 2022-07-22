from django.core.exceptions import PermissionDenied
from rest_framework.response import Response
from .mixins.domain import DomainViewMixin
from rest_framework import viewsets
from rest_framework.exceptions import NotFound
from rest_framework.decorators import action
from interlock_backend.ldap.settings import getSetting
from interlock_backend.ldap.encrypt import validateUser

class DomainViewSet(viewsets.ViewSet, DomainViewMixin):

    @action(detail=False, methods=['get'])
    def details(self, request):
        user = request.user
        validateUser(request=request, requestUser=user)
        data = {}
        code = 0
        data["realm"] = getSetting('LDAP_AUTH_ACTIVE_DIRECTORY_DOMAIN') or ""
        data["name"] = getSetting('LDAP_DOMAIN') or ""
        data["basedn"] = getSetting('LDAP_AUTH_SEARCH_BASE') or ""
        return Response(
             data={
                'code': code,
                'code_msg': 'ok',
                'details': data
             }
        )

    def list(self, request, pk=None):
        raise NotFound

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
