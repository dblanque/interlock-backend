################################## IMPORTS #####################################
### Exceptions
from django.core.exceptions import PermissionDenied

### Mixins
from .mixins.domain import DomainViewMixin

### REST Framework
from rest_framework.response import Response
from rest_framework import viewsets
from rest_framework.exceptions import NotFound
from rest_framework.decorators import action

### Others
from interlock_backend.ldap.encrypt import validateUser
from interlock_backend.ldap.settings_func import SettingsList
################################################################################
class DomainViewSet(viewsets.ViewSet, DomainViewMixin):

    @action(detail=False, methods=['get'])
    def details(self, request):
        user = request.user
        validateUser(request=request, requestUser=user, requireAdmin=False)
        data = {}
        code = 0
        ldap_settings_list = SettingsList(**{"search":{'LDAP_AUTH_ACTIVE_DIRECTORY_DOMAIN', 'LDAP_DOMAIN', 'LDAP_AUTH_SEARCH_BASE'}})
        data["realm"] = ldap_settings_list.LDAP_AUTH_ACTIVE_DIRECTORY_DOMAIN or ""
        data["name"] = ldap_settings_list.LDAP_DOMAIN or ""
        data["basedn"] = ldap_settings_list.LDAP_AUTH_SEARCH_BASE or ""
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
