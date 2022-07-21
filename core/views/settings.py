from django.conf import Settings
from django.core.exceptions import PermissionDenied
from rest_framework.response import Response
from core.models.settings import Setting
from .mixins.settings import SettingsViewMixin
from rest_framework import viewsets
from rest_framework.exceptions import NotFound
from rest_framework.decorators import action
from interlock_backend import ldap_settings
from interlock_backend.ldap_encrypt import validateUser
import logging
import ssl

logger = logging.getLogger(__name__)

class SettingsViewSet(viewsets.ViewSet, SettingsViewMixin):
    queryset = Setting.objects.all()

    @action(detail=False, methods=['post'])
    def all(self, request, pk=None):
        user = request.user
        validateUser(request=request, requestUser=user)
        data = {}
        code = 0

        data = self.getSettingsList()
        data['DEFAULT_ADMIN_ENABLED'] = self.getAdminStatus()

        # TODO - Convert Tuple for LDAP_AUTH_USER_LOOKUP_FIELDS to ARRAY for Front-End

        return Response(
             data={
                'code': code,
                'code_msg': 'ok',
                'settings': data
             }
        )

    @action(detail=False, methods=['post'])
    def save(self, request, pk=None):
        user = request.user
        validateUser(request=request, requestUser=user)
        data = request.data
        code = 0

        for setting in data:
            if setting == 'LDAP_AUTH_TLS_VERSION':
                data[setting]['value'] = getattr(ssl, data[setting]['value'])
            if setting in ldap_settings.__dict__:
                if data[setting]['value'] != ldap_settings.__dict__[setting]:
                    logger.debug('Value in data for ' + setting)
                    logger.debug(data[setting]['value'])
                    logger.debug('Type in data for ' + setting)
                    logger.debug(type(data[setting]['value']))
                    logger.debug('Value in constants dict for ' + setting)
                    logger.debug(ldap_settings.__dict__[setting])
                    logger.debug('Type in constants dict for ' + setting)
                    logger.debug(type(ldap_settings.__dict__[setting]))
                    code = self.update_or_create_setting(setting, data[setting])

        return Response(
             data={
                'code': code,
                'code_msg': 'ok',
                'settings': data
             }
        )

    @action(detail=False, methods=['post'])
    def reset(self, request, pk=None):
        user = request.user
        validateUser(request=request, requestUser=user)
        data = request.data
        code = 0

        self.setAdminStatus(status=data.pop('DEFAULT_ADMIN_ENABLED'), password=data.pop('DEFAULT_ADMIN_PWD'))

        data = self.resetSettings()

        return Response(
             data={
                'code': code,
                'code_msg': 'ok',
                'settings': data
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