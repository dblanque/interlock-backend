from rest_framework.response import Response
from core.models.settings import Setting
from .mixins.settings import SettingsViewMixin
from rest_framework import viewsets
from rest_framework.exceptions import NotFound
from rest_framework.decorators import action
from interlock_backend.ldap import settings as ldap_settings
from interlock_backend.ldap.encrypt import validateUser
from core.exceptions.ldap import ConnectionTestFailed
import logging
import ssl

logger = logging.getLogger(__name__)

class SettingsViewSet(viewsets.ViewSet, SettingsViewMixin):
    queryset = Setting.objects.all()

    def list(self, request, pk=None):
        user = request.user
        validateUser(request=request, requestUser=user)
        data = {}
        code = 0

        data = ldap_settings.getSettingsList()
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

        adminEnabled = data.pop('DEFAULT_ADMIN_ENABLED')
        adminPassword = data.pop('DEFAULT_ADMIN_PWD')
        self.setAdminStatus(status=adminEnabled, password=adminPassword)

        for setting in data:
            data[setting] = ldap_settings.normalizeValues(setting, data[setting])
            if setting == 'LDAP_AUTH_TLS_VERSION':
                data[setting]['value'] = getattr(ssl, data[setting]['value'])
            if setting in ldap_settings.__dict__:
                dictValue = getattr(ldap_settings, setting)
                if data[setting]['value'] != dictValue:
                    logger.debug('Value in data for ' + setting)
                    logger.debug(data[setting]['value'])
                    logger.debug('Type in data for ' + setting)
                    logger.debug(type(data[setting]['value']))
                    logger.debug('Value in constants dict for ' + setting)
                    logger.debug(dictValue)
                    logger.debug('Type in constants dict for ' + setting)
                    logger.debug(type(dictValue))
                    code = self.update_or_create_setting(setting, data[setting])
                if data[setting]['value'] == dictValue or data[setting]['value'] == "":
                    code = self.delete_setting(setting, data[setting])

        return Response(
             data={
                'code': code,
                'code_msg': 'ok',
                'settings': data
             }
        )

    @action(detail=False, methods=['get'])
    def reset(self, request, pk=None):
        user = request.user
        validateUser(request=request, requestUser=user)
        data = request.data
        code = 0

        data = self.resetSettings()

        return Response(
             data={
                'code': code,
                'code_msg': 'ok',
                'settings': data
             }
        )

    @action(detail=False, methods=['post'])
    def test(self, request, pk=None):
        user = request.user
        validateUser(request=request, requestUser=user)
        data = request.data
        code = 0

        data = self.testSettings(user, data)

        if not data:
            raise ConnectionTestFailed

        return Response(
             data={
                'code': code,
                'code_msg': 'ok',
                'settings': data
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
