import copy
from django.conf import Settings
from django.core.exceptions import PermissionDenied
from rest_framework.response import Response
from core.models.settings import Setting
from .mixins.settings import SettingsViewMixin
from rest_framework import viewsets
from rest_framework.exceptions import NotFound
from rest_framework.decorators import action
from interlock_backend import ldap_settings
import logging
from core.exceptions.settings import (
    SettingTypeDoesNotMatch
)
import ssl

logger = logging.getLogger(__name__)

class SettingsViewSet(viewsets.ViewSet, SettingsViewMixin):
    queryset = Setting.objects.all()

    def list(self, request, pk=None):
        user = request.user
        if user.is_staff == False or not user:
            raise PermissionDenied
        data = {}
        code = 0

        validSettings = ldap_settings.SETTINGS_WITH_ALLOWABLE_OVERRIDE

        for c in ldap_settings.__dict__:
            if c in validSettings:
                # Init Object/Dict
                data[c] = {}
                # If an override exists in the DB
                querySet = Setting.objects.filter(id = c).exclude(deleted=True)
                if querySet.count() > 0:
                    logger.debug(c + "was fetched from DB")
                    settingObject = querySet.get(id = c)
                    value = settingObject.value
                    value = settingObject.type
                    data[c]['value'] = value
                    data[c]['type'] = value
                else:
                    logger.debug(c + "was fetched from Constants File")
                    # If not then check the manually configured Constants
                    data[c]['value'] = ldap_settings.__dict__[c]
                    if 'type' in ldap_settings.SETTINGS_WITH_ALLOWABLE_OVERRIDE[c]:
                        data[c]['type'] = ldap_settings.SETTINGS_WITH_ALLOWABLE_OVERRIDE[c]['type']
                    else:
                        data[c]['type'] = 'string'

                    if c == "LDAP_AUTH_URL":
                        data[c]['value'] = copy.deepcopy(ldap_settings.__dict__[c])
                        for key, value in enumerate(data[c]['value']):
                            data[c]['value'][key] = str(value)
                    if c == "LDAP_AUTH_TLS_VERSION":
                        data[c]['value'] = copy.deepcopy(str(ldap_settings.__dict__[c]).split('.')[-1])
                    logger.debug(c)
                    logger.debug(ldap_settings.__dict__[c])
                    logger.debug(data[c])

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
        if user.is_staff == False or not user:
            raise PermissionDenied
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
