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
                # If an override exists in the DB
                querySet = Setting.objects.filter(id = c).exclude(deleted=True)
                if querySet.count() > 0:
                    print("From DB")
                    settingObject = querySet.get(id = c)
                    value = settingObject.value
                    data[c] = value
                else:
                    print("From Constants")
                    # If not then check the manually configured Constants
                    data[c] = ldap_settings.__dict__[c]
                    if c == "LDAP_AUTH_URL":
                        data[c] = copy.deepcopy(ldap_settings.__dict__[c])
                        for key, value in enumerate(data[c]):
                            data[c][key] = str(value).replace('ldap://', '').split(':')[0]
                            data['LDAP_PORT'] = value.split(':')[2]
                    if c == "LDAP_AUTH_TLS_VERSION":
                        data[c] = copy.deepcopy(str(ldap_settings.__dict__[c]).split('.')[-1])
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
