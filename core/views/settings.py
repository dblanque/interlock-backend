import string
import types
from django.core.exceptions import PermissionDenied
from rest_framework.response import Response
from .mixins.domain import DomainViewMixin
from rest_framework import viewsets
from rest_framework.exceptions import NotFound
from rest_framework.decorators import action
from interlock_backend import ldap_settings
import logging

logger = logging.getLogger(__name__)

class SettingsViewSet(viewsets.ViewSet, DomainViewMixin):

    def list(self, request, pk=None):
        user = request.user
        if user.is_staff == False or not user:
            raise PermissionDenied
        data = {}
        code = 0

        validSettings = [
            "LDAP_AUTH_URL",
            "LDAP_DOMAIN",
            "LDAP_AUTH_USE_TLS",
            "LDAP_AUTH_TLS_VERSION",
            "LDAP_AUTH_SEARCH_BASE",
            "LDAP_AUTH_OBJECT_CLASS",
            "EXCLUDE_COMPUTER_ACCOUNTS",
            "LDAP_AUTH_USER_FIELDS",
            "LDAP_AUTH_ACTIVE_DIRECTORY_DOMAIN",
            "LDAP_AUTH_CONNECTION_USER_DN",
            "LDAP_AUTH_CONNECTION_USERNAME",
            "LDAP_AUTH_CONNECTION_PASSWORD",
            "LDAP_AUTH_CONNECT_TIMEOUT",
            "LDAP_AUTH_RECEIVE_TIMEOUT",
            "ADMIN_GROUP_TO_SEARCH",
            "LDAP_AUTH_USER_LOOKUP_FIELDS"
        ]

        for c in ldap_settings.__dict__:
            if c in validSettings:
                
                data[c] = ldap_settings.__dict__[c]
                if c == "LDAP_AUTH_URL":
                    data[c] = ldap_settings.__dict__[c]
                    for key, value in enumerate(data[c]):
                        data[c][key] = str(value).replace('ldap://', '').split(':')[0]
                if c == "LDAP_AUTH_TLS_VERSION":
                    data[c] = str(ldap_settings.__dict__[c]).split('.')[-1]
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
