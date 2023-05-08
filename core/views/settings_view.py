################################################################################
#################### INTERLOCK IS LICENSED UNDER GNU AGPLv3 ####################
################## ORIGINAL PROJECT CREATED BY DYLAN BLANQUÉ ###################
########################## AND BR CONSULTING S.R.L. ############################
################################################################################
# Module: core.views.settings
# Contains the ViewSet for System Setting related operations

#---------------------------------- IMPORTS -----------------------------------#
### Exceptions
from core.exceptions.ldap import ConnectionTestFailed
from core.exceptions import (
    settings_exc as exc_set,
    ldap as exc_ldap
)

### Models
from core.models.log import logToDB

### Mixins
from .mixins.settings_mixin import SettingsViewMixin

### Viewsets
from .base import BaseViewSet

### REST Framework
from rest_framework.response import Response
from rest_framework.exceptions import NotFound
from rest_framework.decorators import action

### Others
from interlock_backend.ldap.connector import LDAPConnector
from interlock_backend.ldap.constants import (
    __dict__ as constantDictionary
)
from interlock_backend.ldap.cacher import saveToCache, resetCacheToDefaults
from interlock_backend.ldap.encrypt import validateUser
from interlock_backend.ldap.constants_cache import *
from interlock_backend.ldap.settings_func import (
    getSettingsList,
    normalizeValues
)
import logging
import ssl
################################################################################

logger = logging.getLogger(__name__)

class SettingsViewSet(BaseViewSet, SettingsViewMixin):

    def list(self, request, pk=None):
        user = request.user
        validateUser(request=request)
        data = {}
        code = 0

        # Gets front-end parsed settings
        data = getSettingsList()
        data['DEFAULT_ADMIN_ENABLED'] = self.getAdminStatus()

        if LDAP_LOG_READ == True:
            # Log this action to DB
            logToDB(
                user_id=request.user.id,
                actionType="READ",
                objectClass="SET",
                affectedObject="ALL"
            )

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
        validateUser(request=request)
        data = request.data
        code = 0

        adminEnabled = data.pop('DEFAULT_ADMIN_ENABLED')
        adminPassword = data.pop('DEFAULT_ADMIN_PWD')
        self.setAdminStatus(status=adminEnabled, password=adminPassword)

        if 'LDAP_LOG_MAX' in data:
            if int(data['LDAP_LOG_MAX']['value']) > 10000:
                raise exc_set.SettingLogMaxLimit

        data['LDAP_AUTH_CONNECTION_USERNAME'] = dict()
        data['LDAP_AUTH_CONNECTION_USERNAME']['value'] = data['LDAP_AUTH_CONNECTION_USER_DN']['value'].split(',')[0].split('CN=')[1].lower()
        affectedObjects = saveToCache(newValues=data)

        if LDAP_LOG_UPDATE == True:
            # Log this action to DB
            logToDB(
                user_id=request.user.id,
                actionType="UPDATE",
                objectClass="SET",
                affectedObject=affectedObjects
            )

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
        validateUser(request=request)
        data = request.data
        code = 0

        data = resetCacheToDefaults()

        return Response(
             data={
                'code': code,
                'code_msg': 'ok',
                'data': data
             }
        )

    # TODO
    @action(detail=False, methods=['post'])
    def manualcmd(self, request, pk=None):
        user = request.user
        validateUser(request=request)
        data = request.data
        code = 0

        operation = data['operation']
        op_dn = data['dn']
        op_object = data['op_object']
        op_filter = data['op_filter']
        op_attributes = data['op_attributes']

        # Open LDAP Connection
        try:
            c = LDAPConnector(user.dn, user.encryptedPassword, request.user).connection
        except Exception as e:
            print(e)
            raise exc_ldap.CouldNotOpenConnection

        # Unbind the connection
        c.unbind()
        return Response(
             data={
                'code': code,
                'code_msg': 'ok',
                'data': data
             }
        )

    @action(detail=False, methods=['post'])
    def test(self, request, pk=None):
        user = request.user
        validateUser(request=request)
        data = request.data
        code = 0

        data = self.testSettings(user, data)

        if not data:
            raise ConnectionTestFailed

        return Response(
             data={
                'code': code,
                'code_msg': 'ok',
                'data': data
             }
        )
