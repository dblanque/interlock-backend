################################################################################
#################### INTERLOCK IS LICENSED UNDER GNU GPLv3 #####################
################## ORIGINAL PROJECT CREATED BY DYLAN BLANQUÉ ###################
########################## AND BR CONSULTING S.R.L. ############################
################################################################################
# Module: core.views.settings
# Contains the ViewSet for System Setting related operations

#---------------------------------- IMPORTS -----------------------------------#
### Exceptions
from core.exceptions.ldap import ConnectionTestFailed

### Models
from core.models.log import logToDB
from core.models.settings_model import Setting

### Mixins
from .mixins.settings_mixin import SettingsViewMixin

### REST Framework
from rest_framework.response import Response
from rest_framework import viewsets
from rest_framework.exceptions import NotFound
from rest_framework.decorators import action

### Others
from interlock_backend.ldap.constants import (
    __dict__ as constantDictionary
)
from interlock_backend.ldap.encrypt import validateUser
from interlock_backend.ldap import constants as ldap_constants
from interlock_backend.ldap.settings_func import (
    SettingsList,
    getSettingsList,
    normalizeValues
)
import logging
import ssl
################################################################################

logger = logging.getLogger(__name__)

class SettingsViewSet(viewsets.ViewSet, SettingsViewMixin):
    queryset = Setting.objects.all()

    def list(self, request, pk=None):
        user = request.user
        validateUser(request=request)
        data = {}
        code = 0

        ######################## Get Latest Settings ###########################
        ldap_settings_list = SettingsList(**{"search":{ 'LDAP_LOG_READ' }})
        ########################################################################

        # Gets front-end parsed settings
        data = getSettingsList()
        data['DEFAULT_ADMIN_ENABLED'] = self.getAdminStatus()

        if ldap_settings_list.LDAP_LOG_READ == True:
            # Log this action to DB
            logToDB(
                user_id=request.user.id,
                actionType="READ",
                objectClass="SET",
                affectedObject="ALL"
            )
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
        validateUser(request=request)
        data = request.data
        code = 0

        ######################## Get Latest Settings ###########################
        ldap_settings_list = SettingsList(**{"search":{ 'LDAP_LOG_UPDATE' }})
        ########################################################################

        adminEnabled = data.pop('DEFAULT_ADMIN_ENABLED')
        adminPassword = data.pop('DEFAULT_ADMIN_PWD')
        self.setAdminStatus(status=adminEnabled, password=adminPassword)

        valueFields = [
            'value',
            'value_bool',
            'value_json',
            'value_int',
            'value_float'
        ]

        affectedObjects = list()

        for setting in data:
            data[setting] = normalizeValues(setting, data[setting])
            if setting in constantDictionary:
                dictValue = getattr(ldap_constants, setting)
                if dictValue not in data[setting].values():
                    logger.debug("Located in: "+__name__+'.save')
                    logger.debug('Value in data for ' + setting)
                    logger.debug(data[setting]['value'])
                    logger.debug('Type in data for ' + setting)
                    logger.debug(type(data[setting]['value']))
                    logger.debug('Value in constants dict for ' + setting)
                    logger.debug(dictValue)
                    logger.debug('Type in constants dict for ' + setting)
                    logger.debug(type(dictValue))
                    code = self.update_or_create_setting(setting, data[setting])
                    if code == "UPDATE_SUCCESS" or code == "CREATE_SUCCESS":
                        affectedObjects.append({
                            'name': setting,
                            'objectInstance': data[setting]
                        })
                else:
                    for field in valueFields:
                        if field in data[setting]:
                            if dictValue == data[setting][field]:
                                code = self.delete_setting(setting, data[setting])
                                if code == "DELETE_SUCCESS":
                                    affectedObjects.append( setting )

        if ldap_settings_list.LDAP_LOG_UPDATE == True:
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

        data = self.resetSettings()

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
