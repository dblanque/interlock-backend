################################################################################
#################### INTERLOCK IS LICENSED UNDER GNU GPLv3 #####################
################## ORIGINAL PROJECT CREATED BY DYLAN BLANQUÉ ###################
########################## AND BR CONSULTING S.R.L. ############################
################################################################################
# Module: core.views.record
# Contains the ViewSet for DNS Record related operations

#---------------------------------- IMPORTS -----------------------------------#
### Models
from core.models.log import logToDB
from core.models.dns import LDAPRecord
from core.models.dnsRecordTypes import *
from core.models.dnsRecordClasses import RECORD_MAPPINGS

### ViewSets
from core.views.base import BaseViewSet

### Exceptions
from django.core.exceptions import PermissionDenied
from core.exceptions import (
    ldap as exc_ldap,
    dns as exc_dns
)

### Mixins
from .mixins.domain import DomainViewMixin

### REST Framework
from rest_framework.response import Response
from rest_framework.exceptions import NotFound
from rest_framework.decorators import action

### Others
from core.utils import dnstool
from core.utils.dnstool import record_to_dict
from interlock_backend.ldap.adsi import addSearchFilter
from interlock_backend.ldap.encrypt import validateUser
from interlock_backend.ldap.settings_func import SettingsList
from interlock_backend.ldap.connector import LDAPConnector
import logging
################################################################################

logger = logging.getLogger(__name__)

class RecordViewSet(BaseViewSet):

    @action(detail=False,methods=['post'])
    def insert(self, request):
        user = request.user
        validateUser(request=request)
        data = {}
        code = 0

        if 'record' not in request.data:
            raise exc_dns.DNSRecordNotInRequest

        recordValues = request.data['record']

        if 'type' not in recordValues:
            raise exc_dns.DNSRecordTypeMissing

        requiredAttributes = [
            'name',
            'type',
            'zone',
            'ttl'
        ]
        # Add the necessary fields for this Record Type to Required Fields
        requiredAttributes.extend(RECORD_MAPPINGS[recordValues['type']]['fields'])

        for a in requiredAttributes:
            if a not in recordValues:
                exception = exc_dns.DNSRecordDataMissing
                data = {
                    "code": exception.default_code,
                    "attribute": a,
                }
                exception.setDetail(exception, data)
                raise exception

        recordName = recordValues.pop('name')
        recordType = recordValues.pop('type')
        recordZone = recordValues.pop('zone')

        ######################## Get Latest Settings ###########################
        ldap_settings_list = SettingsList(**{"search":{
            'LDAP_DOMAIN',
            'LDAP_AUTH_SEARCH_BASE',
            'LDAP_LOG_CREATE'
        }})

        # Open LDAP Connection
        try:
            connector = LDAPConnector(user.dn, user.encryptedPassword, request.user)
            ldapConnection = connector.connection
        except Exception as e:
            print(e)
            raise exc_ldap.CouldNotOpenConnection

        dnsRecord = LDAPRecord(
            connection=ldapConnection,
            rName=recordName,
            rZone=recordZone,
            rType=recordType
        )
        dnsRecord.create(values=recordValues)

        result = dnsRecord.structure.getData()
        dr = dnstool.DNS_RECORD(result)

        ldapConnection.unbind()

        if ldap_settings_list.LDAP_LOG_CREATE == True:
            # Log this action to DB
            logToDB(
                user_id=request.user.id,
                actionType="CREATE",
                objectClass="DNSR",
                affectedObject=recordName + "." + recordZone + " (" + RECORD_MAPPINGS[recordType]['name'] + ")"
            )

        return Response(
             data={
                'code': code,
                'code_msg': 'ok',
                'data' : record_to_dict(dr, ts=False)
             }
        )

    def update(self, request, pk=None):
        user = request.user
        validateUser(request=request)
        data = {}
        code = 0

        ######################## Get Latest Settings ###########################
        ldap_settings_list = SettingsList(**{"search":{
            'LDAP_DOMAIN',
            'LDAP_AUTH_SEARCH_BASE',
            'LDAP_LOG_UPDATE'
        }})

        if 'record' not in request.data or 'oldRecord' not in request.data:
            raise exc_dns.DNSRecordNotInRequest

        recordValues = request.data['record']
        oldRecordValues = request.data['oldRecord']

        if 'type' not in recordValues:
            raise exc_dns.DNSRecordTypeMissing

        requiredAttributes = [
            'name',
            'type',
            'zone',
            'ttl',
            'index'
        ]
        # Add the necessary fields for this Record Type to Required Fields
        requiredAttributes.extend(RECORD_MAPPINGS[recordValues['type']]['fields'])

        for a in requiredAttributes:
            if a not in recordValues:
                exception = exc_dns.DNSRecordDataMissing
                data = {
                    "code": exception.default_code,
                    "attribute": a,
                }
                exception.setDetail(exception, data)
                raise exception

        recordName = recordValues.pop('name')
        recordType = recordValues.pop('type')
        recordZone = recordValues.pop('zone')

        # Open LDAP Connection
        try:
            connector = LDAPConnector(user.dn, user.encryptedPassword, request.user)
            ldapConnection = connector.connection
        except Exception as e:
            print(e)
            raise exc_ldap.CouldNotOpenConnection

        dnsRecord = LDAPRecord(
            connection=ldapConnection,
            rName=recordName,
            rZone=recordZone,
            rType=recordType
        )
        result = dnsRecord.update(recordIndex=recordValues['index'], values=recordValues, oldValues=oldRecordValues)

        result = dnsRecord.structure.getData()
        dr = dnstool.DNS_RECORD(result)

        ldapConnection.unbind()

        return Response(
             data={
                'code': code,
                'code_msg': 'ok',
                'data' : record_to_dict(dr, ts=False)
             }
        )

    @action(detail=False,methods=['post'])
    def delete(self, request):
        user = request.user
        validateUser(request=request)
        data = {}
        code = 0

        if 'record' not in request.data:
            raise exc_dns.DNSRecordNotInRequest

        recordValues = request.data['record']

        if 'type' not in recordValues:
            raise exc_dns.DNSRecordTypeMissing

        requiredAttributes = [
            'name',
            'type',
            'zone',
            'ttl',
            'index'
        ]
        # Add the necessary fields for this Record Type to Required Fields
        requiredAttributes.extend(RECORD_MAPPINGS[recordValues['type']]['fields'])

        for a in requiredAttributes:
            if a not in recordValues:
                exception = exc_dns.DNSRecordDataMissing
                data = {
                    "code": exception.default_code,
                    "attribute": a,
                }
                exception.setDetail(exception, data)
                raise exception

        recordName = recordValues.pop('name')
        recordType = recordValues.pop('type')
        recordZone = recordValues.pop('zone')

        ######################## Get Latest Settings ###########################
        ldap_settings_list = SettingsList(**{"search":{
            'LDAP_DOMAIN',
            'LDAP_AUTH_SEARCH_BASE',
            'LDAP_LOG_DELETE'
        }})

        # Open LDAP Connection
        try:
            connector = LDAPConnector(user.dn, user.encryptedPassword, request.user)
            ldapConnection = connector.connection
        except Exception as e:
            print(e)
            raise exc_ldap.CouldNotOpenConnection

        dnsRecord = LDAPRecord(
            connection=ldapConnection,
            rName=recordName,
            rZone=recordZone,
            rType=recordType
        )
        result = dnsRecord.delete(recordIndex=recordValues['index'], values=recordValues)

        ldapConnection.unbind()

        if ldap_settings_list.LDAP_LOG_DELETE == True:
            # Log this action to DB
            logToDB(
                user_id=request.user.id,
                actionType="DELETE",
                objectClass="DNSR",
                affectedObject=recordName + "." + recordZone + " (" + RECORD_MAPPINGS[recordType]['name'] + ")"
            )

        return Response(
             data={
                'code': code,
                'code_msg': 'ok',
                'data' : result
             }
        )
