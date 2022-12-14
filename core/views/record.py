################################################################################
#################### INTERLOCK IS LICENSED UNDER GNU AGPLv3 ####################
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
from .mixins.record import DNSRecordMixin

### REST Framework
from rest_framework.response import Response
from rest_framework.exceptions import NotFound
from rest_framework.decorators import action

### Others
from core.utils import dnstool
from core.utils.dnstool import record_to_dict
from core.views.mixins.utils import convert_string_to_bytes
from core.models.dnsRecordFieldValidators import FIELD_VALIDATORS as DNS_FIELD_VALIDATORS
from core.models import dnsRecordFieldValidators as dnsValidators
from interlock_backend.ldap.adsi import addSearchFilter
from interlock_backend.ldap.encrypt import validateUser
from interlock_backend.ldap.constants_cache import *
from interlock_backend.ldap.connector import LDAPConnector
import logging
################################################################################

logger = logging.getLogger(__name__)

class RecordViewSet(BaseViewSet, DNSRecordMixin):

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

        recordName = recordValues.pop('name').lower()
        recordType = recordValues.pop('type')
        recordZone = recordValues.pop('zone').lower()

        if recordZone == 'Root DNS Servers':
            raise exc_dns.DNSRootServersOnlyCLI

        for f in recordValues.keys():
            if f in DNS_FIELD_VALIDATORS:
                if DNS_FIELD_VALIDATORS[f] is not None:
                    validator = DNS_FIELD_VALIDATORS[f] + "_validator"
                    if getattr(dnsValidators, validator)(recordValues[f]) == False:
                        data = {
                            'field': f,
                            'value': recordValues[f]
                        }
                        raise exc_dns.DNSFieldValidatorFailed(data=data)

        if recordType == DNS_RECORD_TYPE_SOA and recordName != "@":
            raise exc_dns.SOARecordRootOnly

        if 'stringData' in recordValues:
            if len(recordValues['stringData']) > 255:
                raise exc_dns.DNSStringDataLimit

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

        # Update Start of Authority Record Serial
        if recordType != DNS_RECORD_TYPE_SOA:
            self.incrementSOASerial(ldapConnection=ldapConnection, recordZone=recordZone)

        # result = dnsRecord.structure.getData()
        # dr = dnstool.DNS_RECORD(result)

        ldapConnection.unbind()

        if recordName == "@":
            affectedObject = recordZone + " (" + RECORD_MAPPINGS[recordType]['name'] + ")"
        else:
            affectedObject = recordName + "." + recordZone + " (" + RECORD_MAPPINGS[recordType]['name'] + ")"

        if LDAP_LOG_CREATE == True:
            # Log this action to DB
            logToDB(
                user_id=request.user.id,
                actionType="CREATE",
                objectClass="DNSR",
                affectedObject=affectedObject
            )

        return Response(
             data={
                'code': code,
                'code_msg': 'ok',
                # 'data' : record_to_dict(dr, ts=False)
             }
        )

    def update(self, request, pk=None):
        user = request.user
        validateUser(request=request)
        data = {}
        code = 0

        if 'record' not in request.data or 'oldRecord' not in request.data:
            raise exc_dns.DNSRecordNotInRequest

        recordValues = request.data['record']

        if 'type' not in recordValues:
            raise exc_dns.DNSRecordTypeMissing

        requiredAttributes = [
            'name',
            'type',
            'zone',
            'ttl',
            'index',
            'record_bytes'
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

        recordName = recordValues.pop('name').lower()
        recordType = recordValues.pop('type')
        recordZone = recordValues.pop('zone').lower()
        recordIndex = recordValues.pop('index')
        recordBytes = recordValues.pop('record_bytes')
        recordBytes = convert_string_to_bytes(recordBytes)

        if recordZone == 'Root DNS Servers':
            raise exc_dns.DNSRootServersOnlyCLI

        for f in recordValues.keys():
            if f in DNS_FIELD_VALIDATORS:
                if DNS_FIELD_VALIDATORS[f] is not None:
                    validator = DNS_FIELD_VALIDATORS[f] + "_validator"
                    if getattr(dnsValidators, validator)(recordValues[f]) == False:
                        data = {
                            'field': f,
                            'value': recordValues[f]
                        }
                        raise exc_dns.DNSFieldValidatorFailed(data=data)

        if 'stringData' in recordValues:
            if len(recordValues['stringData']) > 255:
                raise exc_dns.DNSStringDataLimit

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
        result = dnsRecord.update(values=recordValues, oldRecordBytes=recordBytes)

        # Update Start of Authority Record Serial
        if recordType != DNS_RECORD_TYPE_SOA:
            self.incrementSOASerial(ldapConnection=ldapConnection, recordZone=recordZone)

        result = dnsRecord.structure.getData()
        dr = dnstool.DNS_RECORD(result)

        ldapConnection.unbind()

        if recordName == "@":
            affectedObject = recordZone + " (" + RECORD_MAPPINGS[recordType]['name'] + ")"
        else:
            affectedObject = recordName + "." + recordZone + " (" + RECORD_MAPPINGS[recordType]['name'] + ")"

        if LDAP_LOG_UPDATE == True:
            # Log this action to DB
            logToDB(
                user_id=request.user.id,
                actionType="UPDATE",
                objectClass="DNSR",
                affectedObject=affectedObject
            )

        return Response(
             data={
                'code': code,
                'code_msg': 'ok',
                'data' : record_to_dict(dr, ts=False)
             }
        )

    @action(detail=False, methods=['post'])
    def delete(self, request):
        user = request.user
        validateUser(request=request)
        data = {}
        code = 0

        if 'record' in request.data:
            mode = 'single'
        elif 'records' in request.data:
            mode = 'multiple'
        else:
            raise exc_dns.DNSRecordNotInRequest

        if mode == 'single':
            if isinstance(request.data['record'], dict):
                recordValues = request.data['record']
            else:
                data = {
                    'mode': mode,
                    'data': request.data['record']
                }
                raise exc_dns.DNSRecordDataMalformed(data=data)
        elif mode == 'multiple':
            if isinstance(request.data['records'], list):
                recordValues = request.data['records']
            else:
                data = {
                    'mode': mode,
                    'data': request.data['records']
                }
                raise exc_dns.DNSRecordDataMalformed

        if isinstance(recordValues, dict):
            result = self.deleteRecord(recordValues, user)
        elif isinstance(recordValues, list):
            result = list()
            for r in recordValues:
                print(r)
                result.append(self.deleteRecord(r, user))

        return Response(
             data={
                'code': code,
                'code_msg': 'ok',
                'data' : result
             }
        )
