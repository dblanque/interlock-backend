################################################################################
#################### INTERLOCK IS LICENSED UNDER GNU GPLv3 #####################
################## ORIGINAL PROJECT CREATED BY DYLAN BLANQUÉ ###################
########################## AND BR CONSULTING S.R.L. ############################
################################################################################
# Module: core.views.mixins.record
# Contains the Mixin for DNS Record related operations

#---------------------------------- IMPORTS -----------------------------------#
### ViewSets
from rest_framework import viewsets

### Exceptions
from core.exceptions import (
    ldap as exc_ldap,
    dns as exc_dns
)

### Models
from core.models.log import logToDB
from core.models.dns import LDAPRecord
from core.models.dnsRecordTypes import *
from core.models.dnsRecordClasses import RECORD_MAPPINGS
from core.models.dnsRecordFieldValidators import FIELD_VALIDATORS as DNS_FIELD_VALIDATORS
from core.models import dnsRecordFieldValidators as dnsValidators

### Mixins
from core.views.mixins.utils import convert_string_to_bytes

### Interlock
from interlock_backend.ldap.constants_cache import *
from interlock_backend.ldap.connector import LDAPConnector
from core.views.mixins.domain import DomainViewMixin
################################################################################

class DNSRecordMixin(DomainViewMixin):
    def deleteRecord(self, record, user):
        recordValues = record

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
                data = {
                    "attribute": a,
                }
                raise exc_dns.DNSRecordDataMissing(data=data)

        recordName = recordValues.pop('name')
        recordType = recordValues.pop('type')
        recordZone = recordValues.pop('zone')
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

        # Open LDAP Connection
        try:
            connector = LDAPConnector(user.dn, user.encryptedPassword, user)
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

        try:
            result = dnsRecord.delete(recordBytes=recordBytes)
        except Exception as e:
            ldapConnection.unbind()
            raise e

        ldapConnection.unbind()

        if recordName == "@":
            affectedObject = recordZone + " (" + RECORD_MAPPINGS[recordType]['name'] + ")"
        else:
            affectedObject = recordName + "." + recordZone + " (" + RECORD_MAPPINGS[recordType]['name'] + ")"

        if LDAP_LOG_DELETE == True:
            # Log this action to DB
            logToDB(
                user_id=user.id,
                actionType="DELETE",
                objectClass="DNSR",
                affectedObject=affectedObject
            )

        return result