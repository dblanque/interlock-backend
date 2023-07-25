################################################################################
#################### INTERLOCK IS LICENSED UNDER GNU AGPLv3 ####################
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
import logging
################################################################################

logger = logging.getLogger(__name__)

class DNSRecordMixin(DomainViewMixin):
    def validate_record_data(self, record_data):
        valid = False
        # For each field in the Record Value Dictionary
        for f_key in record_data.keys():
            if f_key in DNS_FIELD_VALIDATORS:
                validator = DNS_FIELD_VALIDATORS[f_key]
                f_value = record_data[f_key]
                if validator is not None:
                    # If a list of validators is used, validate with OR
                    if isinstance(validator, list):
                        for v_type in validator:
                            v_func = v_type + "_validator"
                            if valid:
                                break
                            try:
                                valid = self.validate_field(
                                    validator=v_func,
                                    field_name=f_key,
                                    field_value=f_value,
                                    except_on_fail=False
                                )
                            except Exception as e:
                                logger.error(f"Validator: '{v_type}' ({type(v_type)})")
                                logger.error(f"Field Name: '{f_key}' ({type(f_key)})")
                                logger.error(f"Field Value: '{f_value}' ({type(f_value)})")
                                logger.error(e)
                                raise exc_dns.DNSFieldValidatorException
                    elif isinstance(validator, str):
                        validator = validator + "_validator"
                        try:
                            valid = self.validate_field(
                                validator=validator,
                                field_name=f_key,
                                field_value=f_value
                            )
                        except Exception as e:
                            logger.error(f"Validator: '{validator}' ({type(validator)})")
                            logger.error(f"Field Name: '{f_key}' ({type(f_key)})")
                            logger.error(f"Field Value: '{f_value}' ({type(f_value)})")
                            logger.error(e)
                            raise exc_dns.DNSFieldValidatorException

                    if not valid:
                        data = {
                            'field': f_key,
                            'value': f_value
                        }
                        raise exc_dns.DNSFieldValidatorFailed(data)
        return True

    def validate_field(
            self, 
            validator: str, 
            field_name: str, 
            field_value,
            except_on_fail=True,
        ):
        """ DNS Validator Function
        * self
        * validator: Validator Type for Value
        * field_name: DNS Record Field Name (e.g.: address, ttl, etc.)
        * field_value: DNS Record Field Value
        * except_on_fail: Raise exception on failure
        """
        valid = getattr(dnsValidators, validator)(field_value)
        if not valid and except_on_fail:
            data = {
                'field': field_name,
                'value': field_value
            }
            raise exc_dns.DNSFieldValidatorFailed(data=data)
        elif not valid:
            return False
        return True

    def delete_record(self, record, user):
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

        record_name = recordValues.pop('name')
        record_type = recordValues.pop('type')
        record_zone = recordValues.pop('zone')
        record_index = recordValues.pop('index')
        record_bytes = recordValues.pop('record_bytes')
        record_bytes = convert_string_to_bytes(record_bytes)

        if record_zone == 'Root DNS Servers':
            raise exc_dns.DNSRootServersOnlyCLI

        # ! Test record validation with the Mix-in
        DNSRecordMixin.validate_record_data(self, record_data=recordValues)

        # Open LDAP Connection
        try:
            connector = LDAPConnector(user.dn, user.encryptedPassword, user)
            ldapConnection = connector.connection
        except Exception as e:
            print(e)
            raise exc_ldap.CouldNotOpenConnection

        dnsRecord = LDAPRecord(
            connection=ldapConnection,
            rName=record_name,
            rZone=record_zone,
            rType=record_type
        )

        try:
            result = dnsRecord.delete(record_bytes=record_bytes)
        except Exception as e:
            ldapConnection.unbind()
            raise e

        ldapConnection.unbind()

        if record_name == "@":
            affectedObject = record_zone + " (" + RECORD_MAPPINGS[record_type]['name'] + ")"
        else:
            affectedObject = record_name + "." + record_zone + " (" + RECORD_MAPPINGS[record_type]['name'] + ")"

        if LDAP_LOG_DELETE == True:
            # Log this action to DB
            logToDB(
                user_id=user.id,
                actionType="DELETE",
                objectClass="DNSR",
                affectedObject=affectedObject
            )

        return result