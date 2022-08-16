################################################################################
#################### INTERLOCK IS LICENSED UNDER GNU GPLv3 #####################
################## ORIGINAL PROJECT CREATED BY DYLAN BLANQUÉ ###################
########################## AND BR CONSULTING S.R.L. ############################
################################################################################
# Module: core.views.mixins.domain
# Contains the Mixin for domain related operations

#---------------------------------- IMPORTS -----------------------------------#
from copy import deepcopy
from rest_framework import viewsets
from core.models.dnsRecordTypes import *
from core.models.dns import LDAPRecord
################################################################################

class DomainViewMixin(viewsets.ViewSetMixin):
    def incrementSOASerial(self, ldapConnection, recordZone):
        soaRecord = LDAPRecord(
            connection=ldapConnection,
            rName='@',
            rZone=recordZone,
            rType=DNS_RECORD_TYPE_SOA
        )
        for record in soaRecord.data:
            nextSoa = None
            # If there's a SOA Record
            if record['type'] == DNS_RECORD_TYPE_SOA:
                prevSoa = soaRecord.makeRecord(record, record['serial'], record['ttl']).getData()
                nextSoa = deepcopy(record)
                nextSoa['dwSerialNo'] += 1
                nextSoa['serial'] = nextSoa['dwSerialNo']

            # If zone has no SOA Record
            if nextSoa is None:
                return
        try:
            soaRecord.update(values=nextSoa, oldRecordBytes=prevSoa)
            return soaRecord.connection.result
        except Exception as e:
            raise e
