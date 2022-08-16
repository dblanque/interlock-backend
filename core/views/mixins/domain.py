################################################################################
#################### INTERLOCK IS LICENSED UNDER GNU GPLv3 #####################
################## ORIGINAL PROJECT CREATED BY DYLAN BLANQUÉ ###################
########################## AND BR CONSULTING S.R.L. ############################
################################################################################
# Module: core.views.mixins.domain
# Contains the Mixin for domain related operations

#---------------------------------- IMPORTS -----------------------------------#
from rest_framework import viewsets
from core.models.dnsRecordTypes import *
from core.utils.dnstool import record_to_dict
from core.models.dns import LDAPRecord
from core.utils import dnstool
################################################################################

class DomainViewMixin(viewsets.ViewSetMixin):
    def updateSOASerial(self, ldapConnection, recordZone):
        soaRecord = LDAPRecord(
            connection=ldapConnection,
            rName='@',
            rZone=recordZone,
            rType=DNS_RECORD_TYPE_SOA
        )
        for record in soaRecord.rawEntry['raw_attributes']['dnsRecord']:
            searchSoa = dnstool.DNS_RECORD(record)
            if record_to_dict(searchSoa, ts=False)['type'] == DNS_RECORD_TYPE_SOA:
                prevSoa = record_to_dict(searchSoa, ts=False)
                prevSoa['ttl'] = searchSoa.__getTTL__()
                nextSoa = record_to_dict(searchSoa, ts=False)
                nextSoa['ttl'] = searchSoa.__getTTL__()
                nextSoa['dwSerialNo'] += 1
                nextSoa['serial'] = nextSoa['dwSerialNo']
        try:
            soaRecord.update(values=nextSoa, oldValues=prevSoa)
            return soaRecord.connection.result
        except Exception as e:
            raise e
