################################################################################
#################### INTERLOCK IS LICENSED UNDER GNU AGPLv3 ####################
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
    def get_zone_soa(self, zone):
        self.soa_object = LDAPRecord(
            connection=self.connection,
            rName='@',
            rZone=zone,
            rType=DNS_RECORD_TYPE_SOA
        )
        for index, record in enumerate(self.soa_object.data):
            if record['type'] == DNS_RECORD_TYPE_SOA:
                self.soa_bytes = self.soa_object.rawEntry['raw_attributes']['dnsRecord'][index]
                self.soa = record
        return self.soa

    def increment_soa_serial(self, soa_entry, record_serial):
        next_soa_r = None
        for index, record in enumerate(soa_entry.data):
            # If there's a SOA Record
            if record['type'] == DNS_RECORD_TYPE_SOA:
                prev_soa_entry = soa_entry.rawEntry['raw_attributes']['dnsRecord'][index]
                prev_soa_r = record
                next_soa_r = deepcopy(record)
                next_soa_r['dwSerialNo'] = record_serial
                next_soa_r['serial'] = next_soa_r['dwSerialNo']

        # If zone has no SOA Record
        if next_soa_r is None:
            print("No SOA Record")
            return
        try:
            soa_entry.update(values=next_soa_r, old_record_values=prev_soa_r, old_record_bytes=prev_soa_entry)
            return soa_entry.connection.result
        except Exception as e:
            print(e)
