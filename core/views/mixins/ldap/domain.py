################################################################################
#################### INTERLOCK IS LICENSED UNDER GNU AGPLv3 ####################
################## ORIGINAL PROJECT CREATED BY DYLAN BLANQUÉ ###################
########################## AND BR CONSULTING S.R.L. ############################
################################################################################
# Module: core.views.mixins.domain
# Contains the Mixin for domain related operations

# ---------------------------------- IMPORTS -----------------------------------#
from copy import deepcopy
from rest_framework import viewsets
from core.models.types.ldap_dns_record import RecordTypes
from core.models.dns import LDAPRecord
################################################################################


class DomainViewMixin(viewsets.ViewSetMixin):
	def get_zone_soa(self, zone):
		self.soa_object = LDAPRecord(
			connection=self.connection, rName="@", rZone=zone, rType=RecordTypes.DNS_RECORD_TYPE_SOA.value
		)
		for index, record in enumerate(self.soa_object.data):
			if record["type"] == RecordTypes.DNS_RECORD_TYPE_SOA.value:
				self.soa_bytes = self.soa_object.rawEntry["raw_attributes"]["dnsRecord"][index]
				self.soa = record
		return self.soa

	def increment_soa_serial(self, soa_entry: LDAPRecord, record_serial):
		for index, record in enumerate(soa_entry.data):
			if record["type"] != RecordTypes.DNS_RECORD_TYPE_SOA.value:
				continue
			# If there's a SOA Record
			prev_soa_entry = soa_entry.rawEntry["raw_attributes"]["dnsRecord"][index]
			prev_soa_r = record
			next_soa_r = deepcopy(record)
			next_soa_r["dwSerialNo"] = record_serial
			next_soa_r["serial"] = next_soa_r["dwSerialNo"]

			try:
				soa_entry.update(
					values=next_soa_r, old_record_values=prev_soa_r, old_record_bytes=prev_soa_entry
				)
				return soa_entry.connection.result
			except Exception as e:
				print(e)
