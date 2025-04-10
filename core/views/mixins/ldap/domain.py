################################################################################
#################### INTERLOCK IS LICENSED UNDER GNU AGPLv3 ####################
################## ORIGINAL PROJECT CREATED BY DYLAN BLANQUÉ ###################
########################## AND BR CONSULTING S.R.L. ############################
################################################################################
# Module: core.views.mixins.ldap.domain
# Contains the Mixin for domain related operations

# ---------------------------------- IMPORTS -----------------------------------#
from rest_framework import viewsets
from core.models.types.ldap_dns_record import RecordTypes
from core.models.dns import LDAPRecord
################################################################################


class DomainViewMixin(viewsets.ViewSetMixin):
	def get_zone_soa(self, zone):
		self.soa_object = LDAPRecord(
			connection=self.connection,
			record_name="@",
			record_zone=zone,
			record_type=RecordTypes.DNS_RECORD_TYPE_SOA.value,
		)
		self.soa_bytes = self.soa_object.as_bytes
		self.soa = self.soa_object.data
		return self.soa

	def increment_soa_serial(self, soa_entry: LDAPRecord, record_serial):
		record: dict = soa_entry.data
		prev_soa_r = record.copy()
		next_soa_r = record.copy()
		next_soa_r["dwSerialNo"] = record_serial
		next_soa_r["serial"] = next_soa_r["dwSerialNo"]

		try:
			soa_entry.update(new_values=next_soa_r, old_values=prev_soa_r)
			return soa_entry.connection.result
		except Exception as e:
			print(e)
