################################################################################
#################### INTERLOCK IS LICENSED UNDER GNU AGPLv3 ####################
################## ORIGINAL PROJECT CREATED BY DYLAN BLANQUÉ ###################
########################## AND BR CONSULTING S.R.L. ############################
################################################################################
# Module: core.views.mixins.ldap.record
# Contains the Mixin for DNS Record related operations

# ---------------------------------- IMPORTS -----------------------------------#
### Exceptions
from core.exceptions import (
	base as exc_base,
	ldap as exc_ldap,
	dns as exc_dns
)

### Models
from core.views.mixins.logs import LogMixin
from core.models.dns import LDAPRecord, record_type_main_field
from core.models.structs.ldap_dns_record import RecordTypes
from core.models.choices.log import (
	LOG_CLASS_DNSR,
	LOG_ACTION_CREATE,
	LOG_ACTION_UPDATE,
	LOG_ACTION_DELETE,
)

### Interlock
from core.views.mixins.ldap.domain import DomainViewMixin
import logging

### Serializers
from core.serializers.record import DNSRecordSerializer, DNS_RECORD_SERIALIZERS

### Others
from core.models.validators.ldap import record_type_validator
from core.utils import dnstool
import traceback
################################################################################

DBLogMixin = LogMixin()
logger = logging.getLogger(__name__)


class DNSRecordMixin(DomainViewMixin):
	ldap_connection = None
	record_serializer = DNSRecordSerializer

	def get_serializer(self, record_type: RecordTypes) -> DNSRecordSerializer:
		"""Fetches LDAP DNS Record Serializer based on type int

		Args:
			record_type (int): Record Type (see core.models.structs.ldap_dns_record)

		Raises:
			exc_dns.DNSRecordTypeMissing: Raised when record_type is falsy
			exc_dns.DNSRecordTypeUnsupported: Raised when record_type is invalid 
				or unsupported.

		Returns:
			DNSRecordSerializer: Record serializer for corresponding type.
		"""
		if not record_type:
			raise exc_dns.DNSRecordTypeMissing
		record_type_validator(record_type)
		return DNS_RECORD_SERIALIZERS[record_type]

	def validate_record(self, record_data: dict) -> dict:
		"""Validates LDAP DNS Record data dictionary.

		Args:
			record_data (dict): The record data dictionary

		Raises:
			exc_dns.DNSRootServersOnlyCLI: Raised when zone is related to root dns servers.
			exc_dns.SOARecordRootOnly: Raised when a SOA Record uses a
				sub-domain as a name.
			exc_dns.DNSRecordTypeConflict: Raised when a Record Type with NameNode RPC
				Structure references itself.

		Returns:
			dict: Validated data dictionary
		"""
		# Record Data Validation
		record_type = record_data.get("type", None)
		self.record_serializer = self.get_serializer(record_type)
		self.record_serializer: DNSRecordSerializer = self.record_serializer(
			data=record_data
		)
		self.record_serializer.is_valid(raise_exception=True)
		unknown_keys = (
			set(self.record_serializer.initial_data.keys())
			-
			set(self.record_serializer.fields.keys())
		)
		if unknown_keys:
			logger.info(
				"Unknown keys in serialized data for LDAP DNS Record: %s.", unknown_keys)

		# Check that it's not modifying Root DNS Server data
		if record_data["zone"].lower() in [
			"root dns servers",
			"root",
			"root.",
			".",
			"@",
		]:
			raise exc_dns.DNSRootServersOnlyCLI

		# Check that SOA record is at top level of zone
		if (
			record_data["type"] == RecordTypes.DNS_RECORD_TYPE_SOA.value
			and record_data["name"] != "@"
		):
			raise exc_dns.SOARecordRootOnly

		# Check that cname does not reference itself
		if "nameNode" in record_data:
			_name = record_data["name"]
			_zone = record_data["zone"]
			label = str(record_data["nameNode"])

			if _zone in label:
				_check_self_ref = f"{_name}.{_zone}"
				if label == _check_self_ref or label == f"{_check_self_ref}.":
					logger.error("Record Self-reference error detected.")
					raise exc_dns.DNSRecordSelfReference
		return self.record_serializer.validated_data

	def create_record(self, record_data: dict):
		record_name: str = record_data["name"].lower()
		record_type: RecordTypes = record_data["type"]
		record_zone: str = record_data["zone"].lower()

		if "serial" in record_data and isinstance(record_data["serial"], str):
			record_data.pop("serial")

		dnsRecord = LDAPRecord(
			connection=self.ldap_connection,
			record_name=record_name,
			record_zone=record_zone,
			record_type=record_type,
			record_main_value=record_data[record_type_main_field(record_type)],
		)

		dnsRecord.create(values=record_data)

		#########################################
		# Update Start of Authority Record Serial
		if record_type != RecordTypes.DNS_RECORD_TYPE_SOA.value:
			try:
				self.increment_soa_serial(dnsRecord.soa_object, dnsRecord.serial)
			except:
				logger.error(traceback.format_exc())
				raise exc_dns.DNSCouldNotIncrementSOA

		result = dnsRecord.structure.getData()
		dr = dnstool.DNS_RECORD(result)

		DBLogMixin.log(
			user=self.request.user.id,
			operation_type=LOG_ACTION_CREATE,
			log_target_class=LOG_CLASS_DNSR,
			log_target=dnsRecord.__fullname__(),
		)
		return dr

	def update_record(self, record_data: dict, old_record_data: dict):
		old_record_name = old_record_data["name"].lower()
		record_name: str = record_data["name"].lower()
		record_type: RecordTypes = record_data["type"]
		record_zone: str = record_data["zone"].lower()
		old_record_name: str = old_record_data["name"].lower()
		old_record_type: RecordTypes = old_record_data["type"]
		old_record_zone: str = old_record_data["zone"].lower()
		assert record_type == old_record_type
		assert record_zone == old_record_zone

		if (
			isinstance(record_data["serial"], str)
			or record_data["serial"] == old_record_data["serial"]
		):
			record_data.pop("serial")

		dnsRecord = LDAPRecord(
			connection=self.ldap_connection,
			record_name=record_name,
			record_zone=record_zone,
			record_type=record_type,
			record_main_value=record_data[record_type_main_field(record_type)],
		)

		# ! If Record Name is being changed create the new one and delete the old.
		if old_record_name != record_name:
			old_record = LDAPRecord(
				connection=self.ldap_connection,
				record_name=old_record_name,
				record_zone=old_record_zone,
				record_type=old_record_type,
				record_main_value=old_record_data[record_type_main_field(old_record_type)],
			)
			# Create new Record
			result = dnsRecord.create(values=record_data)
			if result["result"] == 0:
				old_record.delete()
			else:
				raise exc_base.CoreException
		else:
			result = dnsRecord.update(new_values=record_data, old_values=old_record_data)

		#########################################
		# Update Start of Authority Record Serial
		if record_type != RecordTypes.DNS_RECORD_TYPE_SOA.value:
			try:
				self.increment_soa_serial(dnsRecord.soa_object, dnsRecord.serial)
			except:
				logger.error(traceback.format_exc())
				raise exc_dns.DNSCouldNotIncrementSOA

		result = dnsRecord.structure.getData()
		dr = dnstool.DNS_RECORD(result)

		DBLogMixin.log(
			user=self.request.user.id,
			operation_type=LOG_ACTION_UPDATE,
			log_target_class=LOG_CLASS_DNSR,
			log_target=dnsRecord.__fullname__(),
		)
		return dr

	def delete_record(self, record_data: dict):
		if not self.ldap_connection:
			raise exc_ldap.LDAPConnectionNotOpen

		record_name = record_data["name"]
		record_type = record_data["type"]
		record_zone = record_data["zone"]

		dnsRecord = LDAPRecord(
			connection=self.ldap_connection,
			record_name=record_name,
			record_zone=record_zone,
			record_type=record_type,
			record_main_value=record_data[record_type_main_field(record_type)],
		)

		try:
			result = dnsRecord.delete()
		except Exception as e:
			raise e

		DBLogMixin.log(
			user=self.request.user.id,
			operation_type=LOG_ACTION_DELETE,
			log_target_class=LOG_CLASS_DNSR,
			log_target=dnsRecord.__fullname__(),
		)

		return result
