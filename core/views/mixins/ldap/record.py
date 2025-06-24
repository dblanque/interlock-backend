################################################################################
#################### INTERLOCK IS LICENSED UNDER GNU AGPLv3 ####################
################## ORIGINAL PROJECT CREATED BY DYLAN BLANQUÉ ###################
########################## AND BR CONSULTING S.R.L. ############################
################################################################################
# Module: core.views.mixins.ldap.record
# Contains the Mixin for DNS Record related operations

# ---------------------------------- IMPORTS --------------------------------- #
### Exceptions
from core.exceptions import base as exc_base, ldap as exc_ldap, dns as exc_dns

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
from ldap3 import Connection
from core.models.validators.ldap import record_type_validator
################################################################################

DBLogMixin = LogMixin()
logger = logging.getLogger(__name__)


class DNSRecordMixin(DomainViewMixin):
	ldap_connection: Connection = None
	record_serializer = DNSRecordSerializer

	def check_if_connection_is_bound(self):
		if not getattr(self.ldap_connection, "bound", False):
			raise exc_ldap.LDAPConnectionNotOpen

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
		unknown_keys = set(self.record_serializer.initial_data.keys()) - set(
			self.record_serializer.fields.keys()
		)
		if unknown_keys:
			logger.info(
				"Unknown keys in serialized data for LDAP DNS Record: %s.",
				unknown_keys,
			)

		# Check that it's not modifying Root DNS Server data
		if record_data["zone"].lower() in [
			"rootdnsservers",
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

	def create_record(self, record_data: dict) -> dict:
		"""Creates LDAP DNS Record in corresponding entry or new entry if it does not
		exist.

		Args:
			record_data (dict): Record Data Dictionary

		Raises:
			exc_dns.DNSCouldNotIncrementSOA: Raised if the SOA Serial could not
				be increased.

		Returns:
			dict: Resulting DNS Record as dict.
		"""
		self.check_if_connection_is_bound()

		record_name: str = record_data["name"].lower()
		record_type: RecordTypes = record_data["type"]
		record_zone: str = record_data["zone"].lower()
		record_serial: int = record_data.pop("serial", None)

		dns_record = LDAPRecord(
			connection=self.ldap_connection,
			record_name=record_name,
			record_zone=record_zone,
			record_type=record_type,
			record_main_value=record_data[record_type_main_field(record_type)],
		)

		dns_record.create(values=record_data)

		#########################################
		# Update Start of Authority Record Serial
		if record_type != RecordTypes.DNS_RECORD_TYPE_SOA.value:
			try:
				# Only auto-increment SOA if no serial is set.
				if not record_serial:
					self.increment_soa_serial(
						dns_record.soa_object, dns_record.serial
					)
			except Exception as e:
				logger.exception(e)
				raise exc_dns.DNSCouldNotIncrementSOA

		DBLogMixin.log(
			user=self.request.user.id,
			operation_type=LOG_ACTION_CREATE,
			log_target_class=LOG_CLASS_DNSR,
			log_target=dns_record.display_name,
		)
		return dns_record.as_dict

	def update_record(self, record_data: dict, old_record_data: dict) -> dict:
		"""Updates LDAP DNS Record in its corresponding entry.

		Args:
			record_data (dict): Validated Record Data Dictionary
			old_record_data (dict): Validated Old Record Data Dictionary

		Raises:
			exc_base.CoreException: Raised if record could not be creating when name has
				changed from it's previous instance.
			exc_dns.DNSCouldNotIncrementSOA: Raised if SOA Serial could not be increased.

		Returns:
			dict: Resulting DNS Record as dict.
		"""
		self.check_if_connection_is_bound()

		# Type Consistency Check
		record_type: RecordTypes = record_data.get("type")
		old_record_type: RecordTypes = old_record_data.get("type")
		if not record_type == old_record_type:
			raise exc_dns.DNSRecordTypeMismatch

		# Zone Consistency Check
		record_zone: str = record_data.get("zone").lower()
		old_record_zone: str = old_record_data.get("zone").lower()
		if not record_zone == old_record_zone:
			raise exc_dns.DNSRecordZoneMismatch

		# Name can differ
		record_name: str = record_data.get("name").lower()
		old_record_name: str = old_record_data.get("name").lower()

		# If serial remains same, remove for auto-increment
		serial_changed = record_data["serial"] != old_record_data["serial"]
		if not serial_changed:
			record_data.pop("serial")

		dns_record = LDAPRecord(
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
				record_main_value=old_record_data[
					record_type_main_field(old_record_type)
				],
			)
			# Create new record with different name
			result = dns_record.create(values=record_data)
			if result["result"] != 0:
				raise exc_base.LDAPBackendException
			# If creation was successful delete old record
			old_record.delete()
		else:
			result = dns_record.update(
				new_values=record_data, old_values=old_record_data
			)

		#########################################
		# Update Start of Authority Record Serial
		if record_type != RecordTypes.DNS_RECORD_TYPE_SOA.value:
			try:
				# Only auto-increment SOA if no serial is set.
				if not serial_changed:
					self.increment_soa_serial(
						dns_record.soa_object, dns_record.serial
					)
			except Exception as e:
				logger.exception(e)
				raise exc_dns.DNSCouldNotIncrementSOA

		DBLogMixin.log(
			user=self.request.user.id,
			operation_type=LOG_ACTION_UPDATE,
			log_target_class=LOG_CLASS_DNSR,
			log_target=dns_record.__fullname__(),
		)
		return dns_record.as_dict

	def delete_record(self, record_data: dict):
		"""Deletes LDAP DNS Record from its corresponding entry

		Args:
			record_data (dict): Record Data Dictionary

		Raises:
			exc_ldap.LDAPConnectionNotOpen: Raised if no ldap connection is available.

		Returns:
			LDAP Operation Result.
		"""
		self.check_if_connection_is_bound()

		record_name = record_data.get("name")
		record_type = record_data.get("type")
		record_zone = record_data.get("zone")

		dns_record = LDAPRecord(
			connection=self.ldap_connection,
			record_name=record_name,
			record_zone=record_zone,
			record_type=record_type,
			record_main_value=record_data[record_type_main_field(record_type)],
		)

		result = dns_record.delete()

		DBLogMixin.log(
			user=self.request.user.id,
			operation_type=LOG_ACTION_DELETE,
			log_target_class=LOG_CLASS_DNSR,
			log_target=dns_record.__fullname__(),
		)

		return result
