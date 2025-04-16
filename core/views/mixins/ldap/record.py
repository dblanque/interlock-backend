################################################################################
#################### INTERLOCK IS LICENSED UNDER GNU AGPLv3 ####################
################## ORIGINAL PROJECT CREATED BY DYLAN BLANQUÉ ###################
########################## AND BR CONSULTING S.R.L. ############################
################################################################################
# Module: core.views.mixins.ldap.record
# Contains the Mixin for DNS Record related operations

# ---------------------------------- IMPORTS -----------------------------------#
### Exceptions
from core.exceptions import base as exc_base, ldap as exc_ldap, dns as exc_dns

### Models
from core.views.mixins.logs import LogMixin
from core.models.dns import LDAPRecord, record_type_main_field
from core.models.structs.ldap_dns_record import RECORD_MAPPINGS, RecordTypes
from core.models.validators.ldap_dns_record import FIELD_VALIDATORS as DNS_FIELD_VALIDATORS
from core.models.validators import ldap_dns_record as dnsValidators
from core.models.choices.log import (
	LOG_CLASS_DNSR,
	LOG_ACTION_CREATE,
	LOG_ACTION_UPDATE,
	LOG_ACTION_DELETE,
)

### Interlock
from core.views.mixins.ldap.domain import DomainViewMixin
import logging

### Others
from typing import overload
from core.utils import dnstool
import traceback
################################################################################

DBLogMixin = LogMixin()
logger = logging.getLogger(__name__)


class DNSRecordMixin(DomainViewMixin):
	ldap_connection = None

	@staticmethod
	def record_data_keys_are_valid(
		record_data: dict,
		required_keys: list[str] | tuple[str] | set[str],
		raise_exception=False,
	):
		"""Verifies exact key matches for record_data dictionary.
		
		De-duplicates keys with usage of set().

		Args:
			record_data (dict): Record data dictionary.
			required_keys (list[str] | tuple[str]): Required keys in dictionary
			raise_exception (bool, optional): Raise exc. on failure. Defaults to False.

		Raises:
			exc_dns.DNSRecordDataMissing: Raised when a key is missing.
			exc_dns.DNSRecordDataMalformed: Raised when an unknown key is present.

		Returns:
			bool
		"""
		if not isinstance(required_keys, (list, tuple, set)):
			raise TypeError("required_keys must be of type list, tuple, or set.")
		if not isinstance(required_keys, set):
			required_keys = set(required_keys)

		for _key in required_keys:
			if _key not in record_data:
				if raise_exception:
					logger.error(f"Record Attribute Failed Validation ({_key})")
					raise exc_dns.DNSRecordDataMissing(
						data={"detail": f"A required attribute is missing ({_key})"}
					)
				else:
					return False

		if required_keys != set(record_data.keys()):
			if raise_exception:
				logger.error(f"Record Data Keys Failed Validation.")
				raise exc_dns.DNSRecordDataMalformed(
					data={"detail": f"Unknown attribute received in record data."}
				)
			else:
				return False
		return True


	def validate_record_data(self, record_data: dict, add_required_keys: list=None):
		"""Validates Request LDAP DNS Record Data Dictionary

		name, type, zone, ttl are always required in data dictionary.

		For other fields check the RECORD_MAPPINGS constant in
		core.models.structs.ldap_dns_record

		Args:
			record_data (dict): DNS	Data Dictionary
			add_required_keys (list, optional): Additional values to require.
				Defaults to None.

		Raises:
			exc_dns.DNSRecordTypeMissing: When record type int is not in record data or
				not a supported type.
			exc_dns.DNSRootServersOnlyCLI: When Root DNS Server data modification is
				attempted, deny.
			exc_dns.SOARecordRootOnly: When a SOA Record with a non root (@) zone is used.
			exc_dns.DNSStringDataLimit: When stringData is over 255 char. length
			exc_dns.DNSZoneNotInRequest: When DNS Zone is not in requested record.
			exc_dns.DNSRecordDataMissing: When an attribute for the record type
				is missing from the data dict.

		Returns:
			bool: If the record data is valid
		"""
		required_keys = ["name", "type", "zone", "ttl"]
		# Type checking
		if "type" not in record_data:
			raise exc_dns.DNSRecordTypeMissing
		try:
			RecordTypes(record_data["type"])
		except:
			raise exc_dns.DNSRecordTypeUnsupported

		# Add the necessary fields for this Record Type to Required Fields
		if add_required_keys is not None and not isinstance(add_required_keys, (list, tuple)):
			raise TypeError("required_values must be a list or tuple.")
		if add_required_keys:
			required_keys.extend(add_required_keys)
		required_keys.extend(RECORD_MAPPINGS[record_data["type"]]["fields"])

		# tuple looping is faster than lists
		required_keys = tuple(set(required_keys))

		# Validate Keys
		self.record_data_keys_are_valid(
			record_data=record_data,
			required_keys=required_keys,
			raise_exception=True,
		)

		# Check that it's not modifying Root DNS Server data
		if "root dns servers" in record_data["zone"].lower():
			raise exc_dns.DNSRootServersOnlyCLI

		if (
			record_data["type"] == RecordTypes.DNS_RECORD_TYPE_SOA.value
			and record_data["name"] != "@"
		):
			raise exc_dns.SOARecordRootOnly

		# Explicit Exceptions
		if "stringData" in record_data and isinstance(record_data["stringData"], str):
			if len(record_data["stringData"]) >= 255:
				raise exc_dns.DNSStringDataLimit

		if "nameNode" in record_data:
			_name = record_data["name"]
			_zone = record_data["zone"]
			label = str(record_data["nameNode"])

			# Check that cname does not reference itself
			if _zone in label:
				_check_self_ref = f"{_name}.{_zone}"
				if label == _check_self_ref or label == f"{_check_self_ref}.":
					logger.error("Record Self-reference error detected.")
					raise exc_dns.DNSRecordTypeConflict

		# Generic Validation Exceptions
		# For each field in the Record Value Dictionary
		for f_key, f_value in record_data.items():
			if f_key in DNS_FIELD_VALIDATORS:
				self.validate_field(field_name=f_key, field_value=f_value)
			else:
				logger.warning(f"LDAP DNS Record field {f_key} has no assigned validator.")
		return True

	@overload
	def validate_field(
		self,
		field_name: str,
		field_value,
		raise_exception=True
	) -> bool | Exception:
		...

	def validate_field(
		self,
		field_name: str,
		field_value,
		raise_exception=True,
		_validator=None,
	) -> bool | Exception:
		"""DNS Field Validation Function

		Args:
			validator (str): Validator function to use
			field_name (str): Field to validate
			field_value (Any): Value to validate
			raise_exception (bool, optional): Whether to raise exception on False return.
				Defaults to True.

		Raises:
			exc_dns.DNSFieldValidatorFailed: Raised when raise_exception is True

		Returns:
			bool: Validation result.
		"""
		# Ensure it isn't recursing infinitely
		if isinstance(_validator, (tuple, list, set)):
			raise ValueError("validate_field recursion depth exceeded.")

		if not _validator:
			_validator = DNS_FIELD_VALIDATORS[field_name]
		if isinstance(_validator, (tuple, list, set)):
			return all(
				self.validate_field(
					field_name=field_name,
					field_value=field_value,
					raise_exception=raise_exception,
					_validator=_validator
				) for _validator in _validator
			)
		elif not isinstance(_validator, str) and not callable(_validator):
			raise TypeError("validator must be of type str, Iterable, or callable function.")

		is_valid = False
		if isinstance(_validator, str):
			is_valid = getattr(dnsValidators, _validator)(field_value)
		elif callable(_validator):
			is_valid = _validator(field_value)

		if not is_valid:
			if raise_exception:
				raise exc_dns.DNSFieldValidatorFailed(data={
					"field": field_name,
					"value": field_value,
				})
			else:
				return False
		return True

	def create_record(self, record_data):
		record_name: str = record_data["name"].lower()
		record_type: int = record_data["type"]
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
		record_name = record_data["name"].lower()
		record_type = record_data["type"]
		record_zone = record_data["zone"].lower()
		old_record_name = old_record_data["name"].lower()
		old_record_type = old_record_data["type"]
		old_record_zone = old_record_data["zone"].lower()
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
