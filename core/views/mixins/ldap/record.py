################################################################################
#################### INTERLOCK IS LICENSED UNDER GNU AGPLv3 ####################
################## ORIGINAL PROJECT CREATED BY DYLAN BLANQUÉ ###################
########################## AND BR CONSULTING S.R.L. ############################
################################################################################
# Module: core.views.mixins.record
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
from core.utils import dnstool
import traceback
################################################################################

DBLogMixin = LogMixin()
logger = logging.getLogger(__name__)


class DNSRecordMixin(DomainViewMixin):
	ldap_connection = None

	def validate_record_data(self, record_data, required_values=None):
		if required_values is None:
			required_values = []
		if "type" not in record_data:
			raise exc_dns.DNSRecordTypeMissing

		if record_data["zone"] == "Root DNS Servers":
			raise exc_dns.DNSRootServersOnlyCLI

		if (
			record_data["type"] == RecordTypes.DNS_RECORD_TYPE_SOA.value
			and record_data["name"] != "@"
		):
			raise exc_dns.SOARecordRootOnly

		if "stringData" in record_data:
			if len(record_data["stringData"]) > 255:
				raise exc_dns.DNSStringDataLimit

		if "nameNode" in record_data:
			label = str(record_data["nameNode"])
			split_labels = label.split(".")
			if len(split_labels[-1]) > 1:
				raise exc_dns.DNSRecordTypeConflict
			# Validate Zone in Record
			if not dnsValidators.canonicalHostname_validator(label):
				logger.error("Canonical Zone not in Request or invalid: " + label)
				raise exc_dns.DNSZoneNotInRequest

		if len(required_values) > 1:
			# Add the necessary fields for this Record Type to Required Fields
			required_values.extend(RECORD_MAPPINGS[record_data["type"]]["fields"])

			for a in required_values:
				if a not in record_data:
					logger.error(f"Record Attribute Failed Validation ({a})")
					raise exc_dns.DNSRecordDataMissing(
						data={
							"detail": f"A required attribute is missing ({a})",
						}
					)

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
									except_on_fail=False,
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
								validator=validator, field_name=f_key, field_value=f_value
							)
						except Exception as e:
							logger.error(f"Validator: '{validator}' ({type(validator)})")
							logger.error(f"Field Name: '{f_key}' ({type(f_key)})")
							logger.error(f"Field Value: '{f_value}' ({type(f_value)})")
							logger.error(e)
							raise exc_dns.DNSFieldValidatorException

					if not valid:
						data = {"field": f_key, "value": f_value}
						raise exc_dns.DNSFieldValidatorFailed(data)
		return True

	def validate_field(
		self,
		validator: str,
		field_name: str,
		field_value,
		except_on_fail=True,
	):
		"""DNS Validator Function
		* self
		* validator: Validator Type for Value
		* field_name: DNS Record Field Name (e.g.: address, ttl, etc.)
		* field_value: DNS Record Field Value
		* except_on_fail: Raise exception on failure
		"""
		valid = getattr(dnsValidators, validator)(field_value)
		if not valid and except_on_fail:
			data = {"field": field_name, "value": field_value}
			raise exc_dns.DNSFieldValidatorFailed(data=data)
		elif not valid:
			return False
		return True

	def create_record(self, record_data):
		record_name = record_data["name"].lower()
		record_type = record_data["type"]
		record_zone = record_data["zone"].lower()

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
			user_id=self.request.user.id,
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
			user_id=self.request.user.id,
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
		record_data.pop("index")

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
			self.ldap_connection.unbind()
			raise e

		DBLogMixin.log(
			user_id=self.request.user.id,
			operation_type=LOG_ACTION_DELETE,
			log_target_class=LOG_CLASS_DNSR,
			log_target=dnsRecord.__fullname__(),
		)

		return result
