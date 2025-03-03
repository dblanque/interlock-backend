################################################################################
#################### INTERLOCK IS LICENSED UNDER GNU AGPLv3 ####################
################## ORIGINAL PROJECT CREATED BY DYLAN BLANQUÉ ###################
########################## AND BR CONSULTING S.R.L. ############################
################################################################################
# Module: core.views.mixins.record
# Contains the Mixin for DNS Record related operations

#---------------------------------- IMPORTS -----------------------------------#
### Exceptions
from core.exceptions import (
	base as exc_base,
	ldap as exc_ldap,
	dns as exc_dns
)

### Models
from core.views.mixins.logs import LogMixin
from core.models.dns import LDAPRecord
from core.models.types.ldap_dns_record import *
from core.models.structs.ldap_dns_record import RECORD_MAPPINGS
from core.models.validators.ldap_dns_record import FIELD_VALIDATORS as DNS_FIELD_VALIDATORS
from core.models.validators import ldap_dns_record as dnsValidators

### Mixins
from core.views.mixins.utils import convert_string_to_bytes

### Interlock
from core.models.ldap_settings_runtime import RunningSettings
from core.views.mixins.domain import DomainViewMixin
import logging

### Others
from core.utils import dnstool
import traceback
from ldap3 import (
	MODIFY_ADD,
	MODIFY_DELETE,
	MODIFY_INCREMENT,
	MODIFY_REPLACE
)
################################################################################

DBLogMixin = LogMixin()
logger = logging.getLogger(__name__)

class DNSRecordMixin(DomainViewMixin):
	ldap_connection = None

	def validate_record_data(self, record_data, required_values=None):
		if required_values is None:
			required_values = []
		if 'type' not in record_data:
			raise exc_dns.DNSRecordTypeMissing

		if record_data['zone'] == 'Root DNS Servers':
			raise exc_dns.DNSRootServersOnlyCLI

		if record_data['type'] == DNS_RECORD_TYPE_SOA and record_data['name'] != "@":
			raise exc_dns.SOARecordRootOnly

		if 'stringData' in record_data:
			if len(record_data['stringData']) > 255:
				raise exc_dns.DNSStringDataLimit

		if 'nameNode' in record_data:
			label = str(record_data['nameNode'])
			split_labels = label.split('.')
			if len(split_labels[-1]) > 1:
				raise exc_dns.DNSRecordTypeConflict
			# Validate Zone in Record
			if not dnsValidators.canonicalHostname_validator(label):
				logger.error("Canonical Zone not in Request or invalid: "+label)
				raise exc_dns.DNSZoneNotInRequest

		if len(required_values) > 1:
			# Add the necessary fields for this Record Type to Required Fields
			required_values.extend(RECORD_MAPPINGS[record_data['type']]['fields'])

			for a in required_values:
				if a not in record_data:
					exception = exc_dns.DNSRecordDataMissing
					logger.error(f"Record Attribute Failed Validation ({a})")
					data = {
						"code": exception.default_code,
						"attribute": a,
					}
					exception.set_detail(exception, data)
					raise exception

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

	def create_record(self, record_data):
		record_name = record_data.pop('name').lower()
		record_type = record_data.pop('type')
		record_zone = record_data.pop('zone').lower()

		if 'serial' in record_data and isinstance(record_data['serial'], str):
			record_data.pop('serial')

		dnsRecord = LDAPRecord(
			connection=self.ldap_connection,
			rName=record_name,
			rZone=record_zone,
			rType=record_type
		)

		dnsRecord.create(values=record_data)

		#########################################
		# Update Start of Authority Record Serial
		if record_type != DNS_RECORD_TYPE_SOA:
			try:
				self.increment_soa_serial(dnsRecord.soa_object, dnsRecord.serial)
			except:
				logger.error(traceback.format_exc())
				raise exc_dns.DNSCouldNotIncrementSOA

		result = dnsRecord.structure.getData()
		dr = dnstool.DNS_RECORD(result)

		if RunningSettings.LDAP_LOG_CREATE == True:
			# Log this action to DB
			DBLogMixin.log(
				user_id=self.request.user.id,
				actionType="CREATE",
				objectClass="DNSR",
				affectedObject=dnsRecord.__fullname__()
			)
		return dr

	def update_record(self, record_data, old_record_data):
		old_record_name = old_record_data['name'].lower()
		record_name = record_data.pop('name').lower()
		record_type = record_data.pop('type')
		record_zone = record_data.pop('zone').lower()
		record_index = record_data.pop('index')
		record_bytes = record_data.pop('record_bytes')
		record_bytes = convert_string_to_bytes(record_bytes)

		if (isinstance(record_data['serial'], str) or record_data['serial'] == old_record_data['serial']):
			record_data.pop('serial')

		dnsRecord = LDAPRecord(
			connection=self.ldap_connection,
			rName=record_name,
			rZone=record_zone,
			rType=record_type
		)
		# ! If Record Name is being changed create the new one and delete the old.
		if old_record_name != record_name:
			# Create new Record
			result = dnsRecord.create(values=record_data)
			if result['result'] == 0:
				# Delete old DNSR after new one is created
				dnsRecord.connection.modify(old_record_data['distinguishedName'], {'dnsRecord': [( MODIFY_DELETE, record_bytes )]})
			else:
				raise exc_base.CoreException
		else:
			result = dnsRecord.update(
				values=record_data,
				old_record_values=old_record_data,
				old_record_bytes=record_bytes
			)

		#########################################
		# Update Start of Authority Record Serial
		if record_type != DNS_RECORD_TYPE_SOA:
			try:
				self.increment_soa_serial(dnsRecord.soa_object, dnsRecord.serial)
			except:
				logger.error(traceback.format_exc())
				raise exc_dns.DNSCouldNotIncrementSOA

		result = dnsRecord.structure.getData()
		dr = dnstool.DNS_RECORD(result)

		if RunningSettings.LDAP_LOG_UPDATE == True:
			# Log this action to DB
			DBLogMixin.log(
				user_id=self.request.user.id,
				actionType="UPDATE",
				objectClass="DNSR",
				affectedObject=dnsRecord.__fullname__()
			)
		return dr

	def delete_record(self, record_data, user):
		if not self.ldap_connection: raise exc_ldap.LDAPConnectionNotOpen

		record_name = record_data.pop('name')
		record_type = record_data.pop('type')
		record_zone = record_data.pop('zone')
		record_index = record_data.pop('index')
		record_bytes = record_data.pop('record_bytes')
		record_bytes = convert_string_to_bytes(record_bytes)

		dnsRecord = LDAPRecord(
			connection=self.ldap_connection,
			rName=record_name,
			rZone=record_zone,
			rType=record_type
		)

		try:
			result = dnsRecord.delete(record_bytes=record_bytes)
		except Exception as e:
			self.ldap_connection.unbind()
			raise e

		if RunningSettings.LDAP_LOG_DELETE == True:
			# Log this action to DB
			DBLogMixin.log(
				user_id=user.id,
				actionType="DELETE",
				objectClass="DNSR",
				affectedObject=dnsRecord.__fullname__()
			)

		return result