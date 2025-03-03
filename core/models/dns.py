################################################################################
#################### INTERLOCK IS LICENSED UNDER GNU AGPLv3 ####################
################## ORIGINAL PROJECT CREATED BY DYLAN BLANQUÉ ###################
########################## AND BR CONSULTING S.R.L. ############################
################################################################################
# Module: core.models.dns
# Contains the Models for DNS Zones and Records
#
#---------------------------------- IMPORTS -----------------------------------#

### Exceptions
from core.exceptions import dns as exc_dns

### Models
from core.models.structs.ldap_dns_record import *

### Interlock
from interlock_backend.ldap.adsi import search_filter_add

### Utils
import traceback
from core.utils.dns import *
from core.utils import dnstool
from core.utils.dnstool import (
	new_record,
	record_to_dict
)
from ldap3 import (
	MODIFY_ADD,
	MODIFY_DELETE,
	MODIFY_INCREMENT,
	MODIFY_REPLACE
)
import logging
import re
from datetime import datetime
from core.models.ldap_settings_runtime import RunningSettings
################################################################################

DATE_FMT = "%Y%m%d"
logger = logging.getLogger(__name__)
class LDAPDNS():
	def __init__(self, connection):
		legacy = RunningSettings.LDAP_DNS_LEGACY
		if legacy == True:
			self.dnsroot = 'CN=MicrosoftDNS,CN=System,%s' % RunningSettings.LDAP_AUTH_SEARCH_BASE
		else:
			self.dnsroot = 'CN=MicrosoftDNS,DC=DomainDnsZones,%s' % RunningSettings.LDAP_AUTH_SEARCH_BASE
		
		self.forestroot = 'CN=MicrosoftDNS,DC=ForestDnsZones,%s' % RunningSettings.LDAP_AUTH_SEARCH_BASE  
		self.connection = connection
		self.list_dns_zones()
		self.list_forest_zones()

	def list_dns_zones(self):
		zones = dnstool.get_dns_zones(self.connection, self.dnsroot)
		self.dnszones = zones
		if len(zones) > 0:
			logger.debug('Found %d domain DNS zone(s):' % len(zones))
			for zone in zones:
				logger.debug('    %s' % zone)

	def list_forest_zones(self):
		zones = dnstool.get_dns_zones(self.connection, self.forestroot)
		self.forestzones = zones
		if len(zones) > 0:
			logger.debug('Found %d forest DNS zone(s):' % len(zones))
			for zone in zones:
				logger.debug('    %s' % zone)

class LDAPRecord(LDAPDNS):

	def __init__(
		self, 
		connection, 
		legacy=False,
		rName=None,
		rZone=None,
		rType=None,
		zoneType="fwdLookup",
	):
		super().__init__(connection=connection)

		self.schemaNamingContext = "%s,%s" % (RunningSettings.LDAP_SCHEMA_NAMING_CONTEXT, RunningSettings.LDAP_AUTH_SEARCH_BASE)

		if rName is None:
			raise ValueError("Name cannot be none (LDAPRecord Object Class)")
		if rZone is None:
			raise ValueError("Zone cannot be none (LDAPRecord Object Class)")
		if rType is None:
			raise ValueError("Record Type cannot be none (LDAPRecord Object Class)")
		if zoneType != 'fwdLookup':
			raise ValueError("Reverse Lookup Entries are unsupported (LDAPRecord Object Class)")

		self.rawEntry = None
		self.data = None
		self.name = rName
		self.zone = rZone
		self.zoneType = zoneType
		self.type = rType
		self.distinguishedName = f"DC={self.name},DC={self.zone},{self.dnsroot}"
		self.fetch()

	def fetch(self):
		if self.zone not in self.dnszones:
			logger.debug(self.dnszones)
			raise Exception(f"Target zone ({self.zone}) is not in the LDAP Server DNS List")

		if self.name.endswith(self.zone) or self.zone in self.name:
			raise exc_dns.DNSZoneInRecord

		searchFilter = search_filter_add("", "objectClass=dnsNode")
		searchFilter = search_filter_add(
			searchFilter,
			f"distinguishedName={self.distinguishedName}"
		)
		attributes=['dnsRecord','dNSTombstoned','name']

		search_target = f"DC={self.zone},{self.dnsroot}"
		self.connection.search(
			search_base=search_target,
			search_filter=searchFilter,
			attributes=attributes
		)
		if len(self.connection.response) > 0:
			self.rawEntry = self.connection.response[0]
		else: 
			return None

		excludeEntries = [
			'ForestDnsZones',
			'DomainDnsZones'
		]

		result = []
		record_dict = {}

		if self.rawEntry['type'] == 'searchResEntry':
			if self.rawEntry['dn'] == self.distinguishedName:
				logger.debug("searchResEntry Data exists")

			# Set Record Name
			record_name = self.rawEntry['raw_attributes']['name'][0]
			record_name = str(record_name)[2:-1]
			logger.debug(f'{__name__} [DEBUG] - Record Name: {record_name}')

			# Set Record Data
			for record in self.rawEntry['raw_attributes']['dnsRecord']:
				dr = dnstool.DNS_RECORD(record)
				record_dict = record_to_dict(dr, self.rawEntry['attributes']['dNSTombstoned'])
				record_dict['name'] = record_name
				record_dict['ttl'] = dr.__getTTL__()
				logger.debug(f'{__name__} [DEBUG] - Record: {record_name}, Starts With Underscore: {record_name.startswith("_")}, Exclude Entry: {record_name in excludeEntries}')
				logger.debug(f'{__name__} [DEBUG] {dr}')
				if (not record_name.startswith("_")
					and record_name not in excludeEntries):
					result.append(record_dict)

			if len(result) > 0:
				self.data = result
		return self.data

	def __attributes__(self):
		# Exclude specific keys from self record attributes
		excluded_keys = [
			'rawEntry',
			'connection',
			'ldap_info'
		]
		return [v for v in self.__dict__.keys() if v not in excluded_keys]

	def __printAttributes__(self, print_raw_data=False):
		if print_raw_data == True:
			print(f"rawEntry: {self.rawEntry}")
		for a in self.__attributes__():
			print(f"{a}: {str(getattr(self, a))}")

	def __connection__(self):
		return self.connection
	
	def __fullname__(self):		
		if self.name == "@":
			return f"{self.zone} ({RECORD_MAPPINGS[self.type]['name']})"
		else:
			return f"{self.name}.{self.zone} ({RECORD_MAPPINGS[self.type]['name']})"

	def make_record_bytes(self, values, serial, ttl=180):
		## Check if class type is supported for creation ##
		if (self.type in RECORD_MAPPINGS):
			record = new_record(self.type, serial, ttl=ttl)

			# Dynamically fetch the class based on the mapping
			if RECORD_MAPPINGS[self.type]['class'] != None:
				if RECORD_MAPPINGS[self.type]['class'] == "DNS_RPC_RECORD_NODE_NAME":
					# If it's NODE_NAME create the record Data as DNS_COUNT_NAME
					record['Data'] = DNS_COUNT_NAME()
				elif RECORD_MAPPINGS[self.type]['class'] == "DNS_RPC_RECORD_NAME_PREFERENCE":
					# If it's NODE_NAME create the record Data as DNS_COUNT_NAME
					record['Data'] = DNS_COUNT_NAME()
				elif RECORD_MAPPINGS[self.type]['class'] == "DNS_RPC_RECORD_STRING":
					# If it's RECORD_STRING create the record Data as DNS_RPC_NAME
					record['Data'] = DNS_RPC_NAME()
				else:
					# Standard Class Creation
					record['Data'] = getattr(dnstool, RECORD_MAPPINGS[self.type]['class'])()

				# ! Print Chosen Class
				# print(RECORD_MAPPINGS[self.type]['class'])

				numFields = [
					'dwSerialNo',
					'dwRefresh',
					'dwRetry',
					'dwExpire',
					'dwMinimumTtl',
					'wPriority',
					'wWeight',
					'wPort',
				]

				# Additional Operations based on special case type
				for field in RECORD_MAPPINGS[self.type]['fields']:
					if (
						RECORD_MAPPINGS[self.type]['class'] == "DNS_RPC_RECORD_A"
						or
						RECORD_MAPPINGS[self.type]['class'] == "DNS_RPC_RECORD_AAAA"
						):
						record['Data'].fromCanonical(values[field])

					if RECORD_MAPPINGS[self.type]['class'] == "DNS_RPC_RECORD_NODE_NAME":
						record['Data'].toCountName(values[field])

					if RECORD_MAPPINGS[self.type]['class'] == "DNS_RPC_RECORD_STRING":
						if field == 'stringData':
							record['Data'].toRPCName(values[field])

					if RECORD_MAPPINGS[self.type]['class'] == "DNS_RPC_RECORD_NAME_PREFERENCE":
						if field == 'wPreference':
							record['Data'].insert_field_to_struct(fieldName=field, fieldStructVal='>H')
							record['Data'].setField(field, value=values[field])
						if field == 'nameExchange':
							record['Data'].toCountName(values[field])
			
					if RECORD_MAPPINGS[self.type]['class'] == "DNS_RPC_RECORD_SOA":
						if field in numFields:
							record['Data'].setField(field, values[field])
						else:
							record['Data'][field] = record['Data'].addCountName(values[field])

					if RECORD_MAPPINGS[self.type]['class'] == "DNS_RPC_RECORD_SRV":
						if field in numFields:
							record['Data'].setField(field, values[field])
						else:
							record['Data'][field] = record['Data'].addCountName(values[field])
			return record
		else:
			self.connection.unbind()
			data = {
				"typeName": RECORD_MAPPINGS[self.type]['name'],
				"typeCode": self.type,
				"name": self.name,
			}
			raise exc_dns.DNSRecordTypeUnsupported(data=data)
   
	def get_soa(self):
		try:
			self.soa_object = LDAPRecord(
				connection=self.connection,
				rName='@',
				rZone=self.zone,
				rType=DNS_RECORD_TYPE_SOA
			)
		except:
			logger.error(traceback.format_exc())
			raise exc_dns.DNSCouldNotGetSOA
		for index, record in enumerate(self.soa_object.data):
			if record['type'] == DNS_RECORD_TYPE_SOA:
				self.soa_bytes = self.soa_object.rawEntry['raw_attributes']['dnsRecord'][index]
				self.soa = record

	def __soa__(self):
		return self.soa

	def serial_is_epoch_datetime(self, soa_serial: int) -> datetime:
		if not isinstance(soa_serial, int):
			raise TypeError('soa_serial must be an int')
		soa_serial = str(soa_serial)
		try:
			as_date = datetime.strptime(soa_serial[:8], DATE_FMT)
		except ValueError:
			return False
		return as_date

	def serial_is_epoch_regex(self, soa_serial: int):
		if not isinstance(soa_serial, int):
			raise TypeError('soa_serial must be an int')
		epoch_regex = r'^[0-9]{4}(0[0-9]|1[0-2])([0-2][0-9]|3[0-1])[0-9]{2}$'
		soa_serial = str(soa_serial)
		if re.match(epoch_regex, str(soa_serial)):
			return True
		return False

	def get_soa_serial(self) -> int:
		"""
		Gets the current Start of Authority Serial
		MUST RETURN AN INTEGER SERIAL
		"""
		self.get_soa()
		if self.soa['dwSerialNo'] != self.soa['serial']:
			raise exc_dns.DNSRecordDataMalformed
		if 'dwSerialNo' in self.soa:
			try:
				serial = int(self.soa['dwSerialNo'])
			except:
				try:
					return str(serial)
				except: raise
			# If serial epoch then sum 1 until last 2 digits are 99 #
			serial_date_obj = self.serial_is_epoch_datetime(serial)
			if serial_date_obj:
				date_changed = False
				if serial_date_obj.date() != datetime.today().date():
					serial_date_obj = datetime.now()
					serial_num = 0
					date_changed = True
				serial_date = serial_date_obj.strftime(DATE_FMT)
				# Get Counter from Epoch Serial
				if not date_changed:
					if len(str(serial)) > 8: serial_num = int(str(serial)[8:])
					# Restart counter if serial after datetime is invalid
					elif len(str(serial)) <= 8 or serial_num > 99: serial_num = 0
				return int(f"{serial_date}{str(serial_num+1).rjust(2, '0')}")
			#########################################################
			return serial + 1
		logger.error(traceback.format_exc())
		raise exc_dns.DNSCouldNotGetSOA

	def get_serial(self, record_values, old_serial=None):
		if self.type == DNS_RECORD_TYPE_SOA:
			return int(record_values['dwSerialNo'])
		serial = None
		if 'serial' in record_values: 
			serial = record_values['serial']
		if not serial or serial == old_serial: 
			return self.get_soa_serial()
		if serial:
			return serial
		logger.error(traceback.format_exc())
		raise exc_dns.DNSCouldNotGetSerial

	def create(self, values, debugMode=False):
		"""
		Create a Record in the LDAP Entry identified by it's Bytes

		Arguments
		- values (dict) | Contains the values for the Record to create

		Returns the connection result
		"""
		if 'ttl' not in values:
			values['ttl'] = 900

		self.serial = None
		try:
			self.serial = self.get_serial(record_values=values)
		except:
			logger.error(traceback.format_exc())
			raise exc_dns.DNSCouldNotGetSerial

		try:
			self.structure = self.make_record_bytes(values, ttl=values['ttl'], serial=self.serial)
		except:
			raise exc_dns.DNSRecordCreate

		# ! For debugging, do the decoding process to see if it's not a broken entry
		try:
			result = self.structure.getData()
		except:
			raise exc_dns.DNSRecordCreate

		## Check if LDAP Entry Exists ##
		# LDAP Entry does not exist
		if self.rawEntry is None:
			# If Entry does not exist create it with the record in it
			logger.info("Create Entry for %s" % (self.name))
			logger.debug(record_to_dict(dnstool.DNS_RECORD(result), ts=False))
			node_data = {
				'objectCategory': 'CN=Dns-Node,%s' % self.schemaNamingContext,
				'dNSTombstoned': 'FALSE',
				'name': self.name,
				'dnsRecord': [ result ]
			}
			try:
				if not debugMode:
					self.connection.add(self.distinguishedName, ['top', 'dnsNode'], node_data)
			except Exception as e:
				logger.error(e)
				logger.error(record_to_dict(dnstool.DNS_RECORD(result), ts=False))
				self.connection.unbind()
		# LDAP entry exists
		else:
			# If it exists add the record to the entry after all the required checks
			if 'mainField' in RECORD_MAPPINGS[self.type]:
				mainField = RECORD_MAPPINGS[self.type]['mainField']
			else:
				mainField = RECORD_MAPPINGS[self.type]['fields'][0]

			# ! Check if record exists in LDAP Entry
			exists = self.record_exists_in_entry(mainField=mainField, mainFieldValue=values[mainField])
			if exists != False:
				logger.error(f"{RECORD_MAPPINGS[self.type]['name']} Record already exists in an LDAP Entry (Conflicting value: {values[mainField]})")
				self.connection.unbind()
				data = {
					"typeName": RECORD_MAPPINGS[self.type]['name'],
					"typeCode": self.type,
					"name": self.name,
					"conflictValue": values[mainField],
					"conflictField": mainField
				}
				raise exc_dns.DNSRecordTypeConflict(data=data)

			# Check Multi-Record eligibility
			if self.record_of_type_exists() == True:
				logger.error(f"{RECORD_MAPPINGS[self.type]['name']} Record already exists in an LDAP Entry (Conflicting value: {values[mainField]})")
				logger.error(record_to_dict(dnstool.DNS_RECORD(self.structure.getData())))
				self.connection.unbind()
				data = {
					"typeName": RECORD_MAPPINGS[self.type]['name'],
					"typeCode": self.type,
					"name": self.name,
					"conflictValue": values[mainField],
					"conflictField": mainField
				}
				raise exc_dns.DNSRecordExistsConflict(data=data)

			# Check if a SOA Record already Exists
			if self.type == DNS_RECORD_TYPE_SOA:
				if self.record_soa_exists() == True:
					logger.error(f"{RECORD_MAPPINGS[self.type]['name']} Record already exists in an LDAP Entry and must be unique in Zone (Conflicting value: {values[mainField]})")
					logger.error(record_to_dict(dnstool.DNS_RECORD(self.structure.getData())))
					self.connection.unbind()
					data = {
						"typeName": RECORD_MAPPINGS[self.type]['name'],
						"typeCode": self.type,
						"name": self.name,
						"conflictValue": values[mainField],
						"conflictField": mainField
					}
					raise exc_dns.DNSRecordExistsConflict(data=data)

			# Check for record type conflicts in Entry
			try:
				self.record_has_collision()
			except Exception as e:
				logger.error(e)
				self.connection.unbind()
				data = {
					"typeName": RECORD_MAPPINGS[self.type]['name'],
					"typeCode": self.type,
					"name": self.name
				}
				raise exc_dns.DNSRecordTypeConflict(data=data)
			logger.info("Adding Record to Entry with name %s" % (self.name))
			logger.debug(record_to_dict(dnstool.DNS_RECORD(result), ts=False))

			# If all checks passed
			if not debugMode:
				self.connection.modify(self.distinguishedName, {'dnsRecord': [( MODIFY_ADD, self.structure.getData() )]})
		return self.connection.result

	def update(
			self, 
			values: dict,
			old_record_values: dict,
			old_record_bytes: bytes,
		):
		"""
		Update a Record in the LDAP Entry identified by it's Bytes

		Arguments
		- values (dict) | Contains the values for the Record to update
		- oldRecordBytes (bytes) | Contains the bytes to identify the Old Record

		Returns the connection result
		"""
		old_record_name = old_record_values.pop('name').lower()

		if self.rawEntry is None or old_record_bytes not in self.rawEntry['raw_attributes']['dnsRecord']:
			self.connection.unbind()
			raise exc_dns.DNSRecordEntryDoesNotExist

		if 'mainField' in RECORD_MAPPINGS[self.type]:
			mainField = RECORD_MAPPINGS[self.type]['mainField']
		else:
			mainField = RECORD_MAPPINGS[self.type]['fields'][0]

		self.serial = None
		try:
			self.serial = self.get_serial(values, old_serial=old_record_values['serial'])
		except:
			logger.error(traceback.format_exc())
			raise exc_dns.DNSCouldNotGetSerial

		self.structure = self.make_record_bytes(values, ttl=values['ttl'], serial=self.serial)

		# ! Check if the record with the new values exists, if true raise exception
		# Exclude SOA from condition as that record is unique in Zone.
		if self.type != DNS_RECORD_TYPE_SOA:
			# ! Check if record exists in Entry
			exists = self.record_exists_in_entry(mainField=mainField, mainFieldValue=values[mainField])
			if exists != False and old_record_name != self.name:
				logger.error(f"{RECORD_MAPPINGS[self.type]['name']} Record already exists in an LDAP Entry (Conflicting value: {values[mainField]})")
				self.connection.unbind()
				data = {
					"typeName": RECORD_MAPPINGS[self.type]['name'],
					"typeCode": self.type,
					"name": self.name,
					"conflictValue": values[mainField],
					"conflictField": mainField
				}
				raise exc_dns.DNSRecordTypeConflict(data=data)
			# Check Multi-Record eligibility
			if self.record_of_type_exists() == True and self.rawEntry['raw_attributes']['dnsRecord'][0] != old_record_bytes:
				logger.error(f"{RECORD_MAPPINGS[self.type]['name']} Record already exists in an LDAP Entry (Conflicting value: {values[mainField]})")
				logger.error(record_to_dict(dnstool.DNS_RECORD(self.structure.getData())))
				self.connection.unbind()
				data = {
					"typeName": RECORD_MAPPINGS[self.type]['name'],
					"typeCode": self.type,
					"name": self.name,
					"conflictValue": values[mainField],
					"conflictField": mainField
				}
				raise exc_dns.DNSRecordExistsConflict(data=data)

		newRecord = self.structure.getData()

		# Check for record type conflicts in Entry
		try:
			self.record_has_collision()
		except Exception as e:
			logger.error(e)
			self.connection.unbind()
			raise exc_dns.DNSRecordTypeConflict

		# All checks passed
		## Delete Old Record
		self.connection.modify(self.distinguishedName, {'dnsRecord': [( MODIFY_DELETE, old_record_bytes )]})
		## Add new DNS Record
		self.connection.modify(self.distinguishedName, {'dnsRecord': [( MODIFY_ADD, newRecord )]})
		return self.connection.result

	def delete(self, record_bytes):
		"""
		Delete a Record in the LDAP Entry identified by it's Bytes

		Arguments
		- record_bytes (bytes)

		Returns the connection result
		"""
		# Check if Record exists in Entry
		if self.rawEntry is None or record_bytes not in self.rawEntry['raw_attributes']['dnsRecord']:
			self.connection.unbind()
			raise exc_dns.DNSRecordEntryDoesNotExist

		# Check if Entry has more than one Record
		# More than one record -> Delete Record Byte Data
		if len(self.rawEntry['raw_attributes']['dnsRecord']) >= 2:
			try:
				self.connection.modify(self.distinguishedName, {'dnsRecord': [( MODIFY_DELETE, record_bytes )]})
			except Exception as e:
				logger.error(e)
				self.connection.unbind()
		else:
			try:
				self.connection.delete(self.distinguishedName)
			except Exception as e:
				logger.error(e)
				logger.error(record_to_dict(dnstool.DNS_RECORD(record_bytes)))
				self.connection.unbind()
		# Only record in Entry -> Delete entire Entry
		return self.connection.result

	def record_exists_in_entry(self, mainField, mainFieldValue):
		"""
		Checks if the record exists in the current LDAP Entry

		Arguments
		- mainField (string) | The main value field for this record
		- mainFieldValue | The main value for this record

		Returns Boolean [ True | False ]
		"""
		if self.data is not None:
			if len(self.data) > 0:
				for record in self.data:
					if mainField in record:
						if (record['name'] == self.name
						and record['type'] == self.type
						and record[mainField] == mainFieldValue):
							return True
		return False

	def record_of_type_exists(self):
		"""
		Checks if a record of this type exists in the LDAP Entry,
		if multiRecord is not allowed for self.type

		Returns Boolean [ True | False ]
		"""
		if 'multiRecord' in RECORD_MAPPINGS[self.type]:
			multiRecord = RECORD_MAPPINGS[self.type]['multiRecord']
		else:
			multiRecord = False

		if multiRecord != True:
			if self.data is not None:
				if len(self.data) > 0:
					for record in self.data:
						if record['type'] == self.type:
							return True
		return False

	def record_soa_exists(self):
		if self.data is not None:
			if len(self.data) > 0:
				for record in self.data:
					if record['type'] == DNS_RECORD_TYPE_SOA:
						return True
		return False

	def record_has_collision(self):
		"""
		Checks if a record of this type conflicts with another record type
		in this entry

		Returns Boolean [ True | False ]
		"""
		if self.data is not None:
			if len(self.data) > 0:
				exc = False
				msg = None
				for record in self.data:
					if (
						# If Any other type of Entry conflicts with CNAME
						(self.type == DNS_RECORD_TYPE_CNAME and record['type'] != DNS_RECORD_TYPE_CNAME)
						# A -> CNAME
						or
						(self.type == DNS_RECORD_TYPE_A and record['type'] == DNS_RECORD_TYPE_CNAME)
						# AAAA -> CNAME
						or
						(self.type == DNS_RECORD_TYPE_AAAA and record['type'] == DNS_RECORD_TYPE_CNAME)
						):
						exc = True
						msg = "A conflicting DNS Record %s was found for this %s Entry: \n -> %s" % \
						(RECORD_MAPPINGS[record['type']]['name'], RECORD_MAPPINGS[self.type]['name'], record)
				if exc == True:
					raise Exception(msg)
		return False
