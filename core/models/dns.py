################################################################################
#################### INTERLOCK IS LICENSED UNDER GNU AGPLv3 ####################
################## ORIGINAL PROJECT CREATED BY DYLAN BLANQUÉ ###################
########################## AND BR CONSULTING S.R.L. ############################
################################################################################
# Module: core.models.dns
# Contains the Models for DNS Zones and Records
#
# ---------------------------------- IMPORTS -----------------------------------#

### Exceptions
from core.exceptions import dns as exc_dns

### Models
from core.models.structs import ldap_dns_record as ldr
from core.models.structs.ldap_dns_record import (
	RECORD_MAPPINGS,
	RecordMapping,
	DNS_RECORD,
	DNS_RPC_RECORD_NAME_PREFERENCE,
	DNS_COUNT_NAME,
	DNS_RPC_NAME,
)
from core.models.types.ldap_dns_record import RecordTypes

### Interlock
from core.ldap.adsi import search_filter_add

### Utils
import traceback
from core.utils.dns import *
from core.utils import dnstool
from core.utils.dnstool import new_record, record_to_dict
from ldap3 import MODIFY_ADD, MODIFY_DELETE, MODIFY_INCREMENT, MODIFY_REPLACE, Connection
import logging
from typing import TypedDict
from datetime import datetime
from core.config.runtime import RuntimeSettings
################################################################################

DATE_FMT = "%Y%m%d"
logger = logging.getLogger(__name__)


class LDAPDNS:
	connection: Connection
	dnszones: list[str]
	forestzones: list[str]
	dnsroot: str
	forestroot: str

	def __init__(self, connection):
		if RuntimeSettings.LDAP_DNS_LEGACY:
			self.dnsroot = "CN=MicrosoftDNS,CN=System,%s" % RuntimeSettings.LDAP_AUTH_SEARCH_BASE
		else:
			self.dnsroot = (
				"CN=MicrosoftDNS,DC=DomainDnsZones,%s" % RuntimeSettings.LDAP_AUTH_SEARCH_BASE
			)

		self.forestroot = (
			"CN=MicrosoftDNS,DC=ForestDnsZones,%s" % RuntimeSettings.LDAP_AUTH_SEARCH_BASE
		)
		self.connection = connection
		self.list_dns_zones()
		self.list_forest_zones()

	def list_dns_zones(self):
		zones = dnstool.get_dns_zones(self.connection, self.dnsroot)
		self.dnszones = zones
		if len(zones) > 0:
			logger.debug("Found %d domain DNS zone(s):" % len(zones))
			for zone in zones:
				logger.debug("    %s" % zone)

	def list_forest_zones(self):
		zones = dnstool.get_dns_zones(self.connection, self.forestroot)
		self.forestzones = zones
		if len(zones) > 0:
			logger.debug("Found %d forest DNS zone(s):" % len(zones))
			for zone in zones:
				logger.debug("    %s" % zone)


class SerialGenerator:
	@staticmethod
	def serial_as_datetime(soa_serial: int) -> datetime:
		if not isinstance(soa_serial, int):
			raise TypeError("soa_serial must be an int")
		soa_serial = str(soa_serial)
		try:
			as_date = datetime.strptime(soa_serial[:8], DATE_FMT)
		except ValueError:
			return False
		return as_date

	@staticmethod
	def generate_epoch(serial: str | int, serial_date_obj: datetime) -> int:
		"""Generates EPOCH Formatted DNS SOA Serial

		Args:
			serial (str or int): Current Zone SOA Serial in EPOCH Format
			serial_date_obj (datetime): serial date as datetime

		Returns:
			int: A new serial
		"""
		if not isinstance(serial, int) and not isinstance(serial, str):
			raise TypeError("serial must be of type int or str.")
		if not isinstance(serial_date_obj, datetime):
			raise TypeError("serial_date_obj must be of type datetime.")
		serial_str = str(serial)
		date_changed = False
		if serial_date_obj.date() != datetime.today().date():
			serial_date_obj = datetime.now()
			serial_num = 0
			date_changed = True

		serial_date = serial_date_obj.strftime(DATE_FMT)
		# Get Counter from Epoch Serial
		if not date_changed:
			if len(serial_str) > 8:
				serial_num = int(serial_str[8:])
			# Restart counter if serial after datetime is invalid
			if len(serial_str) <= 8 or serial_num >= 99:
				serial_num = 0
		return int(f"{serial_date}{str(serial_num + 1).rjust(2, '0')}")


class LDAPRecordMixin:
	def get_soa_serial(self: "LDAPRecord") -> int:
		"""
		Gets the current Start of Authority Serial
		MUST RETURN AN INTEGER SERIAL
		"""
		self.get_soa()
		if self.soa["dwSerialNo"] != self.soa["serial"]:
			raise exc_dns.DNSRecordDataMalformed
		try:
			if "dwSerialNo" in self.soa:
				serial = int(self.soa["dwSerialNo"])
				# If serial epoch then sum 1 until last 2 digits are 99 #
				serial_date_obj = SerialGenerator.serial_as_datetime(serial)
				if isinstance(serial_date_obj, datetime):
					return SerialGenerator.generate_epoch(
						serial=serial, serial_date_obj=serial_date_obj
					)
				#########################################################
				return serial + 1
		except Exception as e:
			logger.exception(e)
			raise exc_dns.DNSCouldNotGetSOA

	def get_serial(self: "LDAPRecord", record_values, old_serial=None) -> int:
		try:
			if self.type == RecordTypes.DNS_RECORD_TYPE_SOA.value:
				return int(record_values["dwSerialNo"])
			if not "serial" in record_values:
				return self.get_soa_serial()

			serial = record_values["serial"]
			if serial == old_serial:
				return self.get_soa_serial()
			else:
				return serial
		except Exception as e:
			logger.exception(e)
			raise exc_dns.DNSCouldNotGetSerial

	def record_exists_in_entry(self: "LDAPRecord", main_field: str, main_field_val) -> bool:
		"""
		Checks if the record exists in the current LDAP Entry

		Args:
			main_field (str): The main value field for this record
			main_field_val: The main value for this record

		Returns:
			bool
		"""
		if not hasattr(self, "data"):
			return False
		if self.data:
			if len(self.data) > 0:
				for record in self.data:
					if main_field in record:
						if (
							record["name"] == self.name
							and record["type"] == self.type
							and record[main_field] == main_field_val
						):
							return True
		return False

	def record_of_type_exists(self: "LDAPRecord") -> bool:
		"""
		Checks if a record of this type exists in the LDAP Entry,
		if multi_record is not allowed for self.type

		Returns:
			bool
		"""
		multi_record = False
		if "multi_record" in self.mapping:
			multi_record = self.mapping["multi_record"]

		if not multi_record:
			if self.data:
				if len(self.data) > 0:
					for record in self.data:
						if record["type"] == self.type:
							return True
		return False

	def record_soa_exists(self: "LDAPRecord") -> bool:
		if self.data:
			if len(self.data) > 0:
				for record in self.data:
					if record["type"] == RecordTypes.DNS_RECORD_TYPE_SOA.value:
						return True
		return False

	def record_has_collision(self: "LDAPRecord", raise_exc=True) -> bool | Exception:
		"""
		Checks if a record of this type conflicts with another record type
		in this entry.

		Args:
			raise_exc (bool): Whether to raise an exception on collision.

		Raises Exception by default.

		Returns:
			bool | Exception
		"""
		if self.data:
			if len(self.data) > 0:
				exc = False
				msg = None
				for record in self.data:
					if (
						# If Any other type of Entry conflicts with CNAME
						(
							self.type == RecordTypes.DNS_RECORD_TYPE_CNAME.value
							and record["type"] != self.type
						)
						# A -> CNAME
						# AAAA -> CNAME
						or (
							self.type in [
								RecordTypes.DNS_RECORD_TYPE_A.value,
								RecordTypes.DNS_RECORD_TYPE_AAAA.value,
							]
							and record["type"] == RecordTypes.DNS_RECORD_TYPE_CNAME.value
						)
					):
						exc = True
						msg = (
							"A conflicting DNS Record %s was found for this %s Entry: \n -> %s"
							% (
								RECORD_MAPPINGS[record["type"]]["name"],
								self.mapping["name"],
								record,
							)
						)
				if exc and raise_exc:
					raise Exception(msg)
				elif exc:
					return True
		return False


class LDAPRecordRawAttributes(TypedDict):
	name: list[bytes] # The Record Name
	dNSTombstoned: list[bytes] # It's actually a list of string boolean as bytes
	dnsRecord: list[bytes] # DNS Record Struct

class LDAPRecordAttributes(TypedDict):
	name: list[str] # The Record Name
	dNSTombstoned: list[str] # It's actually a list of string boolean as bytes
	dnsRecord: list[bytes] # DNS Record Struct

class LDAPRecordEntry(TypedDict):
	# {
	# 	'raw_dn': b'DC=testblackhole,DC=brconsulting,CN=MicrosoftDNS,DC=DomainDnsZones,DC=brconsulting',
	# 	'dn': 'DC=testblackhole,DC=brconsulting,CN=MicrosoftDNS,DC=DomainDnsZones,DC=brconsulting',
	# 	'raw_attributes': {'name': [b'testblackhole'], 'dNSTombstoned': [b'FALSE'], 'dnsRecord': [b'\x04\x00\x01\x00\x05\xf0\x00\x00a\x8c\xb3x\x00\x00\x03\x84\x00\x00\x00\x00\x00\x00\x00\x00\x7f\x00\x00\x02']},
	#   'attributes': {'name': ['testblackhole'], 'dNSTombstoned': ['FALSE'], 'dnsRecord': [b'\x04\x00\x01\x00\x05\xf0\x00\x00a\x8c\xb3x\x00\x00\x03\x84\x00\x00\x00\x00\x00\x00\x00\x00\x7f\x00\x00\x02']},
	# 	'type': 'searchResEntry'
	# }
	raw_dn: bytes
	dn: str
	raw_attributes: LDAPRecordRawAttributes
	attributes: LDAPRecordAttributes
	type: str

class LDAPRecord(LDAPDNS, LDAPRecordMixin):
	rawEntry: LDAPRecordEntry
	data: dict
	name: str
	zone: str
	zoneType: str
	type: str
	mapping: RecordMapping
	structure: bytes
	DEFAULT_TTL = 900
	EXCLUDED_ENTRIES = ["ForestDnsZones", "DomainDnsZones"]

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

		self.schemaNamingContext = "%s,%s" % (
			RuntimeSettings.LDAP_SCHEMA_NAMING_CONTEXT,
			RuntimeSettings.LDAP_AUTH_SEARCH_BASE,
		)

		# Record Name Checks
		if rName is None:
			raise ValueError("Name cannot be none (LDAPRecord Object Class)")
		# Record Zone Checks
		if rZone is None:
			raise ValueError("Zone cannot be none (LDAPRecord Object Class)")
		# Record Type checks
		if rType is None:
			raise ValueError("Record Type cannot be none (LDAPRecord Object Class)")
		elif not isinstance(rType, int):
			raise TypeError("Record Type must be a valid Enum Integer")
		elif rType not in RECORD_MAPPINGS:
			raise TypeError("LDAPRecord type not found in Record Type Mappings.")
		# Zone Type Checks
		if zoneType != "fwdLookup":
			raise ValueError(
				"Reverse Lookup Entries are currently unsupported (LDAPRecord Object Class)"
			)

		self.rawEntry = None
		self.data = None
		self.name: str = rName
		self.zone: str = rZone
		self.zoneType = zoneType
		self.type = rType
		self.mapping: RecordMapping = RECORD_MAPPINGS[self.type]
		# Dynamically fetch the class based on the mapping
		if "class" in self.mapping:
			if not self.mapping["class"]:
				raise exc_dns.DNSRecordTypeUnsupported(
					data={
						"type_name": self.mapping["name"],
						"type_code": self.type,
						"name": self.name,
					}
				)
			if self.mapping["class"] == "DNS_RPC_RECORD_NODE_NAME":
				# If it's NODE_NAME create the record Data as DNS_COUNT_NAME
				self.record_cls = DNS_COUNT_NAME
			elif self.mapping["class"] == "DNS_RPC_RECORD_NAME_PREFERENCE":
				# If it's NODE_NAME create the record Data as DNS_COUNT_NAME
				self.record_cls = DNS_RPC_RECORD_NAME_PREFERENCE
			elif self.mapping["class"] == "DNS_RPC_RECORD_STRING":
				# If it's RECORD_STRING create the record Data as DNS_RPC_NAME
				self.record_cls = DNS_RPC_NAME
			else:
				# Standard Class Creation
				self.record_cls = getattr(ldr, self.mapping["class"])
		else:
			raise TypeError("Class key not in Record Mapping definition.")

		self.distinguishedName = f"DC={self.name},DC={self.zone},{self.dnsroot}"
		self.fetch()

	def __attributes__(self):
		# Exclude specific keys from self record attributes
		excluded_keys = ["rawEntry", "connection", "ldap_info"]
		return [v for v in self.__dict__.keys() if v not in excluded_keys]

	def __printAttributes__(self, print_raw_data=False):
		if print_raw_data == True:
			print(f"rawEntry: {self.rawEntry}")
		for a in self.__attributes__():
			print(f"{a}: {str(getattr(self, a))}")

	def __connection__(self):  # pragma: no cover
		return self.connection

	def __fullname__(self):
		if self.name == "@":
			return f"{self.zone} ({self.mapping['name']})"
		else:
			return f"{self.name}.{self.zone} ({self.mapping['name']})"

	def make_record_bytes(self, values: dict, serial: int | str, ttl: int = None) -> ldr.DNS_RECORD:
		"""Make record byte struct from values dictionary

		Args:
			values (dict): The values to convert to a byte struct
			serial (int | str): Current SOA Serial
			ttl (int, optional): Desired Record TTL. Defaults to None.

		Raises:
			exc_dns.DNSRecordTypeUnsupported: HTTP Response

		Returns:
			DNS_RECORD: DNS Record Struct
		"""
		if not ttl:
			ttl = self.DEFAULT_TTL
		## Check if class type is supported for creation ##
		if self.type in RECORD_MAPPINGS and RECORD_MAPPINGS[self.type]["class"]:
			record: DNS_RECORD = new_record(self.type, serial, ttl=ttl)
			# Dynamically fetch the class based on the mapping
			if self.mapping["class"]:
				record["Data"] = self.record_cls()

				# ! Print Chosen Class
				# print(self.mapping['class'])

				# ! DO NOT ADD wPreference here
				INT_FIELDS = [
					"dwSerialNo",
					"dwRefresh",
					"dwRetry",
					"dwExpire",
					"dwMinimumTtl",
					"wPriority",
					"wWeight",
					"wPort",
				]

				# Additional Operations based on special case type
				for field in self.mapping["fields"]:
					if (
						self.mapping["class"] == "DNS_RPC_RECORD_A"
						or self.mapping["class"] == "DNS_RPC_RECORD_AAAA"
					):
						record["Data"].fromCanonical(values[field])

					elif self.mapping["class"] == "DNS_RPC_RECORD_NODE_NAME":
						record["Data"].toCountName(values[field])

					elif self.mapping["class"] == "DNS_RPC_RECORD_STRING":
						if field == "stringData":
							record["Data"].toRPCName(values[field])

					elif self.mapping["class"] == "DNS_RPC_RECORD_NAME_PREFERENCE":
						if field == "wPreference":
							record["Data"].insert_field_to_struct(
								fieldName=field, fieldStructVal=">H"
							)
							record["Data"].setField(field, value=values[field])
						if field == "nameExchange":
							record["Data"].toCountName(values[field])

					elif self.mapping["class"] == "DNS_RPC_RECORD_SOA":
						if field in INT_FIELDS:
							record["Data"].setField(field, values[field])
						else:
							record["Data"][field] = record["Data"].addCountName(values[field])

					elif self.mapping["class"] == "DNS_RPC_RECORD_SRV":
						if field in INT_FIELDS:
							record["Data"].setField(field, values[field])
						else:
							record["Data"][field] = record["Data"].addCountName(values[field])
			return record
		else:
			raise exc_dns.DNSRecordTypeUnsupported(
				data={
					"type_name": self.mapping["name"],
					"type_code": self.type,
					"name": self.name,
				}
			)

	def get_soa_object(self):
		if self.type == RecordTypes.DNS_RECORD_TYPE_SOA.value:
			raise Exception("Unhandled SOA Recursion.")
		return LDAPRecord(
			connection=self.connection,
			rName="@",
			rZone=self.zone,
			rType=RecordTypes.DNS_RECORD_TYPE_SOA.value,
		)

	def get_soa(self):
		try:
			self.soa_object = self.get_soa_object()
		except:
			logger.error(traceback.format_exc())
			raise exc_dns.DNSCouldNotGetSOA
		for index, record in enumerate(self.soa_object.data):
			if record["type"] == RecordTypes.DNS_RECORD_TYPE_SOA.value:
				self.soa_bytes = self.soa_object.rawEntry["raw_attributes"]["dnsRecord"][index]
				self.soa = record

	def __soa__(self):
		return self.soa

	def create(self, values: dict, dry_run=False):
		"""
		Create a Record in the LDAP Entry identified by it's Bytes

		Args:
			values (dict): The values for the Record Creation

		Returns:
			self.connection.result
		"""
		if not values or not isinstance(values, dict):
			raise TypeError("values must be a dict.")

		if "ttl" not in values:
			values["ttl"] = self.DEFAULT_TTL

		self.serial = None
		try:
			self.serial = self.get_serial(record_values=values)
		except Exception as e:
			logger.exception(e)
			raise exc_dns.DNSCouldNotGetSerial

		try:
			self.structure = self.make_record_bytes(values, ttl=values["ttl"], serial=self.serial)
		except Exception as e:
			logger.exception(e)
			raise exc_dns.DNSRecordCreate

		# ! For debugging, do the decoding process to see if it's not a broken entry
		try:
			result = self.structure.getData()
		except Exception as e:
			logger.exception(e)
			raise exc_dns.DNSRecordCreate

		## Check if LDAP Entry Exists ##
		# LDAP Entry does not exist
		if not self.rawEntry:
			node_data = {
				"objectCategory": "CN=Dns-Node,%s" % self.schemaNamingContext,
				"dNSTombstoned": "FALSE",
				"name": self.name,
				"dnsRecord": [result],
			}
			try:
				if not dry_run:
					self.connection.add(self.distinguishedName, ["top", "dnsNode"], node_data)
			except Exception as e:
				logger.exception(e)
				try:
					logger.error(record_to_dict(dnstool.DNS_RECORD(result), ts=False))
				except: # pragma: no cover
					pass
				raise e

			# Log entry creation
			logger.info("Create Entry for %s" % (self.name))
			logger.debug(record_to_dict(dnstool.DNS_RECORD(result), ts=False))
		# LDAP entry exists
		else:
			# If it exists add the record to the entry after all the required checks
			if "main_field" in self.mapping:
				main_field = self.mapping["main_field"]
			else:
				main_field = self.mapping["fields"][0]

			# ! Check if record exists in LDAP Entry
			if self.record_exists_in_entry(
				main_field=main_field, main_field_val=values[main_field]
			):
				logger.error(
					f"{self.mapping['name']} Record already exists in an LDAP Entry (Conflicting value: {values[main_field]})"
				)
				try:
					logger.error(record_to_dict(dnstool.DNS_RECORD(self.structure.getData())))
				except: # pragma: no cover
					pass
				raise exc_dns.DNSRecordExistsConflict(
					data={
						"type_name": self.mapping["name"],
						"type_code": self.type,
						"name": self.name,
						"conflict_val": values[main_field],
						"conflict_field": main_field,
					}
				)

			# Check Multi-Record eligibility
			if self.record_of_type_exists():
				logger.error(
					f"{self.mapping['name']} Record already exists in an LDAP Entry (Conflicting value: {values[main_field]})"
				)
				try:
					logger.error(record_to_dict(dnstool.DNS_RECORD(self.structure.getData())))
				except: # pragma: no cover
					pass
				raise exc_dns.DNSRecordTypeConflict(
					data={
						"type_name": self.mapping["name"],
						"type_code": self.type,
						"name": self.name,
						"conflict_val": values[main_field],
						"conflict_field": main_field,
					}
				)

			# Check if a SOA Record already Exists
			if self.type == RecordTypes.DNS_RECORD_TYPE_SOA.value:
				if self.record_soa_exists():
					logger.error(
						f"{self.mapping['name']} Record already exists in an LDAP Entry and must be unique in Zone (Conflicting value: {values[main_field]})"
					)
					logger.error(record_to_dict(dnstool.DNS_RECORD(self.structure.getData())))
					raise exc_dns.DNSRecordExistsConflict(
						data={
							"type_name": self.mapping["name"],
							"type_code": self.type,
							"name": self.name,
							"conflict_val": values[main_field],
							"conflict_field": main_field,
						}
					)

			# Check for record type conflicts in Entry
			try:
				self.record_has_collision()
			except Exception as e:
				logger.error(e)
				raise exc_dns.DNSRecordTypeConflict(
					data={
						"type_name": self.mapping["name"],
						"type_code": self.type,
						"name": self.name,
					}
				)

			# Logging entry modify
			logger.info("Adding Record to Entry with name %s" % (self.name))
			logger.debug(record_to_dict(dnstool.DNS_RECORD(result)))

			# If all checks passed
			if not dry_run:
				self.connection.modify(
					self.distinguishedName, {"dnsRecord": [(MODIFY_ADD, self.structure.getData())]}
				)
		return self.connection.result

	def fetch(self):
		if self.zone not in self.dnszones:
			logger.debug(self.dnszones)
			raise exc_dns.DNSZoneIsForeign(
				f"Target zone ({self.zone}) is not in the LDAP Server DNS List"
			)

		if self.name.endswith(self.zone) or self.zone in self.name:
			raise exc_dns.DNSZoneInRecord

		searchFilter = search_filter_add(
			"objectClass=dnsNode", f"distinguishedName={self.distinguishedName}"
		)
		attributes = ["dnsRecord", "dNSTombstoned", "name"]

		search_target = f"DC={self.zone},{self.dnsroot}"
		self.connection.search(
			search_base=search_target, search_filter=searchFilter, attributes=attributes
		)
		if len(self.connection.response) > 0:
			self.rawEntry = self.connection.response[0]
		else:
			return None

		result = []
		record_dict = {}

		if self.rawEntry["type"] == "searchResEntry":
			if self.rawEntry["dn"] == self.distinguishedName:
				logger.debug("searchResEntry Data exists")

			# Set Record Name
			record_name = self.rawEntry["raw_attributes"]["name"][0]
			record_name = str(record_name)[2:-1]
			logger.debug(f"{__name__} [DEBUG] - Record Name: {record_name}")

			# Set Record Data
			for record in self.rawEntry["raw_attributes"]["dnsRecord"]:
				dr = dnstool.DNS_RECORD(record)
				record_dict = record_to_dict(dr, self.rawEntry["attributes"]["dNSTombstoned"])
				record_dict["name"] = record_name
				record_dict["ttl"] = dr.__getTTL__()
				logger.debug(
					f"{__name__} [DEBUG] - Record: {record_name}, Starts With Underscore: {record_name.startswith('_')}, Exclude Entry: {record_name in self.EXCLUDED_ENTRIES}"
				)
				logger.debug(f"{__name__} [DEBUG] {dr}")
				if not record_name.startswith("_") and record_name not in self.EXCLUDED_ENTRIES:
					result.append(record_dict)

			if len(result) > 0:
				self.data = result
		return self.data

	def update(
		self,
		values: dict,
		old_record_values: dict,
		old_record_bytes: bytes,
	):
		"""
		Update a Record in the LDAP Entry identified by it's Bytes

		Args:
			values (dict): The values for the Record Update
			old_record_bytes (bytes): The bytes to identify the old Record Values

		Returns:
			self.connection.result
		"""
		old_record_name = old_record_values.pop("name").lower()

		if (
			self.rawEntry is None
			or old_record_bytes not in self.rawEntry["raw_attributes"]["dnsRecord"]
		):
			raise exc_dns.DNSRecordEntryDoesNotExist

		if "main_field" in self.mapping:
			main_field = self.mapping["main_field"]
		else:
			main_field = self.mapping["fields"][0]

		self.serial = None
		try:
			self.serial = self.get_serial(values, old_serial=old_record_values["serial"])
		except:
			logger.error(traceback.format_exc())
			raise exc_dns.DNSCouldNotGetSerial

		self.structure = self.make_record_bytes(values, ttl=values["ttl"], serial=self.serial)

		# ! Check if the record with the new values exists, if true raise exception
		# Exclude SOA from condition as that record is unique in Zone.
		if self.type != RecordTypes.DNS_RECORD_TYPE_SOA.value:
			# ! Check if record exists in Entry
			exists = self.record_exists_in_entry(
				main_field=main_field, main_field_val=values[main_field]
			)
			if exists != False and old_record_name != self.name:
				logger.error(
					f"{self.mapping['name']} Record already exists in an LDAP Entry (Conflicting value: {values[main_field]})"
				)
				data = {
					"type_name": self.mapping["name"],
					"type_code": self.type,
					"name": self.name,
					"conflict_val": values[main_field],
					"conflict_field": main_field,
				}
				raise exc_dns.DNSRecordTypeConflict(data=data)
			# Check Multi-Record eligibility
			if (
				self.record_of_type_exists() == True
				and self.rawEntry["raw_attributes"]["dnsRecord"][0] != old_record_bytes
			):
				logger.error(
					f"{self.mapping['name']} Record already exists in an LDAP Entry (Conflicting value: {values[main_field]})"
				)
				logger.error(record_to_dict(dnstool.DNS_RECORD(self.structure.getData())))
				data = {
					"type_name": self.mapping["name"],
					"type_code": self.type,
					"name": self.name,
					"conflict_val": values[main_field],
					"conflict_field": main_field,
				}
				raise exc_dns.DNSRecordExistsConflict(data=data)

		newRecord = self.structure.getData()

		# Check for record type conflicts in Entry
		try:
			self.record_has_collision()
		except Exception as e:
			logger.error(e)
			raise exc_dns.DNSRecordTypeConflict

		# All checks passed
		## Delete Old Record
		self.connection.modify(
			self.distinguishedName, {"dnsRecord": [(MODIFY_DELETE, old_record_bytes)]}
		)
		## Add new DNS Record
		self.connection.modify(self.distinguishedName, {"dnsRecord": [(MODIFY_ADD, newRecord)]})
		return self.connection.result

	def delete(self, record_bytes):
		"""
		Delete a Record in the LDAP Entry identified by it's Bytes

		Args:
			record_bytes (bytes): Record Byte Struct

		Returns:
			self.connection.result
		"""
		# Check if Record exists in Entry
		if (
			self.rawEntry is None
			or record_bytes not in self.rawEntry["raw_attributes"]["dnsRecord"]
		):
			raise exc_dns.DNSRecordEntryDoesNotExist

		# Check if Entry has more than one Record
		# More than one record -> Delete Record Byte Data
		if len(self.rawEntry["raw_attributes"]["dnsRecord"]) >= 2:
			try:
				self.connection.modify(
					self.distinguishedName, {"dnsRecord": [(MODIFY_DELETE, record_bytes)]}
				)
			except Exception as e:
				logger.error(e)
				raise e
		else:
			try:
				self.connection.delete(self.distinguishedName)
			except Exception as e:
				logger.error(e)
				logger.error(record_to_dict(dnstool.DNS_RECORD(record_bytes)))
				raise e
		# Only record in Entry -> Delete entire Entry
		return self.connection.result
