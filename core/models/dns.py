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
from core.exceptions import (
	dns as exc_dns,
	base as exc_base,
)

### Models
from core.models.structs import ldap_dns_record as ldr
from core.models.structs.ldap_dns_record import (
	RECORD_MAPPINGS,
	RecordMapping,
	DNS_RECORD,
	DNS_RPC_RECORD_NAME_PREFERENCE,
	DNS_COUNT_NAME,
	DNS_RPC_NAME,
	RECORD_TYPE_ENUM_PREFIX,
)
from core.models.types.ldap_dns_record import RecordTypes

### Interlock
from core.ldap.adsi import search_filter_add

### Utils
import traceback
from core.utils.dns import *
from core.utils import dnstool
from core.utils.dnstool import new_record, record_to_dict
from ldap3 import MODIFY_ADD, MODIFY_DELETE, Connection
import logging
from typing import TypedDict, Iterable
from datetime import datetime
from core.config.runtime import RuntimeSettings
################################################################################

DATE_FMT = "%Y%m%d"
logger = logging.getLogger(__name__)


class LDAPDNS:
	connection: Connection
	dns_zones: list[str]
	forest_zones: list[str]
	dns_root: str
	forest_root: str

	def __init__(self, connection):
		if RuntimeSettings.LDAP_DNS_LEGACY:
			self.dns_root = "CN=MicrosoftDNS,CN=System,%s" % RuntimeSettings.LDAP_AUTH_SEARCH_BASE
		else:
			self.dns_root = (
				"CN=MicrosoftDNS,DC=DomainDnsZones,%s" % RuntimeSettings.LDAP_AUTH_SEARCH_BASE
			)

		self.forest_root = (
			"CN=MicrosoftDNS,DC=ForestDnsZones,%s" % RuntimeSettings.LDAP_AUTH_SEARCH_BASE
		)
		self.connection = connection
		self.list_dns_zones()
		self.list_forest_zones()

	def list_dns_zones(self):
		zones = dnstool.get_dns_zones(self.connection, self.dns_root)
		self.dns_zones = zones
		if len(zones) > 0:
			logger.debug("Found %d domain DNS zone(s):" % len(zones))
			for zone in zones:
				logger.debug("\t%s" % zone)

	def list_forest_zones(self):
		zones = dnstool.get_dns_zones(self.connection, self.forest_root)
		self.forest_zones = zones
		if len(zones) > 0:
			logger.debug("Found %d forest DNS zone(s):" % len(zones))
			for zone in zones:
				logger.debug("\t%s" % zone)


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
	def get_soa_entry(self: "LDAPRecord") -> "LDAPRecord":
		if self.type == RecordTypes.DNS_RECORD_TYPE_SOA.value:
			raise exc_base.CoreException("SOA Recursion Exception (get_soa_entry).")
		return LDAPRecord(
			connection=self.connection,
			record_name="@",
			record_zone=self.zone,
			record_type=RecordTypes.DNS_RECORD_TYPE_SOA.value,
		)

	def get_soa(self: "LDAPRecord") -> None:
		if self.type == RecordTypes.DNS_RECORD_TYPE_SOA.value:
			raise exc_base.CoreException("SOA Recursion Exception (get_soa).")

		try:
			self.soa_object = self.get_soa_entry()
		except:
			logger.error(traceback.format_exc())
			raise exc_dns.DNSCouldNotGetSOA
		for index, record in enumerate(self.soa_object.entry):
			if record["type"] == RecordTypes.DNS_RECORD_TYPE_SOA.value:
				self.soa_bytes = self.soa_object.raw_entry["raw_attributes"]["dnsRecord"][index]
				self.soa = record

	def get_soa_serial(self: "LDAPRecord") -> int:
		"""
		Gets the current Start of Authority Serial

		Returns:
			int
		"""
		if self.type == RecordTypes.DNS_RECORD_TYPE_SOA.value:
			raise exc_base.CoreException("SOA Recursion Exception (get_soa_serial).")

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
		except exc_dns.DNSCouldNotGetSOA:
			raise
		except Exception as e:
			logger.exception(e)
			raise exc_dns.DNSCouldNotGetSOA from e

	def get_serial(self: "LDAPRecord", record_values, old_serial=None) -> int:
		if self.type == RecordTypes.DNS_RECORD_TYPE_SOA.value:
			return int(record_values["dwSerialNo"])

		if not "serial" in record_values:
			return self.get_soa_serial()

		serial = record_values["serial"]
		if serial == old_serial:
			return self.get_soa_serial()
		else:
			return serial

	@property
	def multi_record(self: "LDAPRecord") -> bool:
		# Default: multi_record is disallowed
		multi_record = False

		# If mapped, use mapped value
		if "multi_record" in self.mapping:
			multi_record = self.mapping["multi_record"]

		return multi_record

	@property
	def main_field(self: "LDAPRecord") -> str:
		"""Get the main field for self.type record type

		Raises:
			Exception: Raises generic exception if no main_field key can be returned.

		Returns:
			str: Key to find the main value in structs/data/dicts
		"""
		try:
			if "main_field" in self.mapping:
				return self.mapping["main_field"]
			return self.mapping["fields"][0]
		except:
			raise Exception("LDAPRecord could not obtain a valid main_field key.")

	def record_in_entry(self: "LDAPRecord", values: dict = None) -> bool:
		"""
		Checks if the record exists in the current LDAP Entry.

		Args:
			values (dict): If passed will check against dict. Defaults to None.

		Returns:
			bool
		"""
		if values is not None and not isinstance(values, dict):
			raise TypeError("values must be a dictionary or None.")

		check_against = None
		if hasattr(self, "main_value"):
			check_against = self.main_value
		if values:
			if self.main_field in values:
				check_against = values[self.main_field]
		if not hasattr(self, "entry"):
			return False
		if self.entry:
			for record in self.entry:
				if self.main_field in record:
					if (
						record["name"] == self.name
						and record["type"] == self.type
						and record[self.main_field] == check_against
					):
						return True
		return False

	def validate_soa(self: "LDAPRecord") -> None:
		"""Validates SOA Record based on the following criteria:
			- Must be in the root of the zone
			- Must be unique

		Args:
			self (LDAPRecord)

		Returns:
			None
		"""
		if self.type != RecordTypes.DNS_RECORD_TYPE_SOA.value:
			raise exc_base.CoreException(
				data={"detail": "SOA Validation used in incorrect record type."}
			)
		if self.entry:
			for record in self.entry:
				if record["type"] == RecordTypes.DNS_RECORD_TYPE_SOA.value:
					logger.error(
						f"{self.mapping['name']} Record already exists in an LDAP Entry and must be unique in Zone."
					)
					try:
						logger.error(record_to_dict(dnstool.DNS_RECORD(self.structure.getData())))
					except:
						pass
					raise exc_dns.DNSRecordExistsConflict(
						data={
							"type_name": self.mapping["name"],
							"type_code": self.type,
							"name": self.name,
						}
					)
		raise exc_base.CoreException(data={"detail": "LDAPRecord has no entry attribute."})

	def _validate_create_update(self: "LDAPRecord", values: dict, create=True):
		"""Validates new record values.
		When creating it always checks for exact record existence.
		When updating it checks for exact record existence, except for cases where each
		record type is unique within each entry (CNAME, SOA, etc.)

		Args:
			values (dict): The new record values
			create (bool, optional): Whether to validate creation or update. Defaults to True.

		Raises:
			exc_dns.DNSRecordExistsConflict: When the record already exists
			exc_dns.DNSRecordTypeConflict: When the record conflicts with another type in the entry
		"""
		# All other types
		if self.multi_record or (not self.multi_record and create):
			if self.record_in_entry(values=values):
				logger.error(
					f"{self.mapping['name']} Record already exists in an LDAP Entry (Conflicting value: {values[self.main_field]})"
				)
				try:
					logger.error(record_to_dict(dnstool.DNS_RECORD(self.structure.getData())))
				except:
					pass
				raise exc_dns.DNSRecordExistsConflict(
					data={
						"type_name": self.mapping["name"],
						"type_code": self.type,
						"name": self.name,
						"conflict_val": values[self.main_field],
						"conflict_field": self.main_field,
					}
				)

		# Check for record type conflicts in Entry
		record_has_collision, record_error_msg = self.record_has_collision()
		if record_has_collision:
			logger.error(record_error_msg)
			raise exc_dns.DNSRecordTypeConflict

	def validate_create(self: "LDAPRecord", values: dict):
		# If SOA Type
		if self.type == RecordTypes.DNS_RECORD_TYPE_SOA.value:
			self.validate_soa()
			return
		# All other types
		self._validate_create_update(values=values)

	def validate_update(self: "LDAPRecord", new_values: dict):
		self._validate_create_update(values=new_values, create=False)

	def record_has_collision(self: "LDAPRecord") -> tuple[bool, str]:
		"""
		Checks if a record of this type conflicts with another record type
		in this entry.

		Args:
			raise_exc (bool): Whether to raise an exception on collision.

		Raises Exception by default.

		Returns:
			tuple(has_collision: bool, error_message: str)
		"""
		if self.entry:
			if len(self.entry) > 0:
				exc = False
				msg = None
				for record in self.entry:
					if (
						# If Any other type of Entry conflicts with CNAME
						(
							self.type == RecordTypes.DNS_RECORD_TYPE_CNAME.value
							and record["type"] != self.type
						)
						# A -> CNAME
						# AAAA -> CNAME
						or (
							self.type
							in [
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
				if exc:
					return True, msg
		return False, ""


class LDAPRecordRawAttributes(TypedDict):
	name: list[bytes]  # The Record Name
	dNSTombstoned: list[bytes]  # It's actually a list of string boolean as bytes
	dnsRecord: list[bytes]  # DNS Record Struct


class LDAPRecordAttributes(TypedDict):
	name: list[str]  # The Record Name
	dNSTombstoned: list[str]  # It's actually a list of string boolean as bytes
	dnsRecord: list[bytes]  # DNS Record Struct


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


def get_record_mapping_from_type(t: RecordTypes | int) -> RecordMapping:
	"""Gets the corresponding mapping for a record type.

	Args:
		t (RecordTypes): The record type to fetch the mapping for.

	Raises:
		ValueError: If t is None
		TypeError: If t is not a valid int
		TypeError: If t is not a valid RecordTypes Enum value.

	Returns:
		RecordMapping: A typed dictionary.
	"""
	if t is None:
		raise ValueError("Record Type cannot be none (LDAPRecord Object Class)")
	elif not isinstance(t, int):
		raise TypeError("Record Type must be a valid Enum Integer")
	elif t not in RECORD_MAPPINGS:
		raise TypeError("LDAPRecord type not found in Record Type Mappings.")
	return RECORD_MAPPINGS[t]


def record_type_main_field(t: RecordTypes | int | str) -> str:
	"""Gets the corresponding main field identifier for a record type.

	Args:
		t (RecordTypes | int | str): The record type to fetch the main field for.

	Returns:
		str: Key string for field
	"""
	if not isinstance(t, RecordTypes) and not isinstance(t, int) and not isinstance(t, str):
		raise TypeError(f"t must be a valid RecordType Enum, RecordType int, or string identifier.")
	if isinstance(t, str):
		t_str = t.upper()
		if not t_str.startswith(RECORD_TYPE_ENUM_PREFIX):
			t_str = (RECORD_TYPE_ENUM_PREFIX + t).upper()
		try:
			t = RecordTypes[t_str].value
		except:
			raise ValueError("Could not fetch RecordTypes value from string identifier.")
	elif isinstance(t, RecordTypes):
		t = t.value
	mapping = get_record_mapping_from_type(t)
	if "main_field" in mapping:
		return mapping["main_field"]
	return mapping["fields"][0]


class LDAPRecord(LDAPDNS, LDAPRecordMixin):
	raw_entry: LDAPRecordEntry
	entry: dict
	name: str
	main_value: str
	zone: str
	zone_type: str
	type: str
	mapping: RecordMapping
	structure: DNS_RECORD
	DEFAULT_TTL = 900
	EXCLUDED_ENTRIES = ["ForestDnsZones", "DomainDnsZones"]

	def __init__(
		self,
		connection,
		legacy=False,
		record_name: str = None,
		record_zone: str = None,
		record_type: RecordTypes = None,
		record_main_value=None,
		zone_type="fwdLookup",
		auto_fetch=True,
	):
		super().__init__(connection=connection)

		self.schema_naming_context = "%s,%s" % (
			RuntimeSettings.LDAP_SCHEMA_NAMING_CONTEXT,
			RuntimeSettings.LDAP_AUTH_SEARCH_BASE,
		)

		# Record Name Checks
		if record_name is None:
			raise ValueError("Name cannot be none (LDAPRecord Object Class)")
		# Record Zone Checks
		if record_zone is None:
			raise ValueError("Zone cannot be none (LDAPRecord Object Class)")
		# Record Type checks
		if record_type == RecordTypes.DNS_RECORD_TYPE_SOA.value:
			if record_name != "@":
				raise ValueError("Start of Authority must be in the root of the DNS Zone.")
		else:
			if record_main_value is None:
				raise ValueError("Main value is required for LDAPRecord initialization.")
		# Zone Type Checks
		if zone_type != "fwdLookup":
			raise ValueError(
				"Reverse Lookup Entries are currently unsupported (LDAPRecord Object Class)"
			)

		self.raw_entry = None
		self.entry = None
		self.name: str = record_name
		self.zone: str = record_zone
		self.zone_type = zone_type
		self.type = record_type
		self.mapping = get_record_mapping_from_type(record_type)
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

		if not isinstance(record_main_value, str) and isinstance(record_main_value, Iterable):
			logger.warning("record_main_value is an iterable, is this okay?")
		self.main_value = record_main_value
		self.distinguished_name = f"DC={self.name},DC={self.zone},{self.dns_root}"
		if auto_fetch:
			self.fetch()

	def __attributes__(self):
		# Exclude specific keys from self record attributes
		excluded_keys = ["raw_entry", "connection", "ldap_info"]
		return [v for v in self.__dict__.keys() if v not in excluded_keys]

	def __printAttributes__(self, print_raw_data=False):
		if print_raw_data == True:
			print(f"rawEntry: {self.raw_entry}")
		for a in self.__attributes__():
			print(f"{a}: {str(getattr(self, a))}")

	def __connection__(self):  # pragma: no cover
		return self.connection

	def __fullname__(self):
		if self.name == "@":
			return f"{self.zone} ({self.mapping['name']})"
		else:
			return f"{self.name}.{self.zone} ({self.mapping['name']})"

	def __soa__(self):
		return self.soa

	def get_record_index_from_entry(self):
		if self.type == RecordTypes.DNS_RECORD_TYPE_SOA.value:
			for index, record in enumerate(self.entry):
				if record["type"] == self.type:
					return index
		elif self.main_value:
			for index, record in enumerate(self.entry):
				if record["type"] == self.type and record[self.main_field] == self.main_value:
					return index
		else:
			raise ValueError("main_value must be defined in LDAPRecord call.")

	@property
	def data(self) -> dict:
		if not hasattr(self, "entry") or not self.entry:
			raise exc_dns.DNSRecordEntryDoesNotExist
		return self.entry[self.get_record_index_from_entry()]

	@property
	def as_dict(self) -> dict:
		return self.data

	@property
	def as_bytes(self) -> DNS_RECORD:
		"""Finds record in raw entry.

		Args:
			values (dict)

		Raises:
			exc_dns.DNSRecordEntryDoesNotExist: When the record doesn't exist in the entry.

		Returns:
			DNS_RECORD: record_bytes
		"""
		if not hasattr(self, "raw_entry") or not self.raw_entry:
			raise exc_dns.DNSRecordEntryDoesNotExist
		_raw_entry_records = self.raw_entry["raw_attributes"]["dnsRecord"]
		return _raw_entry_records[self.get_record_index_from_entry()]

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
		try:
			self.serial = self.get_serial(record_values=values)
		except Exception as e:
			raise exc_dns.DNSCouldNotGetSerial from e

		try:
			self.structure = self.make_record_bytes(values, ttl=values["ttl"], serial=self.serial)
		except Exception as e:
			logger.exception(e)
			raise exc_dns.DNSRecordCreate from e

		# ! For debugging, do the decoding process to see if it's not a broken entry
		try:
			result = self.structure.getData()
		except Exception as e:
			logger.exception(e)
			raise exc_dns.DNSRecordCreate from e

		## Check if LDAP Entry Exists ##
		# LDAP Entry does not exist
		if not self.raw_entry:
			node_data = {
				"objectCategory": "CN=Dns-Node,%s" % self.schema_naming_context,
				"dNSTombstoned": "FALSE",
				"name": self.name,
				"dnsRecord": [result],
			}
			try:
				if not dry_run:
					self.connection.add(self.distinguished_name, ["top", "dnsNode"], node_data)
			except Exception as e:
				logger.exception(e)
				try:
					logger.error(record_to_dict(dnstool.DNS_RECORD(result), ts=False))
				except:  # pragma: no cover
					pass
				raise e

			# Log entry creation
			logger.info("Create Entry for %s" % (self.name))
			logger.debug(record_to_dict(dnstool.DNS_RECORD(result), ts=False))

		# LDAP entry exists
		else:
			# Add the record to the entry after all the required checks
			self.validate_create(values=values)
			# Logging entry modify
			logger.info("Adding Record to Entry with name %s" % (self.name))
			logger.debug(record_to_dict(dnstool.DNS_RECORD(result)))

			# If all checks passed
			if not dry_run:
				self.connection.modify(
					self.distinguished_name, {"dnsRecord": [(MODIFY_ADD, self.structure.getData())]}
				)
		return self.connection.result

	def fetch(self) -> list[dict]:
		if self.zone not in self.dns_zones:
			logger.debug(self.dns_zones)
			raise exc_dns.DNSZoneIsForeign(
				f"Target zone ({self.zone}) is not in the LDAP Server DNS List"
			)

		if self.name.endswith(self.zone) or self.zone in self.name:
			raise exc_dns.DNSZoneInRecord

		search_filter = search_filter_add(
			"objectClass=dnsNode", f"distinguishedName={self.distinguished_name}"
		)
		attributes = ["dnsRecord", "dNSTombstoned", "name"]

		search_target = f"DC={self.zone},{self.dns_root}"
		self.connection.search(
			search_base=search_target, search_filter=search_filter, attributes=attributes
		)
		if len(self.connection.response) > 0:
			self.raw_entry = self.connection.response[0]
		else:
			return None

		result = []
		record_dict = {}

		if self.raw_entry["type"] == "searchResEntry":
			if self.raw_entry["dn"] == self.distinguished_name:
				logger.debug("searchResEntry Data exists")

			# Set Record Name
			record_name = self.raw_entry["raw_attributes"]["name"][0]
			record_name = record_name.decode()
			logger.debug(f"{__name__} [DEBUG] - Record Name: {record_name}")

			# Set Record Data
			for record in self.raw_entry["raw_attributes"]["dnsRecord"]:
				dr = dnstool.DNS_RECORD(record)
				record_dict = record_to_dict(dr, self.raw_entry["attributes"]["dNSTombstoned"])
				record_dict["name"] = record_name
				record_dict["ttl"] = dr.__getTTL__()
				logger.debug(
					f"{__name__} [DEBUG] - Record: {record_name}, Starts With Underscore: {record_name.startswith('_')}, Exclude Entry: {record_name in self.EXCLUDED_ENTRIES}"
				)
				logger.debug(f"{__name__} [DEBUG] {dr}")
				if not record_name.startswith("_") and record_name not in self.EXCLUDED_ENTRIES:
					result.append(record_dict)

			if len(result) > 0:
				self.entry = result
		return self.entry

	def update(
		self,
		new_values: dict,
		old_values: dict,
	):
		"""
		Update a Record in the LDAP Entry identified by it's Bytes

		Args:
			values (dict): The values for the Record Update

		Returns:
			self.connection.result
		"""

		self.serial = None
		try:
			self.serial = self.get_serial(record_values=new_values, old_serial=old_values["serial"])
		except:
			logger.error(traceback.format_exc())
			raise exc_dns.DNSCouldNotGetSerial

		# Make new record struct
		self.structure = self.make_record_bytes(
			values=new_values, ttl=new_values["ttl"], serial=self.serial
		)
		# Get struct as bytes
		new_record_bytes = self.structure.getData()

		# ! Check if the record with the new values exists, if true raise exception
		# Exclude SOA from condition as that record is unique in Zone.
		self.validate_update(new_values)

		# All checks passed
		## Delete Old Record
		## ! If this fails the old record does not exist anymore,
		## ! and the operation will be halted.
		self.main_value = old_values[self.main_field]
		self.connection.modify(
			self.distinguished_name, {"dnsRecord": [(MODIFY_DELETE, self.as_bytes)]}
		)

		## Add new DNS Record
		self.main_value = new_values[self.main_field]
		self.connection.modify(
			self.distinguished_name, {"dnsRecord": [(MODIFY_ADD, new_record_bytes)]}
		)
		return self.connection.result

	def delete(self):
		"""
		Delete a Record in the LDAP Entry identified by it's Bytes

		Args:
			values (dict): Record Values

		Returns:
			self.connection.result
		"""
		# Check if Record exists in Entry
		if (
			self.raw_entry is None
			or self.as_bytes not in self.raw_entry["raw_attributes"]["dnsRecord"]
		):
			raise exc_dns.DNSRecordEntryDoesNotExist

		# Check if Entry has more than one Record
		# More than one record -> Delete Record Byte Data
		try:
			if len(self.raw_entry["raw_attributes"]["dnsRecord"]) > 1:
				self.connection.modify(
					self.distinguished_name, {"dnsRecord": [(MODIFY_DELETE, self.as_bytes)]}
				)
			else:  # Delete full entry
				self.connection.delete(self.distinguished_name)
		except Exception as e:
			logger.exception(e)
			raise exc_base.CoreException from e
		# Only record in Entry -> Delete entire Entry
		return self.connection.result
