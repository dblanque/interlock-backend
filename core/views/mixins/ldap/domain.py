################################################################################
#################### INTERLOCK IS LICENSED UNDER GNU AGPLv3 ####################
################## ORIGINAL PROJECT CREATED BY DYLAN BLANQUÉ ###################
########################## AND BR CONSULTING S.R.L. ############################
################################################################################
# Module: core.views.mixins.ldap.domain
# Contains the Mixin for domain related operations

# ---------------------------------- IMPORTS -----------------------------------#
### Types
from core.models.types.ldap_dns_record import RecordTypes

### Constants
from ldap3 import LEVEL as ldap3_LEVEL

### Models
from core.utils.main import getldapattrvalue
from core.models.dns import LDAPDNS, LDAPRecord, DATE_FMT
from core.models.user import User
from core.constants.attrs import LDAP_ATTR_OBJECT_CLASS
from core.constants.dns import *
from core.models.validators.ldap import (
	ipv4_validator,
	ipv6_validator,
)
from core.models.choices.log import (
	LOG_ACTION_READ,
	LOG_ACTION_CREATE,
	LOG_ACTION_DELETE,
	LOG_CLASS_DNSZ,
)

### DNS Utilities
from core.utils.dnstool import record_to_dict, DNS_RECORD

### Exceptions
from core.exceptions import dns as exc_dns

### DRF
from rest_framework import viewsets

### LDAP Core
from core.ldap.filter import LDAPFilter
from core.ldap.connector import LDAPConnector

### Others
from copy import deepcopy
from core.type_hints.connector import LDAPConnectionProtocol
from core.config.runtime import RuntimeSettings
from core.views.mixins.logs import LogMixin
import logging
from datetime import datetime
from ldap3 import Entry as LDAPEntry

################################################################################
logger = logging.getLogger(__name__)
DBLogMixin = LogMixin()


class DomainViewMixin(viewsets.ViewSetMixin):
	connection: LDAPConnectionProtocol = None

	def has_connection(self, raise_exception=True):
		if not self.connection and raise_exception:
			raise Exception("LDAP Connection must be bound in Mixin Class.")
		else:
			return self.connection

	def create_initial_serial(self, as_epoch_serial=True) -> int:
		"""Returns new epoch DNS Zone serial by default, or int"""
		if as_epoch_serial:
			return int(datetime.today().strftime(DATE_FMT) + "01")
		return 1

	def get_zone_soa(self, zone):
		self.has_connection()

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
		next_soa_r[LDNS_ATTR_SOA_SERIAL] = record_serial
		next_soa_r[LDNS_ATTR_SERIAL] = record_serial

		try:
			soa_entry.update(new_values=next_soa_r, old_values=prev_soa_r)
			return soa_entry.connection.result
		except Exception as e:
			print(e)

	def get_zone_records(self, user: User, target_zone: str) -> dict:
		response_data = {}

		# Open LDAP Connection
		with LDAPConnector(user) as ldc:
			self.connection = ldc.connection

			response_data["headers"] = [
				LDNS_ATTR_ENTRY_DISPLAY_NAME,  # Custom Header, attr not in LDAP
				"value",
				LDNS_ATTR_TTL,
				LDNS_ATTR_TYPE_NAME,
				LDNS_ATTR_SERIAL,
			]

			search_filter = LDAPFilter.eq(
				LDAP_ATTR_OBJECT_CLASS, "dnsNode"
			).to_string()
			attributes = [
				LDNS_ATTR_ENTRY_RECORD,
				LDNS_ATTR_ENTRY_TOMBSTONED,
				"name",
			]

			dns_object = LDAPDNS(self.connection)
			dns_zones = dns_object.dns_zones
			forest_zones = dns_object.forest_zones

			search_target = f"DC={target_zone},{dns_object.dns_root}"
			try:
				self.connection.search(
					search_base=search_target,
					search_filter=search_filter,
					attributes=attributes,
				)
			except Exception as e:
				logger.exception(e)
				logger.error(search_target)
				logger.error(search_filter)
				raise e

			result = []
			exclude_entries = ["forestdnszones", "domaindnszones"]

			if not self.connection.response and not self.connection.entries:
				raise exc_dns.DNSListEmpty

			record_id = 0
			# This was changed from ldap_connection.response to .entries
			for entry in self.connection.entries:
				# Set Record Name
				record_index = 0
				record_name: bytes | str = getldapattrvalue(entry, "name")
				if record_name.startswith("_") or any(
					record_name.lower() == v.lower() for v in exclude_entries
				):
					continue
				if isinstance(record_name, bytes):
					record_name = record_name.decode("utf-8")

				logger.debug(f"{__name__} [DEBUG] - {record_name}")

				# Set Record Data
				entry_raw_attrs: dict = entry.entry_raw_attributes
				for record in entry_raw_attrs.get(LDNS_ATTR_ENTRY_RECORD):
					is_tombstoned = bool(
						getldapattrvalue(entry, LDNS_ATTR_ENTRY_TOMBSTONED)
					)
					try:
						dr = DNS_RECORD(record)
					except:
						logger.error(
							f"Could not parse struct values for record {record_name}"
						)
						raise

					try:
						record_dict = record_to_dict(
							record=dr, ts=is_tombstoned
						)
					except:
						logger.error(
							f"Could not parse dict values for record {record_name}"
						)
						raise
					record_dict[LDNS_ATTR_ID] = record_id
					record_dict[LDNS_ATTR_ENTRY_DISPLAY_NAME] = (
						f"{record_name}.{target_zone}"
						if record_name != "@"
						else f"@ ({target_zone})"
					)
					record_dict[LDNS_ATTR_ENTRY_NAME] = record_name
					record_dict[LDNS_ATTR_TTL] = dr.__getTTL__()
					record_dict[LDNS_ATTR_ENTRY_DN] = entry.entry_dn
					logger.debug(
						"%s [DEBUG] - Record: %s, Starts With Underscore: %s, Exclude Entry: %s",
						__name__,
						record_name,
						record_name.startswith("_"),
						record_name in exclude_entries,
					)
					logger.debug("%s [DEBUG] - %s", __name__, dr)
					result.append(record_dict)
					record_id += 1
					record_index += 1

					for i, zone_name in enumerate(dns_zones):
						if zone_name.lower() == "RootDNSServers".lower():
							dns_zones[i] = "Root DNS Servers"

					response_data["dnsZones"] = dns_zones
					response_data["forestZones"] = forest_zones
					response_data["records"] = result
					response_data["legacy"] = (
						RuntimeSettings.LDAP_DNS_LEGACY or False
					)

		DBLogMixin.log(
			user=user.id,
			operation_type=LOG_ACTION_READ,
			log_target_class=LOG_CLASS_DNSZ,
			log_target=target_zone,
		)
		return response_data

	def insert_soa(self, target_zone: str, ttl: int, serial: int):
		self.has_connection()

		# Create Start of Authority
		record_soa = LDAPRecord(
			connection=self.connection,
			record_name="@",
			record_zone=target_zone,
			record_type=RecordTypes.DNS_RECORD_TYPE_SOA.value,
			record_main_value=f"ns.{target_zone}.",
		)
		record_soa.create(
			values={
				LDNS_ATTR_TTL: ttl,
				LDNS_ATTR_SERIAL: serial,
				# SOA Specific
				LDNS_ATTR_SOA_SERIAL: serial,
				LDNS_ATTR_SOA_REFRESH: 900,
				LDNS_ATTR_SOA_RETRY: 600,
				LDNS_ATTR_SOA_EXPIRE: 86400,
				LDNS_ATTR_SOA_MIN_TTL: ttl,
				LDNS_ATTR_SOA_PRIMARY_NS: f"ns.{target_zone}.",
				LDNS_ATTR_SOA_EMAIL: f"hostmaster.{target_zone}",
			}
		)
		return deepcopy(self.connection.result)

	def insert_nameserver_a(
		self, target_zone: str, ip_address: str, ttl: int, serial: int
	):
		self.has_connection()

		a_record = LDAPRecord(
			connection=self.connection,
			record_name="@",
			record_zone=target_zone,
			record_type=RecordTypes.DNS_RECORD_TYPE_A.value,
			record_main_value=ip_address,
		)
		a_record.create(
			values={
				LDNS_ATTR_IPV4_ADDRESS: ip_address,
				LDNS_ATTR_TTL: ttl,
				LDNS_ATTR_SERIAL: serial,
			}
		)
		a_record_result = deepcopy(self.connection.result)

		ns_record_a = LDAPRecord(
			connection=self.connection,
			record_name="ns1",
			record_zone=target_zone,
			record_type=RecordTypes.DNS_RECORD_TYPE_A.value,
			record_main_value=ip_address,
		)
		ns_record_a.create(
			values={
				LDNS_ATTR_IPV4_ADDRESS: ip_address,
				LDNS_ATTR_TTL: ttl,
				LDNS_ATTR_SERIAL: serial,
			}
		)
		a_to_ns_record_result = deepcopy(self.connection.result)

		return a_record_result, a_to_ns_record_result

	def insert_nameserver_aaaa(
		self, target_zone: str, ip_address: str, ttl: int, serial: int
	):
		self.has_connection()

		aaaa_record = LDAPRecord(
			connection=self.connection,
			record_name="@",
			record_zone=target_zone,
			record_type=RecordTypes.DNS_RECORD_TYPE_AAAA.value,
			record_main_value=ip_address,
		)
		aaaa_record.create(
			values={
				LDNS_ATTR_IPV6_ADDRESS: ip_address,
				LDNS_ATTR_TTL: ttl,
				LDNS_ATTR_SERIAL: serial,
			}
		)
		aaaa_record_result = deepcopy(self.connection.result)

		ns_record_aaaa = LDAPRecord(
			connection=self.connection,
			record_name="ns1",
			record_zone=target_zone,
			record_type=RecordTypes.DNS_RECORD_TYPE_AAAA.value,
			record_main_value=ip_address,
		)
		ns_record_aaaa.create(
			values={
				LDNS_ATTR_IPV6_ADDRESS: ip_address,
				LDNS_ATTR_TTL: ttl,
				LDNS_ATTR_SERIAL: serial,
			}
		)
		aaaa_to_ns_record_result = deepcopy(self.connection.result)

		return aaaa_record_result, aaaa_to_ns_record_result

	def insert_nameserver_ns(self, target_zone: str, ttl: int, serial: int):
		self.has_connection()

		# NS Record Creation
		record_ns = LDAPRecord(
			connection=self.connection,
			record_name="@",
			record_zone=target_zone,
			record_type=RecordTypes.DNS_RECORD_TYPE_NS.value,
			record_main_value=f"ns1.{target_zone}.",
		)
		record_ns.create(
			values={
				LDNS_ATTR_NAME_NODE: f"ns1.{target_zone}.",
				LDNS_ATTR_TTL: ttl,
				LDNS_ATTR_SERIAL: serial,
			}
		)
		return deepcopy(self.connection.result)

	def insert_zone(self, user: User, target_zone: str) -> dict:
		result = {}
		new_zone_serial = self.create_initial_serial()
		default_ttl = 900

		# Open LDAP Connection
		with LDAPConnector(user) as ldc:
			self.connection = ldc.connection
			dns_list = LDAPDNS(self.connection)
			dns_zones = dns_list.dns_zones

			if target_zone in dns_zones:
				raise exc_dns.DNSZoneExists

			####################################################################
			################### Create DNS and Forest Zones ####################
			####################################################################
			zone_to_create_dns = f"DC={target_zone},{dns_list.dns_root}"
			zone_to_create_forest = (
				f"DC=_msdcs.{target_zone},{dns_list.forest_root}"
			)
			forest_dc = f"_msdcs.{target_zone}"

			self.connection.add(
				dn=zone_to_create_dns,
				object_class=["dnsZone", "top"],
				attributes={"dc": target_zone},
			)
			create_result = deepcopy(self.connection.result)

			self.connection.add(
				dn=zone_to_create_forest,
				object_class=["dnsZone", "top"],
				attributes={"dc": forest_dc},
			)
			result_forest = deepcopy(self.connection.result)
			####################################################################

			# Obtain current LDAP Server IP
			current_ldap_server = (
				self.connection.server_pool.get_current_server(self.connection)
			)
			current_ldap_server_ip = current_ldap_server.host

			####################################################################
			############## Insert Zone Start of Authority Record ###############
			####################################################################
			result_record_soa = self.insert_soa(
				target_zone=target_zone,
				ttl=default_ttl,
				serial=new_zone_serial,
			)
			####################################################################

			# Check if server is ipv4
			ipv4 = False
			try:
				ipv4_validator(current_ldap_server_ip)
				ipv4 = True
			except:
				pass

			# Check if server is ipv6
			ipv6 = False
			try:
				ipv6_validator(current_ldap_server_ip)
				ipv6 = True
			except:
				pass

			####################################################################
			######## Insert Nameserver and corresponding A/AAAA Record #########
			####################################################################
			if ipv4:
				a_record_result, a_to_ns_record_result = (
					self.insert_nameserver_a(
						target_zone=target_zone,
						ip_address=current_ldap_server_ip,
						ttl=default_ttl,
						serial=new_zone_serial,
					)
				)
			elif ipv6:
				aaaa_record_result, aaaa_to_ns_record_result = (
					self.insert_nameserver_aaaa(
						target_zone=target_zone,
						ip_address=current_ldap_server_ip,
						ttl=default_ttl,
						serial=new_zone_serial,
					)
				)

			result_record_ns = self.insert_nameserver_ns(
				target_zone=target_zone,
				ttl=3600 if default_ttl < 3600 else default_ttl,
				serial=new_zone_serial,
			)
			####################################################################

			result = {
				"dns": create_result,
				"forest": result_forest,
				"soa": result_record_soa,
				"ns": result_record_ns,
			}

			if ipv4:
				result.update(
					{"a_ns": a_to_ns_record_result, "a": a_record_result}
				)
			elif ipv6:
				result.update(
					{
						"aaaa_ns": aaaa_to_ns_record_result,
						"aaaa": aaaa_record_result,
					}
				)

		DBLogMixin.log(
			user=user.id,
			operation_type=LOG_ACTION_CREATE,
			log_target_class=LOG_CLASS_DNSZ,
			log_target=target_zone,
		)
		return result

	def delete_zone(self, user: User, target_zone: str) -> tuple[str, str]:
		# Open LDAP Connection
		with LDAPConnector(user) as ldc:
			self.connection = ldc.connection
			dns_object = LDAPDNS(self.connection)
			dns_zones = dns_object.dns_zones

			if target_zone not in dns_zones:
				raise exc_dns.DNSZoneDoesNotExist

			zone_to_delete_dn = "DC=%s,%s" % (target_zone, dns_object.dns_root)
			zone_to_delete_forest_dn = "DC=_msdcs.%s,%s" % (
				target_zone,
				dns_object.forest_root,
			)

			search_target = f"DC={target_zone},{dns_object.dns_root}"
			search_filter = LDAPFilter.eq(
				LDAP_ATTR_OBJECT_CLASS, "dnsNode"
			).to_string()
			self.connection.search(
				search_base=search_target,
				search_filter=search_filter,
				search_scope=ldap3_LEVEL,
				attributes=[
					LDNS_ATTR_ENTRY_RECORD,
					LDNS_ATTR_ENTRY_TOMBSTONED,
					LDNS_ATTR_ENTRY_NAME,
				],
			)
			records = self.connection.entries

			for _record in list(records):
				_record: LDAPEntry
				self.connection.delete(dn=_record.entry_dn)

			self.connection.delete(dn=zone_to_delete_dn)
			result_zone = deepcopy(self.connection.result)

			self.connection.delete(dn=zone_to_delete_forest_dn)
			result_forest = deepcopy(self.connection.result)

		DBLogMixin.log(
			user=user.id,
			operation_type=LOG_ACTION_DELETE,
			log_target_class=LOG_CLASS_DNSZ,
			log_target=target_zone,
		)
		return result_zone, result_forest
