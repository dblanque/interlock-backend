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
from core.models.dns import LDAPDNS, LDAPRecord
from core.models.user import User
from core.models.validators.ldap import (
	domain_validator,
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
from core.utils.dnstool import record_to_dict
from core.utils import dnstool

### Exceptions
from core.exceptions import dns as exc_dns

### DRF
from rest_framework import viewsets

### LDAP Core
from core.ldap.filter import LDAPFilter
from core.ldap.connector import LDAPConnector

### Others
from core.config.runtime import RuntimeSettings
from core.views.mixins.logs import LogMixin
import logging
from datetime import datetime
################################################################################
logger = logging.getLogger(__name__)
DBLogMixin = LogMixin()


class DomainViewMixin(viewsets.ViewSetMixin):
	def create_initial_serial(self, as_epoch_serial=True) -> int:
		"""Returns new epoch DNS Zone serial by default, or int"""
		if as_epoch_serial:
			return int(datetime.today().strftime("%Y%m%d") + "01")
		return 1

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

	def get_zone_records(self, user: User, request_data: dict) -> dict:
		response_data = {}

		# Set zone_filter
		request_filter: dict = request_data.get("filter", None)
		if request_filter:
			if not "dnsZone" in request_filter:
				raise exc_dns.DNSZoneNotInRequest

			zone_filter: str = request_filter.get("dnsZone")
			if not isinstance(zone_filter, str):
				zone_filter = None

		if zone_filter:
			target_zone = zone_filter.replace(" ", "")
			target_zone = target_zone.lower()
			try:
				domain_validator(target_zone)
			except Exception as e:
				raise exc_dns.DNSFieldValidatorFailed(data={"dnsZone": target_zone})
		else:
			target_zone = RuntimeSettings.LDAP_DOMAIN

		# Open LDAP Connection
		with LDAPConnector(user) as ldc:
			ldap_connection = ldc.connection

			response_data["headers"] = [
				# 'displayName', # Custom Header, attr not in LDAP
				"name",
				"value",
				"ttl",
				"typeName",
				"serial",
				# 'ts',
			]

			search_filter = LDAPFilter.eq("objectClass", "dnsNode").to_string()
			attributes = ["dnsRecord", "dNSTombstoned", "name"]

			dns_object = LDAPDNS(ldap_connection)
			dns_zones = dns_object.dns_zones
			forest_zones = dns_object.forest_zones

			search_target = "DC=%s,%s" % (target_zone, dns_object.dns_root)
			try:
				ldap_connection.search(
					search_base=search_target,
					search_filter=search_filter,
					attributes=attributes,
				)
			except Exception as e:
				logger.exception(e)
				logger.error(search_target)
				logger.error(search_filter)

			result = []

			excludeEntries = ["ForestDnsZones", "DomainDnsZones"]

			if not ldap_connection.response:
				raise exc_dns.DNSListEmpty

			record_id = 0
			for entry in ldap_connection.response:
				# Set Record Name
				record_index = 0
				record_name = entry["raw_attributes"]["name"][0]
				record_name = record_name.decode("utf-8")
				orig_name = record_name
				if record_name != "@":
					record_name += "." + target_zone
				else:
					record_name = target_zone
				logger.debug(f"{__name__} [DEBUG] - {record_name}")

				# Set Record Data
				for record in entry["raw_attributes"]["dnsRecord"]:
					dr = dnstool.DNS_RECORD(record)
					record_dict = record_to_dict(
						dr, entry["attributes"]["dNSTombstoned"]
					)
					record_dict["id"] = record_id
					record_dict["index"] = record_index
					record_dict["displayName"] = record_name
					record_dict["name"] = orig_name
					record_dict["ttl"] = dr.__getTTL__()
					record_dict["distinguishedName"] = entry["dn"]
					logger.debug(
						f"{__name__} [DEBUG] - Record: {record_name}, Starts With Underscore: {record_name.startswith('_')}, Exclude Entry: {record_name in excludeEntries}"
					)
					logger.debug(f"{__name__} [DEBUG] - {dr}")
					if (
						not record_name.startswith("_")
						and orig_name not in excludeEntries
					):
						result.append(record_dict)
					record_id += 1
					record_index += 1

					for i in range(len(dns_zones)):
						zoneName = dns_zones[i]
						if zoneName == "RootDNSServers":
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

	def insert_zone(self, user: User, request_data: dict) -> dict:
		result = {}
		new_zone_serial = self.create_initial_serial()
		default_ttl = 900

		target_zone: str = request_data.get("dnsZone", None)
		if not target_zone:
			raise exc_dns.DNSZoneNotInRequest

		target_zone = target_zone.lower()
		try:
			domain_validator(target_zone)
		except:
			raise exc_dns.DNSFieldValidatorFailed(data={"dnsZone": target_zone})

		if (
			target_zone == RuntimeSettings.LDAP_DOMAIN
			or target_zone == "RootDNSServers"
		):
			raise exc_dns.DNSZoneNotDeletable

		# Open LDAP Connection
		with LDAPConnector(user) as ldc:
			connection = ldc.connection
			dns_list = LDAPDNS(connection)
			dns_zones = dns_list.dns_zones
			forest_zones = dns_list.forest_zones

			if target_zone in dns_zones:
				raise exc_dns.DNSZoneExists

			zone_to_create_dns = "DC=%s,%s" % (target_zone, dns_list.dns_root)
			zone_to_create_forest = "DC=_msdcs.%s,%s" % (
				target_zone,
				dns_list.forest_root,
			)
			forest_dc = "_msdcs.%s" % (target_zone)

			attributes_dns = {}
			attributes_dns["dc"] = target_zone

			attributes_forest = {}
			attributes_forest["dc"] = forest_dc

			connection.add(
				dn=zone_to_create_dns,
				object_class=["dnsZone", "top"],
				attributes=attributes_dns,
			)
			create_result = connection.result

			connection.add(
				dn=zone_to_create_forest,
				object_class=["dnsZone", "top"],
				attributes=attributes_forest,
			)
			result_forest = connection.result

			current_ldap_server = connection.server_pool.get_current_server(
				connection
			)
			current_ldap_server_ip = current_ldap_server.host

			# Create Start of Authority
			record_soa = LDAPRecord(
				connection=connection,
				record_name="@",
				record_zone=target_zone,
				record_type=RecordTypes.DNS_RECORD_TYPE_SOA.value,
				record_main_value=f"ns.{target_zone}.",
			)
			values_soa = {
				"ttl": default_ttl,
				"serial": new_zone_serial,
				# SOA Specific
				"dwSerialNo": new_zone_serial,
				"dwRefresh": 900,
				"dwRetry": 600,
				"dwExpire": 86400,
				"dwMinimumTtl": default_ttl,
				"namePrimaryServer": f"ns.{target_zone}.",
				"zoneAdminEmail": f"hostmaster.{target_zone}",
			}
			record_soa.create(values=values_soa)

			result_record_soa = connection.result

			ipv4 = False
			ipv6 = False

			# Check if server is ipv4
			try:
				ipv4_validator(current_ldap_server_ip)
				ipv4 = True
			except:
				pass

			# Check if server is ipv6
			try:
				ipv6_validator(current_ldap_server_ip)
				ipv6 = True
			except:
				pass

			# LDAP Server IP Address
			if ipv4:
				values_a = {
					"address": current_ldap_server_ip,
					"ttl": default_ttl,
					"serial": new_zone_serial,
				}
				record_a = LDAPRecord(
					connection=connection,
					record_name="@",
					record_zone=target_zone,
					record_type=RecordTypes.DNS_RECORD_TYPE_A.value,
					record_main_value=current_ldap_server_ip,
				)
				record_a.create(values=values_a)

				result_record_a = connection.result

				values_a_ns = {
					"address": current_ldap_server_ip,
					"ttl": default_ttl,
					"serial": new_zone_serial,
				}
				record_a_to_ns = LDAPRecord(
					connection=connection,
					record_name="ns1",
					record_zone=target_zone,
					record_type=RecordTypes.DNS_RECORD_TYPE_A.value,
					record_main_value=current_ldap_server_ip,
				)
				record_a_to_ns.create(values=values_a_ns)

				result_record_a_to_ns = connection.result
			elif ipv6:
				values_aaaa = {
					"address": current_ldap_server_ip,
					"ttl": default_ttl,
					"serial": new_zone_serial,
				}
				record_aaaa = LDAPRecord(
					connection=connection,
					record_name="@",
					record_zone=target_zone,
					record_type=RecordTypes.DNS_RECORD_TYPE_AAAA.value,
					record_main_value=current_ldap_server_ip,
				)
				record_aaaa.create(values=values_aaaa)

				aaaa_record_result = connection.result

				values_aaaa_ns = {
					"address": current_ldap_server_ip,
					"ttl": default_ttl,
					"serial": new_zone_serial,
				}
				record_aaaa_to_ns = LDAPRecord(
					connection=connection,
					record_name="ns1",
					record_zone=target_zone,
					record_type=RecordTypes.DNS_RECORD_TYPE_AAAA.value,
					record_main_value=current_ldap_server_ip,
				)
				record_aaaa_to_ns.create(values=values_aaaa_ns)

				aaaa_to_ns_record_result = connection.result

			# NS Record Creation
			values_ns = {
				"nameNode": f"ns1.{target_zone}.",
				"ttl": 3600,
				"serial": new_zone_serial,
			}
			record_a_to_ns = LDAPRecord(
				connection=connection,
				record_name="@",
				record_zone=target_zone,
				record_type=RecordTypes.DNS_RECORD_TYPE_NS.value,
				record_main_value=f"ns1.{target_zone}.",
			)
			record_a_to_ns.create(values=values_ns)

			result_record_a_to_ns = connection.result

			result = {
				"dns": create_result,
				"forest": result_forest,
				"soa": result_record_soa,
				"ns": result_record_a_to_ns,
			}

			if ipv4:
				result.update(
					{"a_ns": result_record_a_to_ns, "a": result_record_a}
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
			ldap_connection = ldc.connection
			dns_object = LDAPDNS(ldap_connection)
			dns_zones = dns_object.dns_zones
			forest_zones = dns_object.forest_zones

			if target_zone not in dns_zones:
				raise exc_dns.DNSZoneDoesNotExist

			zone_to_delete_dn = "DC=%s,%s" % (target_zone, dns_object.dns_root)
			zone_to_delete_forest_dn = "DC=_msdcs.%s,%s" % (
				target_zone,
				dns_object.forest_root,
			)
			forest_dc = "_msdcs.%s" % (target_zone)

			attributes_dns = {}
			attributes_dns["dc"] = target_zone

			attributes_forest = {}
			attributes_forest["dc"] = forest_dc

			search_target = "DC=%s,%s" % (target_zone, dns_object.dns_root)
			search_filter = LDAPFilter.eq("objectClass", "dnsNode").to_string()
			attributes = ["dnsRecord", "dNSTombstoned", "name"]
			records = ldap_connection.extend.standard.paged_search(
				search_base=search_target,
				search_filter=search_filter,
				search_scope=ldap3_LEVEL,
				attributes=attributes,
			)

			for r in list(records):
				ldap_connection.delete(r["dn"])

			ldap_connection.delete(dn=zone_to_delete_dn)
			result_zone = ldap_connection.result

			ldap_connection.delete(dn=zone_to_delete_forest_dn)
			result_forest = ldap_connection.result

		DBLogMixin.log(
			user=user.id,
			operation_type=LOG_ACTION_DELETE,
			log_target_class=LOG_CLASS_DNSZ,
			log_target=target_zone,
		)
		return result_zone, result_forest