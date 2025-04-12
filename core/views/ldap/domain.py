################################################################################
#################### INTERLOCK IS LICENSED UNDER GNU AGPLv3 ####################
################## ORIGINAL PROJECT CREATED BY DYLAN BLANQUÉ ###################
########################## AND BR CONSULTING S.R.L. ############################
################################################################################
# Module: core.views.domain
# Contains the ViewSet for Domain related operations

# ---------------------------------- IMPORTS -----------------------------------#
### Models
from core.views.mixins.logs import LogMixin
from core.models.interlock_settings import InterlockSetting, INTERLOCK_SETTING_ENABLE_LDAP
from core.models.dns import LDAPDNS, LDAPRecord
from core.models.types.ldap_dns_record import RecordTypes
from core.models.user import User
from core.models.choices.log import (
	LOG_ACTION_READ,
	LOG_ACTION_CREATE,
	LOG_ACTION_DELETE,
	LOG_CLASS_DNSZ,
)

### ViewSets
from core.views.base import BaseViewSet

### Exceptions
from django.core.exceptions import ObjectDoesNotExist
from core.exceptions import ldap as exc_ldap, dns as exc_dns

### Mixins
from core.views.mixins.ldap.domain import DomainViewMixin

### REST Framework
from rest_framework.response import Response
from rest_framework.decorators import action

### Others
from core.decorators.login import auth_required, admin_required
from core.models.validators.ldap_dns_record import domain_validator, ipv4_validator, ipv6_validator
from interlock_backend.settings import DEBUG as INTERLOCK_DEBUG
from core.utils import dnstool
from core.utils.dnstool import record_to_dict
from core.ldap.adsi import join_ldap_filter
from core.config.runtime import RuntimeSettings
from core.ldap import defaults
from core.ldap.connector import LDAPConnector
import logging
################################################################################

DBLogMixin = LogMixin()
logger = logging.getLogger(__name__)


class LDAPDomainViewSet(BaseViewSet, DomainViewMixin):
	@action(detail=False, methods=["get"])
	@auth_required
	def details(self, request):
		data = {
			"realm": "",
			"name": "",
			"basedn": "",
			"user_selector": RuntimeSettings.LDAP_AUTH_USERNAME_IDENTIFIER or "",
		}
		code = 0
		try:
			ldap_enabled = InterlockSetting.objects.get(name=INTERLOCK_SETTING_ENABLE_LDAP)
			ldap_enabled = ldap_enabled.value
		except ObjectDoesNotExist:
			ldap_enabled = False

		if ldap_enabled:
			if (
				RuntimeSettings.LDAP_AUTH_ACTIVE_DIRECTORY_DOMAIN
				!= defaults.LDAP_AUTH_ACTIVE_DIRECTORY_DOMAIN
			):
				data["realm"] = RuntimeSettings.LDAP_AUTH_ACTIVE_DIRECTORY_DOMAIN or ""

			if RuntimeSettings.LDAP_DOMAIN != defaults.LDAP_DOMAIN:
				data["name"] = RuntimeSettings.LDAP_DOMAIN or ""

			if RuntimeSettings.LDAP_AUTH_SEARCH_BASE != defaults.LDAP_AUTH_SEARCH_BASE:
				data["basedn"] = RuntimeSettings.LDAP_AUTH_SEARCH_BASE or ""

		if INTERLOCK_DEBUG:
			data["debug"] = INTERLOCK_DEBUG
		return Response(data={"code": code, "code_msg": "ok", "details": data})

	@action(detail=False, methods=["post"])
	@auth_required
	@admin_required
	def zones(self, request):
		user: User = request.user
		data = {}
		code = 0
		reqData = request.data
		responseData = {}

		if "filter" in reqData:
			if "dnsZone" in reqData["filter"]:
				zoneFilter = str(reqData["filter"]["dnsZone"]).replace(" ", "")
			else:
				raise exc_dns.DNSZoneNotInRequest

		if zoneFilter is not None:
			if zoneFilter == "" or len(zoneFilter) == 0:
				zoneFilter = None

		# Open LDAP Connection
		with LDAPConnector(user) as ldc:
			ldapConnection = ldc.connection

			responseData["headers"] = [
				# 'displayName', # Custom Header, attr not in LDAP
				"name",
				"value",
				"ttl",
				"typeName",
				"serial",
				# 'ts',
			]

			searchFilter = join_ldap_filter("", "objectClass=dnsNode")
			attributes = ["dnsRecord", "dNSTombstoned", "name"]

			dnsList = LDAPDNS(ldapConnection)
			dnsZones = dnsList.dns_zones
			forestZones = dnsList.forest_zones

			if zoneFilter is not None:
				target_zone = zoneFilter
			else:
				target_zone = RuntimeSettings.LDAP_DOMAIN
			search_target = "DC=%s,%s" % (target_zone, dnsList.dns_root)
			try:
				ldapConnection.search(
					search_base=search_target, search_filter=searchFilter, attributes=attributes
				)
			except Exception as e:
				print(search_target)
				print(searchFilter)
				print(e)

			result = []

			excludeEntries = ["ForestDnsZones", "DomainDnsZones"]

			if not ldapConnection.response:
				raise exc_dns.DNSListEmpty

			record_id = 0
			for entry in ldapConnection.response:
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
					record_dict = record_to_dict(dr, entry["attributes"]["dNSTombstoned"])
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
					if not record_name.startswith("_") and orig_name not in excludeEntries:
						result.append(record_dict)
					record_id += 1
					record_index += 1

					for i in range(len(dnsZones)):
						zoneName = dnsZones[i]
						if zoneName == "RootDNSServers":
							dnsZones[i] = "Root DNS Servers"

					DBLogMixin.log(
						user=request.user.id,
						operation_type=LOG_ACTION_READ,
						log_target_class=LOG_CLASS_DNSZ,
						log_target=target_zone,
					)

					responseData["dnsZones"] = dnsZones
					responseData["forestZones"] = forestZones
					responseData["records"] = result
					responseData["legacy"] = RuntimeSettings.LDAP_DNS_LEGACY or False

		return Response(data={"code": code, "code_msg": "ok", "data": responseData})

	@action(detail=False, methods=["post"])
	@auth_required
	@admin_required
	def insert(self, request):
		user: User = request.user
		data = {}
		code = 0
		reqData = request.data
		result = {}

		if "dnsZone" not in reqData:
			raise exc_dns.DNSZoneNotInRequest
		else:
			target_zone = reqData["dnsZone"].lower()

		if domain_validator(target_zone) != True:
			data = {"dnsZone": target_zone}
			raise exc_dns.DNSFieldValidatorFailed(data=data)

		if target_zone == RuntimeSettings.LDAP_DOMAIN or target_zone == "RootDNSServers":
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
			zone_to_create_forest = "DC=_msdcs.%s,%s" % (target_zone, dns_list.forest_root)
			forest_dc = "_msdcs.%s" % (target_zone)

			attributes_dns = {}
			attributes_dns["dc"] = target_zone

			attributes_forest = {}
			attributes_forest["dc"] = forest_dc

			connection.add(
				dn=zone_to_create_dns, object_class=["dnsZone", "top"], attributes=attributes_dns
			)
			create_result = connection.result

			connection.add(
				dn=zone_to_create_forest,
				object_class=["dnsZone", "top"],
				attributes=attributes_forest,
			)
			forestCreateResult = connection.result

			current_ldap_server = connection.server_pool.get_current_server(connection)
			current_ldap_server_ip = current_ldap_server.host

			# Create Start of Authority
			base_soaRecord = LDAPRecord(
				connection=connection,
				record_name="@",
				record_zone=target_zone,
				record_type=RecordTypes.DNS_RECORD_TYPE_SOA.value,
				record_main_value=f"ns.{target_zone}.",
			)
			values_soa = {
				"dwSerialNo": 1,
				"dwRefresh": 900,
				"dwRetry": 600,
				"dwExpire": 86400,
				"dwMinimumTtl": 900,
				"namePrimaryServer": f"ns.{target_zone}.",
				"zoneAdminEmail": f"hostmaster.{target_zone}",
			}
			base_soaRecord.create(values=values_soa)

			soaCreateResult = connection.result

			ipv4 = False
			ipv6 = False
			if ipv4_validator(current_ldap_server_ip):
				ipv4 = True
			elif ipv6_validator(current_ldap_server_ip):
				ipv6 = True

			# LDAP Server IP Address
			if ipv4:
				values_a = {"address": current_ldap_server_ip, "ttl": 900, "serial": 1}
				base_record_a = LDAPRecord(
					connection=connection,
					record_name="@",
					record_zone=target_zone,
					record_type=RecordTypes.DNS_RECORD_TYPE_A.value,
					record_main_value=current_ldap_server_ip,
				)
				base_record_a.create(values=values_a)

				a_record_result = connection.result

				values_a_ns = {"address": current_ldap_server_ip, "ttl": 900, "serial": 1}
				base_record_a_to_ns = LDAPRecord(
					connection=connection,
					record_name="ns1",
					record_zone=target_zone,
					record_type=RecordTypes.DNS_RECORD_TYPE_A.value,
					record_main_value=current_ldap_server_ip,
				)
				base_record_a_to_ns.create(values=values_a_ns)

				a_to_ns_record_result = connection.result
			elif ipv6:
				values_aaaa = {"address": current_ldap_server_ip, "ttl": 900, "serial": 1}
				base_record_a = LDAPRecord(
					connection=connection,
					record_name="@",
					record_zone=target_zone,
					record_type=RecordTypes.DNS_RECORD_TYPE_AAAA.value,
					record_main_value=current_ldap_server_ip,
				)
				base_record_a.create(values=values_aaaa)

				aaaa_record_result = connection.result

				values_aaaa_ns = {"address": current_ldap_server_ip, "ttl": 900, "serial": 1}
				base_record_aaaa_to_ns = LDAPRecord(
					connection=connection,
					record_name="ns1",
					record_zone=target_zone,
					record_type=RecordTypes.DNS_RECORD_TYPE_AAAA.value,
					record_main_value=current_ldap_server_ip,
				)
				base_record_aaaa_to_ns.create(values=values_aaaa_ns)

				aaaa_to_ns_record_result = connection.result

			values_ns = {"nameNode": f"ns1.{target_zone}.", "ttl": 3600, "serial": 1}
			base_record_a_to_ns = LDAPRecord(
				connection=connection,
				record_name="@",
				record_zone=target_zone,
				record_type=RecordTypes.DNS_RECORD_TYPE_NS.value,
				record_main_value=f"ns1.{target_zone}.",
			)
			base_record_a_to_ns.create(values=values_ns)

			a_to_ns_record_result = connection.result

			connection.unbind()

			result = {
				"dns": create_result,
				"forest": forestCreateResult,
				"soa": soaCreateResult,
				"ns": a_to_ns_record_result,
			}

			if ipv4:
				result.update({"a_ns": a_to_ns_record_result, "a": a_record_result})
			elif ipv6:
				result.update({"aaaa_ns": aaaa_to_ns_record_result, "aaaa": aaaa_record_result})

			DBLogMixin.log(
				user=request.user.id,
				operation_type=LOG_ACTION_CREATE,
				log_target_class=LOG_CLASS_DNSZ,
				log_target=target_zone,
			)

		return Response(data={"code": code, "code_msg": "ok", "result": result})

	@action(detail=False, methods=["post"])
	@auth_required
	@admin_required
	def delete(self, request):
		user: User = request.user
		data = {}
		code = 0
		reqData = request.data
		dnsDeleteResult = None
		forestDeleteResult = None

		if "dnsZone" not in reqData:
			raise exc_dns.DNSZoneNotInRequest
		else:
			target_zone = reqData["dnsZone"].lower()

		if domain_validator(target_zone) != True:
			data = {"dnsZone": target_zone}
			raise exc_dns.DNSFieldValidatorFailed(data=data)

		if target_zone == RuntimeSettings.LDAP_DOMAIN or target_zone == "RootDNSServers":
			raise exc_dns.DNSZoneNotDeletable

		# Open LDAP Connection
		with LDAPConnector(user) as ldc:
			ldapConnection = ldc.connection
			dnsList = LDAPDNS(ldapConnection)
			dnsZones = dnsList.dns_zones
			forestZones = dnsList.forest_zones

			if target_zone not in dnsZones:
				raise exc_dns.DNSZoneDoesNotExist

			zoneToCreate_dns = "DC=%s,%s" % (target_zone, dnsList.dns_root)
			zoneToCreate_forest = "DC=_msdcs.%s,%s" % (target_zone, dnsList.forest_root)
			forest_dc = "_msdcs.%s" % (target_zone)

			attributes_dns = {}
			attributes_dns["dc"] = target_zone

			attributes_forest = {}
			attributes_forest["dc"] = forest_dc

			search_target = "DC=%s,%s" % (target_zone, dnsList.dns_root)
			searchFilter = join_ldap_filter("", "objectClass=dnsNode")
			attributes = ["dnsRecord", "dNSTombstoned", "name"]
			records = ldapConnection.extend.standard.paged_search(
				search_base=search_target,
				search_filter=searchFilter,
				search_scope="LEVEL",
				attributes=attributes,
			)

			for r in list(records):
				ldapConnection.delete(r["dn"])

			ldapConnection.delete(dn=zoneToCreate_dns)
			dnsDeleteResult = ldapConnection.result

			ldapConnection.delete(dn=zoneToCreate_forest)
			forestDeleteResult = ldapConnection.result

			ldapConnection.unbind()

			DBLogMixin.log(
				user=request.user.id,
				operation_type=LOG_ACTION_DELETE,
				log_target_class=LOG_CLASS_DNSZ,
				log_target=target_zone,
			)

		return Response(
			data={
				"code": code,
				"code_msg": "ok",
				"result": {"dns": dnsDeleteResult, "forest": forestDeleteResult},
			}
		)
