################################################################################
#################### INTERLOCK IS LICENSED UNDER GNU AGPLv3 ####################
################## ORIGINAL PROJECT CREATED BY DYLAN BLANQUÉ ###################
########################## AND BR CONSULTING S.R.L. ############################
################################################################################
# Module: core.views.domain
# Contains the ViewSet for Domain related operations

#---------------------------------- IMPORTS -----------------------------------#
### Models
from core.views.mixins.logs import LogMixin
from core.models.dns import LDAPDNS, LDAPRecord
from core.models.types.ldap_dns_record import *

### ViewSets
from core.views.base import BaseViewSet

### Exceptions
from core.exceptions import (
	ldap as exc_ldap,
	dns as exc_dns
)

### Mixins
from .mixins.domain import DomainViewMixin

### REST Framework
from rest_framework.response import Response
from rest_framework.decorators import action

### Others
from core.decorators.login import auth_required
from core.models.validators.ldap_dns_record import (
	domain_validator,
	ipv4_validator,
	ipv6_validator
)
from interlock_backend.settings import DEBUG as INTERLOCK_DEBUG
from core.utils import dnstool
from core.utils.dnstool import record_to_dict
from interlock_backend.ldap.adsi import search_filter_add
from core.models.ldap_settings_db import RunningSettings
from interlock_backend.ldap.connector import LDAPConnector
import logging
################################################################################

DBLogMixin = LogMixin()
logger = logging.getLogger(__name__)

class DomainViewSet(BaseViewSet, DomainViewMixin):

	@action(detail=False, methods=['get'])
	@auth_required(require_admin=False)
	def details(self, request):
		user = request.user
		data = {}
		code = 0
		data["realm"] = RunningSettings.LDAP_AUTH_ACTIVE_DIRECTORY_DOMAIN or ""
		data["name"] = RunningSettings.LDAP_DOMAIN or ""
		data["basedn"] = RunningSettings.LDAP_AUTH_SEARCH_BASE or ""
		data["user_selector"] = RunningSettings.LDAP_AUTH_USERNAME_IDENTIFIER or ""
		if INTERLOCK_DEBUG:
			data["debug"] = INTERLOCK_DEBUG
		return Response(
			 data={
				'code': code,
				'code_msg': 'ok',
				'details': data
			 }
		)

	@action(detail=False, methods=['post'])
	@auth_required()
	def zones(self, request):
		user = request.user
		data = dict()
		code = 0
		reqData = request.data
		responseData = dict()

		if 'filter' in reqData:
			if 'dnsZone' in reqData['filter']:
				zoneFilter = str(reqData['filter']['dnsZone']).replace(" ", "")
			else: raise exc_dns.DNSZoneNotInRequest

		if zoneFilter is not None:
			if zoneFilter == "" or len(zoneFilter) == 0:
				zoneFilter = None

		# Open LDAP Connection
		with LDAPConnector(user.dn, user.encryptedPassword, request.user) as ldc:
			ldapConnection = ldc.connection

			responseData['headers'] = [
				# 'displayName', # Custom Header, attr not in LDAP
				'name',
				'value',
				'ttl',
				'typeName',
				'serial',
				# 'ts',
			]

			searchFilter = search_filter_add("", "objectClass=dnsNode")
			attributes=['dnsRecord','dNSTombstoned','name']

			dnsList = LDAPDNS(ldapConnection)
			dnsZones = dnsList.dnszones
			forestZones = dnsList.forestzones

			if zoneFilter is not None:
				target_zone = zoneFilter
			else:
				target_zone = RunningSettings.LDAP_DOMAIN
			search_target = 'DC=%s,%s' % (target_zone, dnsList.dnsroot)
			try:
				ldapConnection.search(
					search_base=search_target,
					search_filter=searchFilter,
					attributes=attributes
					)
			except Exception as e:
				print(search_target)
				print(searchFilter)
				print(e)

			result = list()

			excludeEntries = [
				'ForestDnsZones',
				'DomainDnsZones'
			]

			if not ldapConnection.response:
				raise exc_dns.DNSListEmpty

			record_id = 0
			for entry in ldapConnection.response:
				# Set Record Name
				record_index = 0
				record_name = entry['raw_attributes']['name'][0]
				record_name = record_name.decode('utf-8')
				orig_name = record_name
				if record_name != "@":
					record_name += "." + target_zone
				else:
					record_name = target_zone
				logger.debug(f'{__name__} [DEBUG] - {record_name}')

				# Set Record Data
				for record in entry['raw_attributes']['dnsRecord']:
					dr = dnstool.DNS_RECORD(record)
					record_dict = record_to_dict(dr, entry['attributes']['dNSTombstoned'])
					record_dict['id'] = record_id
					record_dict['record_bytes'] = str(record)
					record_dict['index'] = record_index
					record_dict['displayName'] = record_name
					record_dict['name'] = orig_name
					record_dict['ttl'] = dr.__getTTL__()
					record_dict['distinguishedName'] = entry['dn']
					logger.debug(f'{__name__} [DEBUG] - Record: {record_name}, Starts With Underscore: {record_name.startswith("_")}, Exclude Entry: {record_name in excludeEntries}')
					logger.debug(f'{__name__} [DEBUG] - {dr}')
					if not record_name.startswith("_") and orig_name not in excludeEntries:
						result.append(record_dict)
					record_id += 1
					record_index += 1

					for i in range(len(dnsZones)):
						zoneName = dnsZones[i]
						if zoneName == 'RootDNSServers':
							dnsZones[i] = "Root DNS Servers"

					if RunningSettings.LDAP_LOG_READ == True:
						# Log this action to DB
						DBLogMixin.log(
							user_id=request.user.id,
							actionType="READ",
							objectClass="DNSZ",
							affectedObject=target_zone
						)

					responseData['dnsZones'] = dnsZones
					responseData['forestZones'] = forestZones
					responseData['records'] = result
					responseData['legacy'] = RunningSettings.LDAP_DNS_LEGACY or False

		return Response(
			 data={
				'code': code,
				'code_msg': 'ok',
				'data' : responseData
			 }
		)

	@action(detail=False, methods=['post'])
	@auth_required()
	def insert(self, request):
		user = request.user
		data = dict()
		code = 0
		reqData = request.data
		result = dict()

		if 'dnsZone' not in reqData:
			raise exc_dns.DNSZoneNotInRequest
		else:
			target_zone = reqData['dnsZone'].lower()

		if domain_validator(target_zone) != True:
			data = {
				'dnsZone': target_zone
			}
			raise exc_dns.DNSFieldValidatorFailed(data=data)

		if target_zone == RunningSettings.LDAP_DOMAIN or target_zone == 'RootDNSServers':
			raise exc_dns.DNSZoneNotDeletable

		# Open LDAP Connection
		with LDAPConnector(user.dn, user.encryptedPassword, request.user) as ldc:
			ldapConnection = ldc.connection
			dnsList = LDAPDNS(ldapConnection)
			dnsZones = dnsList.dnszones
			forestZones = dnsList.forestzones

			if target_zone in dnsZones:
				raise exc_dns.DNSZoneExists

			zoneToCreate_dns = 'DC=%s,%s' % (target_zone, dnsList.dnsroot)
			zoneToCreate_forest = 'DC=_msdcs.%s,%s' % (target_zone, dnsList.forestroot)
			forest_dc = "_msdcs.%s" % (target_zone)

			attributes_dns = dict()
			attributes_dns['dc'] = target_zone

			attributes_forest = dict()
			attributes_forest['dc'] = forest_dc

			ldapConnection.add(dn=zoneToCreate_dns, object_class=[ 'dnsZone', 'top' ], attributes=attributes_dns)
			dnsCreateResult = ldapConnection.result

			ldapConnection.add(dn=zoneToCreate_forest, object_class=[ 'dnsZone', 'top' ], attributes=attributes_forest)
			forestCreateResult = ldapConnection.result

			currentLDAPServer = ldapConnection.server_pool.get_current_server(ldapConnection)
			currentLDAPServer_IP = currentLDAPServer.host
			
			# Create Start of Authority
			base_soaRecord = LDAPRecord(
				connection=ldapConnection, 
				rName="@", 
				rZone=target_zone,
				rType=DNS_RECORD_TYPE_SOA
			)
			values_soa = {
				'dwSerialNo': 1,
				'dwRefresh': 900,
				'dwRetry': 600,
				'dwExpire': 86400,
				'dwMinimumTtl': 900,
				'namePrimaryServer': f'ns.{target_zone}.',
				'zoneAdminEmail': f'hostmaster.{target_zone}'
			}
			base_soaRecord.create(values=values_soa)

			soaCreateResult = ldapConnection.result

			ipv4 = False
			ipv6 = False
			if ipv4_validator(currentLDAPServer_IP):
				ipv4 = True
			elif ipv6_validator(currentLDAPServer_IP):
				ipv6 = True

			# LDAP Server IP Address
			if ipv4:
				values_a = {
					'address': currentLDAPServer.host,
					'ttl': 900,
					'serial': 1
				}
				base_aRecord = LDAPRecord(
					connection=ldapConnection,
					rName="@",
					rZone=target_zone,
					rType=DNS_RECORD_TYPE_A
				)
				base_aRecord.create(values=values_a)

				aCreateResult = ldapConnection.result

				values_a_ns = {
					'address': currentLDAPServer.host,
					'ttl': 900,
					'serial': 1
				}
				a_nsRecord = LDAPRecord(
					connection=ldapConnection,
					rName="ns1",
					rZone=target_zone,
					rType=DNS_RECORD_TYPE_A
				)
				a_nsRecord.create(values=values_a_ns)

				a_nsCreateResult = ldapConnection.result
			elif ipv6:
				values_aaaa = {
					'address': currentLDAPServer.host,
					'ttl': 900,
					'serial': 1
				}
				base_aaaaRecord = LDAPRecord(
					connection=ldapConnection,
					rName="@",
					rZone=target_zone,
					rType=DNS_RECORD_TYPE_AAAA
				)
				base_aaaaRecord.create(values=values_aaaa)

				aaaaCreateResult = ldapConnection.result

				values_aaaa_ns = {
					'address': currentLDAPServer.host,
					'ttl': 900,
					'serial': 1
				}
				aaaa_nsRecord = LDAPRecord(
					connection=ldapConnection,
					rName="ns1",
					rZone=target_zone,
					rType=DNS_RECORD_TYPE_AAAA
				)
				aaaa_nsRecord.create(values=values_aaaa_ns)

				aaaa_nsCreateResult = ldapConnection.result

			values_ns = {
				'nameNode':f'ns1.{target_zone}.',
				'ttl': 3600,
				'serial': 1
			}
			base_nsRecord = LDAPRecord(
				connection=ldapConnection,
				rName="@",
				rZone=target_zone,
				rType=DNS_RECORD_TYPE_NS
			)
			base_nsRecord.create(values=values_ns)

			nsCreateResult = ldapConnection.result

			ldapConnection.unbind()

			result = {
				"dns": dnsCreateResult,
				"forest": forestCreateResult,
				"soa": soaCreateResult,
				"ns": nsCreateResult
			}

			if ipv4:
				result.update({
					"a_ns": a_nsCreateResult,
					"a": aCreateResult
				})
			elif ipv6:
				result.update({
					"aaaa_ns": aaaa_nsCreateResult,
					"aaaa": aaaaCreateResult
				})

			if RunningSettings.LDAP_LOG_CREATE == True:
				# Log this action to DB
				DBLogMixin.log(
					user_id=request.user.id,
					actionType="CREATE",
					objectClass="DNSZ",
					affectedObject=target_zone
				)

		return Response(
			 data={
				'code': code,
				'code_msg': 'ok',
				'result' : result
			 }
		)

	@action(detail=False, methods=['post'])
	@auth_required()
	def delete(self, request):
		user = request.user
		data = {}
		code = 0
		reqData = request.data
		dnsDeleteResult = None
		forestDeleteResult = None

		if 'dnsZone' not in reqData:
			raise exc_dns.DNSZoneNotInRequest
		else:
			target_zone = reqData['dnsZone'].lower()

		if domain_validator(target_zone) != True:
			data = {
				'dnsZone': target_zone
			}
			raise exc_dns.DNSFieldValidatorFailed(data=data)

		if target_zone == RunningSettings.LDAP_DOMAIN or target_zone == 'RootDNSServers':
			raise exc_dns.DNSZoneNotDeletable

		# Open LDAP Connection
		with LDAPConnector(user.dn, user.encryptedPassword, request.user) as ldc:
			ldapConnection = ldc.connection
			dnsList = LDAPDNS(ldapConnection)
			dnsZones = dnsList.dnszones
			forestZones = dnsList.forestzones

			if target_zone not in dnsZones:
				raise exc_dns.DNSZoneDoesNotExist

			zoneToCreate_dns = 'DC=%s,%s' % (target_zone, dnsList.dnsroot)
			zoneToCreate_forest = 'DC=_msdcs.%s,%s' % (target_zone, dnsList.forestroot)
			forest_dc = "_msdcs.%s" % (target_zone)

			attributes_dns = dict()
			attributes_dns['dc'] = target_zone

			attributes_forest = dict()
			attributes_forest['dc'] = forest_dc

			search_target = 'DC=%s,%s' % (target_zone, dnsList.dnsroot)
			searchFilter = search_filter_add("", "objectClass=dnsNode")
			attributes=['dnsRecord','dNSTombstoned','name']
			records = ldapConnection.extend.standard.paged_search(
				search_base=search_target,
				search_filter=searchFilter,
				search_scope='LEVEL',
				attributes=attributes
			)

			for r in list(records):
				ldapConnection.delete(r['dn'])

			ldapConnection.delete(dn=zoneToCreate_dns)
			dnsDeleteResult = ldapConnection.result

			ldapConnection.delete(dn=zoneToCreate_forest)
			forestDeleteResult = ldapConnection.result

			ldapConnection.unbind()

			if RunningSettings.LDAP_LOG_DELETE == True:
				# Log this action to DB
				DBLogMixin.log(
					user_id=request.user.id,
					actionType="DELETE",
					objectClass="DNSZ",
					affectedObject=target_zone
				)

		return Response(
			 data={
				'code': code,
				'code_msg': 'ok',
				'result' : {
					"dns": dnsDeleteResult,
					"forest": forestDeleteResult
				}
			 }
		)
