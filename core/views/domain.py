################################## IMPORTS #####################################
### Models
from core.models.log import logToDB
from core.models.dns import LDAPDNS, record_to_dict

### ViewSets
from email import header
from core.views.base import BaseViewSet

### Exceptions
from django.core.exceptions import PermissionDenied
from core.exceptions import (
    ldap as exc_ldap,
    dns as exc_dns
)

### Mixins
from .mixins.domain import DomainViewMixin

### REST Framework
from rest_framework.response import Response
from rest_framework.exceptions import NotFound
from rest_framework.decorators import action

### Others
from core.utils import dnstool
from interlock_backend.ldap.adsi import addSearchFilter
from interlock_backend.ldap.encrypt import validateUser
from interlock_backend.ldap.settings_func import SettingsList
from interlock_backend.ldap.connector import LDAPConnector
import logging
################################################################################

logger = logging.getLogger(__name__)

class DomainViewSet(BaseViewSet, DomainViewMixin):

    @action(detail=False, methods=['get'])
    def details(self, request):
        user = request.user
        validateUser(request=request, requireAdmin=False)
        data = {}
        code = 0
        ldap_settings_list = SettingsList(**{"search":{'LDAP_AUTH_ACTIVE_DIRECTORY_DOMAIN', 'LDAP_DOMAIN', 'LDAP_AUTH_SEARCH_BASE'}})
        data["realm"] = ldap_settings_list.LDAP_AUTH_ACTIVE_DIRECTORY_DOMAIN or ""
        data["name"] = ldap_settings_list.LDAP_DOMAIN or ""
        data["basedn"] = ldap_settings_list.LDAP_AUTH_SEARCH_BASE or ""
        return Response(
             data={
                'code': code,
                'code_msg': 'ok',
                'details': data
             }
        )

    @action(detail=False, methods=['post'])
    def zones(self, request):
        user = request.user
        validateUser(request=request)
        data = {}
        code = 0

        reqData = request.data

        if 'filter' in reqData:
            if 'dnsZone' in reqData['filter']:
                zoneFilter = str(reqData['filter']['dnsZone']).replace(" ", "")

        if zoneFilter is not None:
            if zoneFilter == "" or len(zoneFilter) == 0:
                zoneFilter = None

        ######################## Get Latest Settings ###########################
        ldap_settings_list = SettingsList(**{"search":{
            'LDAP_DOMAIN',
            'LDAP_AUTH_SEARCH_BASE',
            'LDAP_LOG_READ'
        }})

        # Open LDAP Connection
        try:
            connector = LDAPConnector(user.dn, user.encryptedPassword, request.user)
            ldapConnection = connector.connection
        except Exception as e:
            print(e)
            raise exc_ldap.CouldNotOpenConnection

        responseData = {}

        responseData['headers'] = [
            'displayName', # Custom Header, attr not in LDAP
            # 'name',
            'address',
            'typeName',
            'serial',
            'ts',
            # 'nameTarget',
            # 'type',
            # 'tstime',
            # 'wPriority',
            # 'wWeight',
            # 'wPort',
            # 'dwSerialNo',
            # 'dwRefresh',
            # 'dwRetry',
            # 'dwExpire',
            # 'dwMinimumTtl',
            # 'namePrimaryServer',
            # 'zoneAdminEmail',
        ]

        searchFilter = addSearchFilter("", "objectClass=dnsNode")
        attributes=['dnsRecord','dNSTombstoned','name']

        dnsList = LDAPDNS(ldapConnection)
        dnsZones = dnsList.list_dns_zones()
        forestZones = dnsList.list_forest_zones()

        if zoneFilter is not None:
            target_zone = zoneFilter
        else:
            target_zone = ldap_settings_list.LDAP_DOMAIN
        search_target = 'DC=%s,%s' % (target_zone, dnsList.dnsroot)
        ldapConnection.search(
            search_base=search_target,
            search_filter=searchFilter,
            attributes=attributes
            )

        result = list()

        excludeEntries = [
            'ForestDnsZones',
            'DomainDnsZones'
        ]

        for entry in ldapConnection.response:
            # Set Record Name
            record_name = entry['raw_attributes']['name'][0]
            record_name = str(record_name)[2:-1]
            orig_name = record_name
            if record_name != "@":
                record_name += "." + target_zone
            else:
                record_name = target_zone
            logger.info(record_name)

            # Set Record Data
            for record in entry['raw_attributes']['dnsRecord']:
                dr = dnstool.DNS_RECORD(record)
                logger.info(dr)
                record_dict = record_to_dict(dr, entry['attributes']['dNSTombstoned'])
                record_dict['displayName'] = record_name
                record_dict['name'] = orig_name
                record_dict['distinguishedName'] = entry['dn']
                logger.debug('Record: %s, Starts With Underscore: %s, Exclude Entry: %s' % (record_name, record_name.startswith("_"), record_name in excludeEntries))
                if not record_name.startswith("_") and orig_name not in excludeEntries:
                    result.append(record_dict)

        ldapConnection.unbind()

        cleanDnsZones = list()
        c = 0
        for i in dnsZones:
            zoneName = dnsZones[c][0]
            if zoneName == 'RootDNSServers':
                cleanDnsZones.append("Root DNS Servers")
            else:
                cleanDnsZones.append(dnsZones[c][0])
            c += 1

        if ldap_settings_list.LDAP_LOG_READ == True:
            # Log this action to DB
            logToDB(
                user_id=request.user.id,
                actionType="READ",
                objectClass="DNSZ",
                affectedObject=target_zone
            )

        responseData['dnsZones'] = cleanDnsZones
        responseData['forestZones'] = forestZones
        responseData['records'] = result

        return Response(
             data={
                'code': code,
                'code_msg': 'ok',
                'data' : responseData
             }
        )

    # @action(detail=False, methods=['post'])
    # def insert(self, request):
    #     user = request.user
    #     validateUser(request=request)
    #     data = {}
    #     code = 0

    #     reqData = request.data

    #     if 'record' in reqData:
    #         if 'distinguishedName' in reqData['record']:
    #             recordToSearch = reqData['record']['distinguishedName']
    #             target_zone = recordToSearch.split(",")[1].replace("DC=", "")
    #         else:
    #             raise exc_dns.DistinguishedNameNotInDNSRecord
    #     else:
    #         raise exc_dns.DNSRecordNotInRequest

    #     ######################## Get Latest Settings ###########################
    #     ldap_settings_list = SettingsList(**{"search":{
    #         'LDAP_DOMAIN',
    #         'LDAP_AUTH_SEARCH_BASE',
    #         'LDAP_LOG_READ'
    #     }})

    #     # Open LDAP Connection
    #     try:
    #         connector = LDAPConnector(user.dn, user.encryptedPassword, request.user)
    #         ldapConnection = connector.connection
    #     except Exception as e:
    #         print(e)
    #         raise exc_ldap.CouldNotOpenConnection

    #     responseData = dict()

    #     searchFilter = addSearchFilter("", "objectClass=dnsNode")
    #     attributes=['dnsRecord','dNSTombstoned','name']

    #     dnsList = LDAPDNS(ldapConnection)
    #     dnsZones = dnsList.list_dns_zones()
    #     forestZones = dnsList.list_forest_zones()

    #     search_target = recordToSearch
    #     ldapConnection.search(
    #         search_base=search_target,
    #         search_filter=searchFilter,
    #         attributes=attributes
    #         )

    #     result = list()

    #     excludeEntries = [
    #         'ForestDnsZones',
    #         'DomainDnsZones'
    #     ]
    #     recordObject = ldapConnection.response[0]

    #     # Set Record Name
    #     record_name = recordObject['raw_attributes']['name'][0]
    #     record_name = str(record_name)[2:-1]
    #     orig_name = record_name
    #     if record_name != "@":
    #         record_name += "." + target_zone
    #     else:
    #         record_name = target_zone
    #     logger.info(record_name)

    #     # Set Record Data
    #     for record in recordObject['raw_attributes']['dnsRecord']:
    #         dr = dnstool.DNS_RECORD(record)
    #         logger.info(dr)
    #         record_dict = record_to_dict(dr, recordObject['attributes']['dNSTombstoned'])
    #         record_dict['displayName'] = record_name
    #         record_dict['name'] = orig_name
    #         record_dict['distinguishedName'] = recordObject['dn']
    #         logger.debug('Record: %s, Starts With Underscore: %s, Exclude Entry: %s' % (record_name, record_name.startswith("_"), record_name in excludeEntries))
    #         if not record_name.startswith("_") and orig_name not in excludeEntries:
    #             result.append(record_dict)

    #     ldapConnection.unbind()

    #     cleanDnsZones = list()
    #     c = 0
    #     for i in dnsZones:
    #         zoneName = dnsZones[c][0]
    #         if zoneName == 'RootDNSServers':
    #             cleanDnsZones.append("Root DNS Servers")
    #         else:
    #             cleanDnsZones.append(dnsZones[c][0])
    #         c += 1

    #     if ldap_settings_list.LDAP_LOG_READ == True:
    #         # Log this action to DB
    #         logToDB(
    #             user_id=request.user.id,
    #             actionType="READ",
    #             objectClass="DNSZ",
    #             affectedObject=target_zone
    #         )

    #     responseData['dnsZones'] = cleanDnsZones
    #     responseData['forestZones'] = forestZones
    #     responseData['records'] = result

    #     return Response(
    #          data={
    #             'code': code,
    #             'code_msg': 'ok',
    #             'data' : responseData
    #          }
    #     )
