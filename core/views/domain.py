################################## IMPORTS #####################################
### ViewSets
from email import header
from core.views.base import BaseViewSet

### Exceptions
from django.core.exceptions import PermissionDenied
from core.exceptions import (
    ldap as exc_ldap,
)

### Mixins
from .mixins.domain import DomainViewMixin

### REST Framework
from rest_framework.response import Response
from rest_framework.exceptions import NotFound
from rest_framework.decorators import action

### Others
from interlock_backend.ldap.adsi import addSearchFilter
from interlock_backend.ldap.encrypt import validateUser
from interlock_backend.ldap.settings_func import SettingsList
from interlock_backend.ldap.connector import LDAPConnector
from core.utils import dnstool
from core.models.dns import LDAPDNS, record_to_dict
import logging
################################################################################

logger = logging.getLogger(__name__)

class DomainViewSet(BaseViewSet, DomainViewMixin):

    @action(detail=False, methods=['get'])
    def details(self, request):
        user = request.user
        validateUser(request=request, requestUser=user, requireAdmin=False)
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
        validateUser(request=request, requestUser=user, requireAdmin=False)
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
            'name',
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
                record_dict['name'] = record_name
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
