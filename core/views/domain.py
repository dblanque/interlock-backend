################################################################################
#################### INTERLOCK IS LICENSED UNDER GNU GPLv3 #####################
################## ORIGINAL PROJECT CREATED BY DYLAN BLANQUÉ ###################
########################## AND BR CONSULTING S.R.L. ############################
################################################################################
# Module: core.views.domain
# Contains the ViewSet for Domain related operations

#---------------------------------- IMPORTS -----------------------------------#
### Models
from core.models.log import logToDB
from core.models.dns import LDAPDNS

### ViewSets
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
from core.models.dnsRecordFieldValidators import domain_validator
from core.utils import dnstool
from core.utils.dnstool import record_to_dict
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
            'value',
            'ttl',
            'typeName',
            'serial',
            # 'ts',
        ]

        searchFilter = addSearchFilter("", "objectClass=dnsNode")
        attributes=['dnsRecord','dNSTombstoned','name']

        dnsList = LDAPDNS(ldapConnection)
        dnsZones = dnsList.dnszones
        forestZones = dnsList.forestzones

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
            logger.info(record_name)

            # Set Record Data
            for record in entry['raw_attributes']['dnsRecord']:
                dr = dnstool.DNS_RECORD(record)
                logger.info(dr)
                record_dict = record_to_dict(dr, entry['attributes']['dNSTombstoned'])
                record_dict['id'] = record_id
                record_dict['record_bytes'] = str(record)
                record_dict['index'] = record_index
                record_dict['displayName'] = record_name
                record_dict['name'] = orig_name
                record_dict['ttl'] = dr.__getTTL__()
                record_dict['distinguishedName'] = entry['dn']
                logger.debug('Record: %s, Starts With Underscore: %s, Exclude Entry: %s' % (record_name, record_name.startswith("_"), record_name in excludeEntries))
                if not record_name.startswith("_") and orig_name not in excludeEntries:
                    result.append(record_dict)
                record_id += 1
                record_index += 1

        ldapConnection.unbind()

        for i in range(len(dnsZones)):
            zoneName = dnsZones[i]
            if zoneName == 'RootDNSServers':
                dnsZones[i] = "Root DNS Servers"

        if ldap_settings_list.LDAP_LOG_READ == True:
            # Log this action to DB
            logToDB(
                user_id=request.user.id,
                actionType="READ",
                objectClass="DNSZ",
                affectedObject=target_zone
            )

        responseData['dnsZones'] = dnsZones
        responseData['forestZones'] = forestZones
        responseData['records'] = result

        return Response(
             data={
                'code': code,
                'code_msg': 'ok',
                'data' : responseData
             }
        )

    @action(detail=False, methods=['post'])
    def insert(self, request):
        user = request.user
        validateUser(request=request)
        data = {}
        code = 0

        reqData = request.data

        if 'dnsZone' not in reqData:
            raise exc_dns.DNSZoneNotInRequest
        else:
            target_zone = reqData['dnsZone'].lower()

        if domain_validator(target_zone) != True:
            data = {
                'dnsZone': target_zone
            }
            raise exc_dns.DNSFieldValidatorFailed(data=data)

        ######################## Get Latest Settings ###########################
        ldap_settings_list = SettingsList(**{"search":{
            'LDAP_DOMAIN',
            'LDAP_AUTH_SEARCH_BASE',
            'LDAP_LOG_CREATE'
        }})

        if target_zone == ldap_settings_list.LDAP_DOMAIN or target_zone == 'RootDNSServers':
            raise exc_dns.DNSZoneNotDeletable

        # Open LDAP Connection
        try:
            connector = LDAPConnector(user.dn, user.encryptedPassword, request.user)
            ldapConnection = connector.connection
        except Exception as e:
            print(e)
            raise exc_ldap.CouldNotOpenConnection

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

        ldapConnection.unbind()

        if ldap_settings_list.LDAP_LOG_CREATE == True:
            # Log this action to DB
            logToDB(
                user_id=request.user.id,
                actionType="CREATE",
                objectClass="DNSZ",
                affectedObject=target_zone
            )

        return Response(
             data={
                'code': code,
                'code_msg': 'ok',
                'result' : {
                    "dns": dnsCreateResult,
                    "forest": forestCreateResult
                }
             }
        )

    @action(detail=False, methods=['post'])
    def delete(self, request):
        user = request.user
        validateUser(request=request)
        data = {}
        code = 0

        reqData = request.data

        if 'dnsZone' not in reqData:
            raise exc_dns.DNSZoneNotInRequest
        else:
            target_zone = reqData['dnsZone'].lower()

        if domain_validator(target_zone) != True:
            data = {
                'dnsZone': target_zone
            }
            raise exc_dns.DNSFieldValidatorFailed(data=data)

        ######################## Get Latest Settings ###########################
        ldap_settings_list = SettingsList(**{"search":{
            'LDAP_DOMAIN',
            'LDAP_AUTH_SEARCH_BASE',
            'LDAP_LOG_DELETE'
        }})

        if target_zone == ldap_settings_list.LDAP_DOMAIN or target_zone == 'RootDNSServers':
            raise exc_dns.DNSZoneNotDeletable

        # Open LDAP Connection
        try:
            connector = LDAPConnector(user.dn, user.encryptedPassword, request.user)
            ldapConnection = connector.connection
        except Exception as e:
            print(e)
            raise exc_ldap.CouldNotOpenConnection

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

        ldapConnection.delete(dn=zoneToCreate_dns)
        dnsDeleteResult = ldapConnection.result

        ldapConnection.delete(dn=zoneToCreate_forest)
        forestDeleteResult = ldapConnection.result

        ldapConnection.unbind()

        if ldap_settings_list.LDAP_LOG_DELETE == True:
            # Log this action to DB
            logToDB(
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
