################################## IMPORTS #####################################
### Exceptions
from core.exceptions.test import TestError

### ViewSets
import dns
import ldap3
from core.views.base import BaseViewSet

### REST Framework
from rest_framework.response import Response
from rest_framework.decorators import action

### Others
from interlock_backend.ldap.encrypt import validateUser
import logging
import json
################################################################################

################################# Test Imports #################################
from core.views.mixins.group import GroupViewMixin
from core.exceptions.ldap import CouldNotOpenConnection
from core.exceptions import dns as exc_dns
from interlock_backend.ldap.connector import LDAPConnector, LDAPInfo
from interlock_backend.ldap.adsi import addSearchFilter, buildFilterFromDict
from interlock_backend.ldap.settings_func import SettingsList
from core.utils import dnstool
from core.utils.dnstool import record_to_dict, RECORD_MAPPINGS
from core.models.dnsRecordTypes import *
from core.models.dns import LDAPDNS, LDAPRecord
################################################################################

logger = logging.getLogger(__name__)

class TestViewSet(BaseViewSet):

    def list(self, request, pk=None):
        user = request.user
        validateUser(request=request)
        data = {}
        code = 0

        ######################## Get Latest Settings ###########################
        ldap_settings_list = SettingsList(**{"search":{
            'LDAP_DOMAIN',
            'LDAP_AUTH_USERNAME_IDENTIFIER',
            'LDAP_AUTH_OBJECT_CLASS',
            'LDAP_AUTH_SEARCH_BASE',
            'LDAP_LOG_READ'
        }})

        # Open LDAP Connection
        try:
            connector = LDAPConnector()
            ldapConnection = connector.connection
        except Exception as e:
            print(e)
            raise CouldNotOpenConnection

        ### DNS RECORD TEST

        dnsList = LDAPDNS(ldapConnection)
        dnsZones = dnsList.dnszones
        forestZones = dnsList.forestzones

        currentLDAPServer = ldapConnection.server_pool.get_current_server(ldapConnection)
        print(currentLDAPServer.host)
        # testRecord = "A"
        # values_soa = {
        #     # SOA TEST
        #     'dwSerialNo': 82,
        #     'dwRefresh': 900,
        #     'dwRetry': 600,
        #     'dwExpire': 86400,
        #     'dwMinimumTtl': 3600,
        #     'namePrimaryServer': 'vm113-ldap.brconsulting.info.',
        #     'zoneAdminEmail': 'dylan.brconsulting.info.'
        # }
        # values_a = {
        #     # A TEST
        #     'address': '10.10.10.1',
        #     'ttl': 900,
        #     'serial': 1
        # }
        # values_txt = {
        #     # TXT TEST
        #     'stringData': '"v=spf1 mx a ip4:190.183.222.180 ip4:190.183.222.179 ip4:190.183.222.178 ~all"'
        # }
        # values_cname = {
        #     # CNAME TEST
        #     'nameNode': 'front.brconsulting.info.',
        # }
        # values_mx = {
        #     # MX TEST
        #     'wPreference': 10,
        #     'nameExchange': 'front.brconsulting.info.',
        # }
        # values_srv = {
        #     # SRV TEST
        #     'wPriority': 10,
        #     'wWeight': 5,
        #     'wPort': 3306,
        #     'nameTarget': 'psql.brconsulting.info.',
        # }

        # if testRecord == 'A' or testRecord == 'ALL':
        #     dnsRecord = LDAPRecord(
        #         connection=ldapConnection,
        #         rName="@",
        #         rZone="brconsulting.info",
        #         rType=DNS_RECORD_TYPE_A
        #     )
        #     print(dnsRecord.create(values=values_a, debugMode=True))

        # if testRecord == 'CNAME' or testRecord == 'ALL':
        #     dnsRecord = LDAPRecord(
        #         connection=ldapConnection, 
        #         rName="javier", 
        #         rZone="brconsulting.info",
        #         rType=DNS_RECORD_TYPE_CNAME
        #     )
        #     print(dnsRecord.create(values=values_cname, debugMode=True))

        # if testRecord == 'MX' or testRecord == 'ALL':
        #     dnsRecord = LDAPRecord(
        #         connection=ldapConnection, 
        #         rName="mail", 
        #         rZone="brconsulting.info",
        #         rType=DNS_RECORD_TYPE_MX
        #     )
        #     print(dnsRecord.create(values=values_mx, debugMode=True))

        # if testRecord == 'TXT' or testRecord == 'ALL':
        #     dnsRecord = LDAPRecord(
        #         connection=ldapConnection, 
        #         rName="@", 
        #         rZone="brconsulting.info",
        #         rType=DNS_RECORD_TYPE_TXT
        #     )
        #     print(dnsRecord.create(values=values_txt, debugMode=True))

        # if testRecord == 'SOA' or testRecord == 'ALL':
        #     dnsRecord = LDAPRecord(
        #         connection=ldapConnection, 
        #         rName="@", 
        #         rZone="brconsulting.info",
        #         rType=DNS_RECORD_TYPE_SOA
        #     )
        #     print(dnsRecord.create(values=values_soa, debugMode=True))

        # if testRecord == 'SRV' or testRecord == 'ALL':
        #     dnsRecord = LDAPRecord(
        #         connection=ldapConnection, 
        #         rName="@", 
        #         rZone="brconsulting.info",
        #         rType=DNS_RECORD_TYPE_SRV
        #     )
        #     print(dnsRecord.create(values=values_srv, debugMode=True))

        ###

        ldapConnection.unbind()
        return Response(
             data={
                'code': code,
                'code_msg': 'ok',
                'data' : ldapConnection.result
             }
        )
