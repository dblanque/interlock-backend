################################## IMPORTS #####################################
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
from core.exceptions.ldap import CouldNotOpenConnection
from interlock_backend.ldap.connector import LDAPConnector
from interlock_backend.ldap.adsi import addSearchFilter, buildFilterFromDict
from interlock_backend.ldap.settings_func import SettingsList
from dns import (
    query as dnsQuery,
    update as dnsUpdate,
    zone as dnsZone,
    xfr as dnsXfr,
    ipv4,
    message as dnsMessage,
    name as dnsName,
    rdatatype,
    rdataclass,
    resolver as dnsResolver
)
import dns
################################################################################

logger = logging.getLogger(__name__)

class TestViewSet(BaseViewSet):

    def list(self, request, pk=None):
        user = request.user
        validateUser(request=request, requestUser=user)
        data = {}
        code = 0

        ######################## Get Latest Settings ###########################
        ldap_settings_list = SettingsList(**{"search":{
            'LDAP_AUTH_USERNAME_IDENTIFIER',
            'LDAP_AUTH_OBJECT_CLASS',
            'LDAP_AUTH_SEARCH_BASE',
            'LDAP_LOG_READ'
        }})

        # Open LDAP Connection
        try:
            ldapConnection = LDAPConnector(user.dn, user.encryptedPassword, request.user).connection
        except Exception as e:
            print(e)
            raise CouldNotOpenConnection

        ldapConnection.search(
            ldap_settings_list.LDAP_AUTH_SEARCH_BASE,
            search_filter="(objectClass=group)",
            search_scope=ldap3.SUBTREE,
            attributes=ldap3.ALL_ATTRIBUTES,
        )

        print(ldapConnection.result)

        # domain = 'brconsulting.info'
        # dns_zone = domain + "."
        # qname = dnsName.from_text("brconsulting.info")
        # query = dnsMessage.make_query(qname=qname, rdtype=rdatatype.A)
        # result = dnsQuery.udp(query, "10.10.10.13")
        # print(result)

        ldapConnection.unbind()
        return Response(
             data={
                'code': code,
                'code_msg': 'ok',
                'data' : data
             }
        )
