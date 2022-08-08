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
from interlock_backend.ldap.connector import LDAPConnector, LDAPInfo
from interlock_backend.ldap.adsi import addSearchFilter, buildFilterFromDict
from interlock_backend.ldap.settings_func import SettingsList
from core.utils import dnstool
from core.models.dns import LDAPDNS, record_to_dict
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

        # try:
        #     print(connector.get_domain_root())
        #     print(connector.get_forest_root())
        # except:
        #     raise TestError

        searchFilter = addSearchFilter("", "objectClass=dnsNode")
        attributes=['dnsRecord','dNSTombstoned','name']

        dnsList = LDAPDNS(ldapConnection)

        print(dnsList.dnsroot)
        print(dnsList.forestroot)
        print(dnsList.list_dns_zones())
        print(dnsList.list_forest_zones())

        search_target = 'DC=%s,%s' % ("brconsulting.info", dnsList.dnsroot)
        ldapConnection.search(
            search_base=search_target,
            search_filter=searchFilter,
            attributes=attributes
        )

        for entry in ldapConnection.response:
            for record in entry['raw_attributes']['dnsRecord']:
                dr = dnstool.DNS_RECORD(record)
                result = record_to_dict(dr, entry['attributes']['dNSTombstoned'])
                print(result)

        ldapConnection.unbind()
        return Response(
             data={
                'code': code,
                'code_msg': 'ok',
                'data' : ldapConnection.result
             }
        )
