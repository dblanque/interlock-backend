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
################################################################################

logger = logging.getLogger(__name__)

class TestViewSet(BaseViewSet):

    def list(self, request, pk=None):
        user = request.user
        validateUser(request=request, requestUser=user)
        data = {}
        code = 0

        dnsServer = "10.10.10.1"
        queryZone = "brconsulting.info"
        # entry = dnsEntry(
        #             dnsAddresses=dnsServer,
        #             dnsZone=queryZone,
        #             queryString="pfsenseborde"
        #         )

        # answer = entry.query().__dict__
        # for i in answer:
        #     print(answer[i])

        # zone = dnsZone(dnsZone=queryZone)

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
            connector = LDAPInfo()
            ldapConnection = connector.connection
        except Exception as e:
            print(e)
            raise CouldNotOpenConnection

        try:
            print(connector.get_domain_root())
            print(connector.get_forest_root())
        except:
            raise TestError

        # ldapConnection.search(
        #     search_base=ldap_settings_list.LDAP_AUTH_SEARCH_BASE,
        #     search_filter=searchFilter,
        #     search_scope=ldap3.LEVEL,
        #     attributes=['dc']
        #     )

        # print(ldapConnection.response)

        ldapConnection.unbind()
        return Response(
             data={
                'code': code,
                'code_msg': 'ok',
                'data' : ldapConnection.result
             }
        )
