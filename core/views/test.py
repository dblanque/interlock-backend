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

        rType = DNS_RECORD_TYPE_TXT
        values = {
            # 'address': '10.10.10.202',
            # 'nameNode': 'front.brconsulting.info.',
            'stringData': '"v=spf1 mx a ip4:190.183.222.180 ip4:190.183.222.179 ip4:190.183.222.178 ~all"'
        }

        dnsRecord = LDAPRecord(
            connection=ldapConnection, 
            rName="pepe", 
            rZone="brconsulting.info",
            rType=rType
        )
        print(dnsRecord.create(values=values))

        ldapConnection.unbind()
        return Response(
             data={
                'code': code,
                'code_msg': 'ok',
                'data' : ldapConnection.result
             }
        )
