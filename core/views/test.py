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
from interlock_backend.ldap.encrypt import validate_request_user
import logging
import json
################################################################################

################################# Test Imports #################################
from core.views.mixins.group import GroupViewMixin
from core.exceptions.ldap import CouldNotOpenConnection
from core.exceptions import dns as exc_dns
from interlock_backend.ldap.connector import LDAPConnector, LDAPInfo
from interlock_backend.ldap.adsi import search_filter_add, search_filter_from_dict
from core.utils import dnstool
from core.utils.dnstool import record_to_dict, RECORD_MAPPINGS
from core.models.dnsRecordTypes import *
from core.models.dns import LDAPDNS, LDAPRecord
from interlock_backend.ldap import constants_cache
################################################################################

logger = logging.getLogger(__name__)

class TestViewSet(BaseViewSet):

    def list(self, request, pk=None):
        user = request.user
        validate_request_user(request=request)
        data = {}
        code = 0
        printSettings = False

        if printSettings == True:
            for i in constants_cache.__dict__:
                if not i.startswith("_"):
                    value = getattr(constants_cache, i)
                    print("%s (%s): %s" % (i, type(value), value))

        # Open LDAP Connection
        try:
            connector = LDAPConnector()
            ldapConnection = connector.connection
        except Exception as e:
            print(e)
            raise CouldNotOpenConnection


        currentLDAPServer = ldapConnection.server_pool.get_current_server(ldapConnection)

        ldapConnection.unbind()
        return Response(
             data={
                'code': code,
                'code_msg': 'ok',
                'data' : ldapConnection.result,
                'active_server': currentLDAPServer.host
             }
        )
