################################## IMPORTS #####################################
### ViewSets
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
from core.models.ldapTree import LDAPTree
from core.exceptions.ldap import CouldNotOpenConnection
from interlock_backend.ldap.connector import openLDAPConnection
################################################################################

logger = logging.getLogger(__name__)

class TestViewSet(BaseViewSet):

    def list(self, request, pk=None):
        user = request.user
        validateUser(request=request, requestUser=user)
        data = {}
        code = 0

        # Open LDAP Connection
        try:
            ldapConnection = openLDAPConnection(user.dn, user.encryptedPassword, request.user)
        except Exception as e:
            print(e)
            raise CouldNotOpenConnection

        ldapTree = LDAPTree(**{
            "connection": ldapConnection,
            "recursive": True,
            "ldapAttributes": [ 'dn' ],
            "testFetch": True
        })
        # print(json.dumps(ldapTree.children[0], indent=1))
        # print(ldapTree.children)
        # print(ldapTree.__getTreeCount__())

        ldapConnection.unbind()
        return Response(
             data={
                'code': code,
                'code_msg': 'ok',
                'data' : ldapTree.children
             }
        )
