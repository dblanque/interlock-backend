################################## IMPORTS #####################################
### Exceptions
from core.exceptions.test import TestError

### ViewSets
from core.views.base import BaseViewSet

### REST Framework
from rest_framework.response import Response
from rest_framework.decorators import action

### Others
from core.decorators.login import auth_required
import logging
################################################################################

################################# Test Imports #################################
from core.exceptions.ldap import CouldNotOpenConnection
from interlock_backend.ldap.connector import LDAPConnector, LDAPInfo
from core.models.dnsRecordTypes import *
from interlock_backend.ldap import constants_cache
from interlock_backend.settings import LOG_FILE_FOLDER
################################################################################

logger = logging.getLogger(__name__)

class TestViewSet(BaseViewSet):

	@auth_required()
	def list(self, request, pk=None):
		user = request.user
		data = {}
		code = 0
		printSettings = False

		if printSettings == True:
			for i in constants_cache.__dict__:
				if not i.startswith("_"):
					value = getattr(constants_cache, i)
					print(f"{i} ({type(value)}): {value}")

		# Open LDAP Connection
		try:
			connector = LDAPConnector(force_admin=True)
			self.ldap_connection = connector.connection
		except Exception as e:
			print(e)
			raise CouldNotOpenConnection

		ldap_server = self.ldap_connection.server_pool.get_current_server(self.ldap_connection)

		ldap_info = LDAPInfo(force_admin=True)
		with open(f"{LOG_FILE_FOLDER}/test.log", "w") as f:
			print(ldap_info.schema.to_json(), file=f)
			f.close()

		self.ldap_connection.unbind()
		return Response(
			 data={
				'code': code,
				'code_msg': 'ok',
				'data' : self.ldap_connection.result,
				'active_server': ldap_server.host
			 }
		)
