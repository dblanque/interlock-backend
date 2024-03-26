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
from core.models import ldap_settings_db
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
			for i in ldap_settings_db.__dict__:
				if not i.startswith("_"):
					value = getattr(ldap_settings_db, i)
					print(f"{i} ({type(value)}): {value}")

		# Open LDAP Connection
		try:
			connector = LDAPConnector(force_admin=True)
			self.ldap_connection = connector.connection
		except Exception as e:
			print(e)
			raise CouldNotOpenConnection

		ldap_server = self.ldap_connection.server_pool.get_current_server(self.ldap_connection)

		with LDAPInfo(force_admin=True) as ldap_info:
			CONNECTION_OPEN = True if ldap_info.connection.bound else False
			with open(f"{LOG_FILE_FOLDER}/test.log", "w") as f:
				print(ldap_info)
				if hasattr(ldap_info, "schema") and ldap_info.schema:
					f.write(ldap_info.schema.to_json())
				f.close()
		CONNECTION_CLOSED = True if not ldap_info.connection.bound else False
		return Response(
			 data={
				'code': code,
				'code_msg': 'ok',
				'data' : self.ldap_connection.result,
				'active_server': ldap_server.host,
				'connection_open_success': CONNECTION_OPEN,
				'connection_close_success': CONNECTION_CLOSED,
			 }
		)
