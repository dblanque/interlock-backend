################################## IMPORTS #####################################
### ViewSets
from core.views.base import BaseViewSet

### REST Framework
from rest_framework.response import Response

### Others
from core.decorators.login import auth_required, admin_required
import logging
################################################################################

################################# Test Imports #################################
from core.exceptions.ldap import CouldNotOpenConnection
from core.ldap.connector import LDAPConnector, LDAPInfo
from core.models.types.ldap_dns_record import *
from core.models import ldap_settings_runtime
from core.models.user import User
from interlock_backend.settings import LOG_FILE_FOLDER
################################################################################

logger = logging.getLogger(__name__)


class TestViewSet(BaseViewSet):  # pragma: no cover
	@auth_required
	@admin_required
	def list(self, request, pk=None):
		user: User = request.user
		data = {}
		code = 0
		printSettings = False

		if printSettings == True:
			for i in ldap_settings_runtime.__dict__:
				if not i.startswith("_"):
					value = getattr(ldap_settings_runtime, i)
					print(f"{i} ({type(value)}): {value}")

		# Open LDAP Connection
		ldap_result = None
		try:
			with LDAPConnector(force_admin=True) as ldc:
				ldap_server = ldc.connection.server_pool.get_current_server(
					ldc.connection
				)
				ldap_result = ldc.connection.result
		except Exception as e:
			print(e)
			raise CouldNotOpenConnection

		try:
			with LDAPInfo(force_admin=True) as ldap_info:
				CONNECTION_OPEN = True if ldap_info.connection.bound else False
				with open(f"{LOG_FILE_FOLDER}/test.log", "w") as f:
					print(ldap_info)
					if hasattr(ldap_info, "schema") and ldap_info.schema:
						f.write(ldap_info.schema.to_json())
					f.close()
			CONNECTION_CLOSED = (
				True if not ldap_info.connection.bound else False
			)
		except:
			logger.warning("LDAP Connector Debugging could not log schema.")
			pass
		return Response(
			data={
				"code": code,
				"code_msg": "ok",
				"data": ldap_result,
				"active_server": ldap_server.host,
				"connection_open_success": CONNECTION_OPEN,
				"connection_close_success": CONNECTION_CLOSED,
			}
		)
