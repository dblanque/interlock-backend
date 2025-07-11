################################## IMPORTS #####################################
### ViewSets
from core.views.base import BaseViewSet

### REST Framework
from rest_framework.response import Response

### Models
from core.models.user import User, USER_TYPE_LDAP, USER_TYPE_LOCAL
from core.ldap.connector import LDAPConnector
from ldap3 import Server, ServerPool
from core.models.interlock_settings import (
	InterlockSetting,
	INTERLOCK_SETTING_ENABLE_LDAP,
)

### Auth
from core.decorators.login import auth_required, admin_required

### Others
from oidc_provider.views import ProviderInfoView
import logging
from django.core.exceptions import ObjectDoesNotExist
################################################################################

logger = logging.getLogger(__name__)


class HomeViewSet(BaseViewSet):
	@auth_required
	@admin_required
	def list(self, request):
		user: User = request.user
		code = 0
		local_user_count = User.objects.filter(
			user_type=USER_TYPE_LOCAL
		).count()
		ldap_user_count = 0
		oidc_well_known_info = ProviderInfoView()._build_response_dict(
			request=request
		)

		# Check if LDAP Enabled
		ldap_enabled = False
		try:
			ldap_enabled = InterlockSetting.objects.get(
				name=INTERLOCK_SETTING_ENABLE_LDAP
			)
			ldap_enabled = ldap_enabled.value
		except ObjectDoesNotExist:
			pass

		if ldap_enabled:
			ldap_user_count = User.objects.filter(
				user_type=USER_TYPE_LDAP
			).count()

		# Check LDAP Backend status
		ldap_ok = False
		ldap_server = None
		ldap_ssl = False
		ldap_tls = False
		if ldap_enabled:
			try:
				with LDAPConnector(user=user) as ldc:
					is_bound = ldc.connection.bound
					CONNECTION_OPEN = True if is_bound is True else False
					ldap_server_pool: ServerPool = ldc.connection.server_pool
					ldap_server: Server = ldap_server_pool.get_current_server(
						ldc.connection
					)
					if ldap_server.name.startswith("ldaps"):
						ldap_tls = True
					ldap_ssl = ldap_server.ssl
					ldap_server = ldap_server.host

				is_bound = ldc.connection.bound
				CONNECTION_CLOSED = True if is_bound is not True else False
				if CONNECTION_OPEN and CONNECTION_CLOSED:
					ldap_ok = True
			except:
				pass
		return Response(
			data={
				"code": code,
				"code_msg": "ok",
				"data": {
					"local_user_count": local_user_count,
					"oidc_well_known": oidc_well_known_info,
					"ldap_user_count": ldap_user_count,
					"ldap_enabled": ldap_enabled,
					"ldap_tls": ldap_tls,
					"ldap_ssl": ldap_ssl,
					"ldap_ok": ldap_ok,
					"ldap_active_server": ldap_server,
				},
			}
		)
