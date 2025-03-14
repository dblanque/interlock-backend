################################## IMPORTS #####################################
### ViewSets
from core.views.base import BaseViewSet

### REST Framework
from rest_framework.response import Response

### Models
from core.models.user import User, USER_TYPE_LDAP, USER_TYPE_LOCAL
from interlock_backend.ldap.connector import LDAPInfo
from ldap3 import Server, ServerPool
from core.models.interlock_settings import InterlockSetting, INTERLOCK_SETTING_ENABLE_LDAP
from core.models.ldap_settings_runtime import RuntimeSettings

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
		code = 0
		local_user_count = User.objects.filter(user_type=USER_TYPE_LOCAL).count()
		ldap_user_count = User.objects.filter(user_type=USER_TYPE_LDAP).count()
		oidc_well_known_info = ProviderInfoView()._build_response_dict(request=request)

		# Check if LDAP Enabled
		ldap_enabled = False
		try:
			ldap_enabled = InterlockSetting.objects.get(name=INTERLOCK_SETTING_ENABLE_LDAP)
			ldap_enabled = ldap_enabled.value
		except ObjectDoesNotExist:
			pass

		# Check LDAP Backend status
		ldap_ok = False
		ldap_server = None
		if ldap_enabled:
			try:
				with LDAPInfo(force_admin=True) as ldap_info:
					CONNECTION_OPEN = True if ldap_info.connection.bound else False
					ldap_server_pool: ServerPool = ldap_info.connection.server_pool
					ldap_server: Server = ldap_server_pool.get_current_server(
						ldap_info.connection
					)
					ldap_server = ldap_server.host
				CONNECTION_CLOSED = True if not ldap_info.connection.bound else False
				if CONNECTION_OPEN and CONNECTION_CLOSED:
					ldap_ok = True
			except:
				pass
		return Response(
			 data={
				'code': code,
				'code_msg': 'ok',
				'data' : {
					'local_user_count': local_user_count,
					'oidc_well_known': oidc_well_known_info,
					'ldap_user_count': ldap_user_count,
					'ldap_enabled': ldap_enabled,
					'ldap_tls': RuntimeSettings.LDAP_AUTH_USE_TLS,
					'ldap_ssl': RuntimeSettings.LDAP_AUTH_USE_SSL,
					'ldap_ok': ldap_ok,
					'active_server': ldap_server,
				}
			 }
		)
