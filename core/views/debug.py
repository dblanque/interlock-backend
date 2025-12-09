################################################################################
#################### INTERLOCK IS LICENSED UNDER GNU AGPLv3 ####################
################## ORIGINAL PROJECT CREATED BY DYLAN BLANQUÉ ###################
########################## AND BR CONSULTING S.R.L. ############################
################################################################################
# Module: core.views.debug
# Contains the ViewSet for Developer related operations

# ---------------------------------- IMPORTS --------------------------------- #
### ViewSets
from .base import BaseViewSet

### Decorators
from core.decorators.login import auth_required, admin_required

### REST Framework
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.decorators import action

### LDAP
from core.constants.attrs.ldap import LDAP_ATTR_SECURITY_ID
from core.ldap.defaults import LDAP_OPERATIONS
from core.ldap.connector import LDAPConnector
from core.config.runtime import RuntimeSettings
from core.ldap.filter import LDAPFilter

### Others
import logging
################################################################################

logger = logging.getLogger(__name__)


class DebugViewSet(BaseViewSet):  # pragma: no cover
	@auth_required
	@admin_required
	def list(self, request: Request):
		NON_DEBUGGABLE_OPERATIONS = ["BIND", "UNBIND", "COMPARE", "ABANDON"]
		valid_debug_operations = LDAP_OPERATIONS
		for op in NON_DEBUGGABLE_OPERATIONS:
			if op in valid_debug_operations:
				valid_debug_operations.remove(op)
		code = 0
		code_msg = "ok"

		m_object_sid = "S-1-5-21-2209570321-9700970-2859064192-1105"  # samba
		m_object_sid = "S-1-5-21-998508399-3078841688-3447918036-500"  # adds
		with LDAPConnector(force_admin=True) as ldc:
			connection = ldc.connection
			if connection:
				connection.search(
					search_base=RuntimeSettings.LDAP_AUTH_SEARCH_BASE,
					search_filter=LDAPFilter.eq(
						LDAP_ATTR_SECURITY_ID, m_object_sid
					).to_string(),
				)
				if connection.entries:
					print(connection.entries[0].entry_dn)
		return Response(
			data={
				"code": code,
				"code_msg": code_msg,
				"data": valid_debug_operations,
			}
		)

	@action(detail=False, methods=["post"])
	@auth_required
	@admin_required
	def action(self, request: Request):
		data = request.data
		code = 0
		code_msg = "ok"
		return Response(data={"code": code, "code_msg": code_msg, "data": data})
