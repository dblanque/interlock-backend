################################################################################
#################### INTERLOCK IS LICENSED UNDER GNU AGPLv3 ####################
################## ORIGINAL PROJECT CREATED BY DYLAN BLANQUÉ ###################
########################## AND BR CONSULTING S.R.L. ############################
################################################################################
# Module: core.views.debug
# Contains the ViewSet for Developer related operations

#---------------------------------- IMPORTS -----------------------------------#
### ViewSets
from .base import BaseViewSet

### Decorators
from core.decorators.login import auth_required

### REST Framework
from rest_framework.response import Response
from rest_framework.decorators import action

### LDAP
from interlock_backend.ldap.defaults import LDAP_OPERATIONS

### Others
import logging
################################################################################

logger = logging.getLogger(__name__)

class DebugViewSet(BaseViewSet):
	@auth_required()
	def list(self, request):
		user = request.user
		data = []
		NON_DEBUGGABLE_OPERATIONS = [
			"BIND",
			"UNBIND",
			"COMPARE",
			"ABANDON"
		]
		valid_debug_operations = LDAP_OPERATIONS
		for op in NON_DEBUGGABLE_OPERATIONS:
			if op in valid_debug_operations: valid_debug_operations.remove(op)
		code = 0
		code_msg = 'ok'
		return Response(
			 data={
				'code': code,
				'code_msg': code_msg,
				'data': valid_debug_operations
			 }
		)

	@action(detail=False,methods=['post'])
	@auth_required()
	def action(self, request):
		user = request.user
		data = request.data
		code = 0
		code_msg = 'ok'
		return Response(
			 data={
				'code': code,
				'code_msg': code_msg,
				'data': data
			 }
		)