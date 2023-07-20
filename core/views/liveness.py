################################## IMPORTS #####################################
from core.views.base import BaseViewSet

### REST Framework
from rest_framework.response import Response
from rest_framework.decorators import action
from core.decorators.login import auth_required

### Others
import logging
################################################################################

logger = logging.getLogger(__name__)

class LivenessViewSet(BaseViewSet):

	@action(detail=False, methods=['get'])
	@auth_required()
	def check(self, request, pk=None):
		user = request.user
		data = {}
		code = 0
		return Response(
			 data={
				'code': code,
				'code_msg': 'ok'
			 }
		)