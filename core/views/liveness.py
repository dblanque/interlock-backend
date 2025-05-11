################################################################################
#################### INTERLOCK IS LICENSED UNDER GNU AGPLv3 ####################
################## ORIGINAL PROJECT CREATED BY DYLAN BLANQUÉ ###################
########################## AND BR CONSULTING S.R.L. ############################
################################################################################
# Module: core.views.liveness
# Description: Contains the ViewSet for Liveness related operations
#
# ---------------------------------- IMPORTS -----------------------------------#
from core.views.base import BaseViewSet

### REST Framework
from rest_framework.response import Response
from rest_framework.decorators import action
from core.decorators.login import auth_required

### Others
import logging
################################################################################

logger = logging.getLogger(__name__)


class LivenessViewSet(BaseViewSet):  # pragma: no cover
	@action(detail=False, methods=["get"])
	def check(self, request, pk=None):
		code = 0
		return Response(data={"code": code, "code_msg": "ok"})
