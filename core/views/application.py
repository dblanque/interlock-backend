################################################################################
#################### INTERLOCK IS LICENSED UNDER GNU AGPLv3 ####################
################## ORIGINAL PROJECT CREATED BY DYLAN BLANQUÉ ###################
########################## AND BR CONSULTING S.R.L. ############################
################################################################################
# Module: core.views.application
# Contains the ViewSet for SSO Application related operations

#---------------------------------- IMPORTS -----------------------------------#
### ViewSets
from core.views.base import BaseViewSet

### Models
from core.models.user import User
from core.models.application import Application

### Exception
from core.exceptions.base import BadRequest

### Mixins
from .mixins.application import ApplicationViewMixin

### Serializers
from core.serializers.application import ApplicationSerializer

### REST Framework
from rest_framework.response import Response
from rest_framework.decorators import action

### Others
from core.decorators.login import auth_required
import logging
################################################################################
logger = logging.getLogger(__name__)

class ApplicationViewSet(BaseViewSet, ApplicationViewMixin):
	queryset = Application.objects.all()
	serializer_class = ApplicationSerializer

	@auth_required()
	def list(self, request):
		user: User = request.user
		data = dict()
		code = 0
		code_msg = 'ok'

		return Response(
			 data={
				'code': code,
				'code_msg': code_msg,
				'application': data['application'],
				'headers': data['headers']
			 }
		)

	@action(detail=False,methods=['post'])
	@auth_required()
	def insert(self, request):
		user: User = request.user
		data: dict = request.data
		code = 0
		code_msg = 'ok'
		data["name"] = "PAP@"
		serializer = ApplicationSerializer(data=data)
		if not serializer.is_valid():
			raise BadRequest(data={
				"errors": serializer.errors
			})

		return Response(
			 data={
				'code': code,
				'code_msg': code_msg
			 }
		)