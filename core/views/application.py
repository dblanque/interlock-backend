################################################################################
#################### INTERLOCK IS LICENSED UNDER GNU AGPLv3 ####################
################## ORIGINAL PROJECT CREATED BY DYLAN BLANQUÉ ###################
########################## AND BR CONSULTING S.R.L. ############################
################################################################################
# Module: core.views.application
# Contains the ViewSet for SSO Application related operations

# ---------------------------------- IMPORTS -----------------------------------#
### ViewSets
from core.views.base import BaseViewSet

### Models
from core.models.user import User
from core.models.application import Application

### Mixins
from core.views.mixins.application import ApplicationViewMixin

### REST Framework
from rest_framework.response import Response
from rest_framework.request import Request
from rest_framework.decorators import action

### Others
from core.decorators.login import auth_required, admin_required
import logging

################################################################################
logger = logging.getLogger(__name__)


class ApplicationViewSet(BaseViewSet, ApplicationViewMixin):
	queryset = Application.objects.all()

	@auth_required
	@admin_required
	def list(self, request: Request):
		code = 0
		code_msg = "ok"
		data = self.list_applications()
		return Response(
			data={
				"code": code,
				"code_msg": code_msg,
				"applications": data["applications"],
				"headers": data["headers"],
			}
		)

	@action(detail=False, methods=["post"])
	@auth_required
	@admin_required
	def insert(self, request: Request):
		data: dict = request.data
		code = 0
		code_msg = "ok"
		serializer, extra_fields = self.insert_clean_data(data=data)
		self.insert_application(
			serializer=serializer, extra_fields=extra_fields
		)
		return Response(data={"code": code, "code_msg": code_msg})

	@action(detail=True, methods=["delete"], url_path="delete")
	@auth_required
	@admin_required
	def delete(self, request: Request, pk):
		code = 0
		code_msg = "ok"
		application_id = int(pk)
		self.delete_application(application_id)
		return Response(
			data={
				"code": code,
				"code_msg": code_msg,
				"data": {"id": application_id},
			}
		)

	@action(detail=True, methods=["get"])
	@auth_required
	@admin_required
	def fetch(self, request: Request, pk):
		code = 0
		code_msg = "ok"
		application_id = int(pk)
		data = self.fetch_application(application_id=application_id)
		return Response(
			data={
				"code": code,
				"code_msg": code_msg,
				"data": data,
				"response_types": self.get_response_type_codes(),
			}
		)

	@auth_required
	@admin_required
	def update(self, request: Request, pk):
		data: dict = request.data
		code = 0
		code_msg = "ok"
		application_id = int(pk)
		self.update_application(application_id, data)
		return Response(data={"code": code, "code_msg": code_msg})
