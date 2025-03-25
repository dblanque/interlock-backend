################################################################################
#################### INTERLOCK IS LICENSED UNDER GNU AGPLv3 ####################
################## ORIGINAL PROJECT CREATED BY DYLAN BLANQUÉ ###################
########################## AND BR CONSULTING S.R.L. ############################
################################################################################
# Module: core.views.application
# Contains the ViewSet for SSO Application related operations

# ---------------------------------- IMPORTS -----------------------------------#
# ViewSets
from core.views.base import BaseViewSet

# Models
from core.models.user import USER_TYPE_LOCAL

# Mixins
from core.views.mixins.application_group import ApplicationSecurityGroupViewMixin

# REST Framework
from rest_framework.response import Response
from rest_framework.request import Request
from rest_framework.decorators import action

# Others
from core.decorators.login import auth_required, admin_required
import logging

################################################################################
logger = logging.getLogger(__name__)


class ApplicationGroupViewSet(BaseViewSet, ApplicationSecurityGroupViewMixin):
	@action(detail=False, methods=["get"])
	@auth_required
	@admin_required
	def create_info(self, request: Request):
		code = 0
		code_msg = "ok"
		data = {"applications": [], "users": []}
		for app in self.app_queryset.values("id", "name"):
			if not self.queryset.filter(application=app["id"]).exists():
				data["applications"].append(app)
		if len(data["applications"]) > 0:
			for user in self.user_queryset.filter(user_type=USER_TYPE_LOCAL).values(
				*("id", "username", "first_name", "last_name")
			):
				data["users"].append(user)
		return Response(data={"code": code, "code_msg": code_msg, "data": data})

	@action(detail=False, methods=["post"])
	@auth_required
	@admin_required
	def insert(self, request: Request):
		data: dict = request.data
		code = 0
		code_msg = "ok"
		self.insert_application_group(data=data)
		return Response(data={"code": code, "code_msg": code_msg})

	@auth_required
	@admin_required
	def list(self, request: Request):
		code = 0
		code_msg = "ok"
		data = self.list_application_groups()
		return Response(
			data={
				"code": code,
				"code_msg": code_msg,
				"application_groups": data["application_groups"],
				"headers": data["headers"],
			}
		)

	@auth_required
	@admin_required
	def retrieve(self, request: Request, pk):
		code = 0
		code_msg = "ok"
		pk = int(pk)
		return Response(
			data={
				"code": code,
				"code_msg": code_msg,
				"data": self.retrieve_application(pk=pk),
			}
		)

	@auth_required
	@admin_required
	def update(self, request: Request, pk):
		data: dict = request.data
		code = 0
		code_msg = "ok"
		pk = int(pk)
		self.update_application_group(pk=pk, data=data)
		return Response(data={"code": code, "code_msg": code_msg})

	@action(detail=True, methods=["patch"])
	@auth_required
	@admin_required
	def change_status(self, request: Request, pk):
		data: dict = request.data
		code = 0
		code_msg = "ok"
		pk = int(pk)
		self.change_application_group_status(pk=pk, data=data)
		return Response(data={"code": code, "code_msg": code_msg})

	@action(detail=True, methods=["delete"])
	@auth_required
	@admin_required
	def delete(self, request: Request, pk):
		data: dict = request.data
		code = 0
		code_msg = "ok"
		pk = int(pk)
		self.delete_application_group(pk=pk)
		return Response(data={"code": code, "code_msg": code_msg})
