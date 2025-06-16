################################################################################
#################### INTERLOCK IS LICENSED UNDER GNU AGPLv3 ####################
################## ORIGINAL PROJECT CREATED BY DYLAN BLANQUÉ ###################
########################## AND BR CONSULTING S.R.L. ############################
################################################################################
# Module: core.views.application_group
# Contains the ViewSet for SSO Application related operations

# ---------------------------------- IMPORTS --------------------------------- #
# ViewSets
from core.views.base import BaseViewSet

# Models
from core.models.user import USER_TYPE_LOCAL

# Mixins
from core.views.mixins.application_group import (
	ApplicationSecurityGroupViewMixin,
)

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
	@auth_required
	@admin_required
	@action(
		detail=False,
		methods=["get"],
		url_name="create-info",
		url_path="create-info",
	)
	def create_info(self, request: Request):
		"""Returns required creation info for application groups"""
		code = 0
		code_msg = "ok"
		data = {"applications": [], "users": []}
		for app in self.app_queryset.values("id", "name"):
			# Return any application that does not have an associated app group
			if not self.queryset.filter(application=app["id"]).exists():
				data["applications"].append(app)

		for user in self.user_queryset.filter(user_type=USER_TYPE_LOCAL).values(
			*("id", "username", "first_name", "last_name")
		):
			data["users"].append(user)
		return Response(data={"code": code, "code_msg": code_msg, "data": data})

	@auth_required
	@admin_required
	def create(self, request: Request):
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

	@auth_required
	@admin_required
	@action(
		detail=True,
		methods=["patch"],
		url_name="change-status",
		url_path="change-status",
	)
	def change_status(self, request: Request, pk):
		data: dict = request.data
		code = 0
		code_msg = "ok"
		pk = int(pk)
		self.change_application_group_status(pk=pk, data=data)
		return Response(data={"code": code, "code_msg": code_msg})

	@auth_required
	@admin_required
	def destroy(self, request: Request, pk):
		code = 0
		code_msg = "ok"
		pk = int(pk)
		self.delete_application_group(pk=pk)
		return Response(data={"code": code, "code_msg": code_msg})
