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
from core.models.user import User, USER_TYPE_LOCAL
from core.models.application import Application, ApplicationSecurityGroup

# Mixins
from core.views.mixins.application_group import ApplicationSecurityGroupViewMixin

# REST Framework
from rest_framework.response import Response
from rest_framework.decorators import action

# Exceptions
from core.exceptions.application_group import ApplicationGroupExists

# Others
from core.exceptions.base import BadRequest
from core.decorators.login import auth_required
from django.db import transaction
import logging
################################################################################
logger = logging.getLogger(__name__)


class ApplicationGroupViewSet(BaseViewSet, ApplicationSecurityGroupViewMixin):

	@action(detail=False, methods=["post"])
	@auth_required()
	def insert(self, request):
		data: dict = request.data
		code = 0
		code_msg = "ok"
		serializer = self.serializer_class(data=data)
		application: Application = self.app_queryset.get(
			id=int(data["application"])
		)
		if self.queryset.filter(application=application.id).exists():
			raise ApplicationGroupExists

		if not serializer.is_valid():
			raise BadRequest(data={
				"errors": serializer.errors
			})
		with transaction.atomic():
			asg = ApplicationSecurityGroup.objects.create(
				application=application,
				ldap_objects=serializer.data["ldap_objects"]
			)
			users = list(self.user_queryset.filter(pk__in=serializer.data["users"]))
			for user in users:
				asg.users.add(user)
			asg.save()
		return Response(
			data={
				"code": code,
				"code_msg": code_msg
			}
		)

	@action(detail=False, methods=["get"])
	@auth_required()
	def create_info(self, request):
		code = 0
		code_msg = "ok"
		data = {
			"applications": [],
			"users": []
		}
		for app in self.app_queryset.values("id", "name"):
			if not self.queryset.filter(application=app["id"]).exists():
				data["applications"].append(app)
		if len(data["applications"]) > 0:
			for user in self.user_queryset.filter(user_type=USER_TYPE_LOCAL).values(*(
				"id",
				"username",
				"first_name",
				"last_name"
			)):
				data["users"].append(user)

		# TODO - send LDAP Groups
		return Response(
			data={
				"code": code,
				"code_msg": code_msg,
				"data": data
			}
		)

	@auth_required()
	def list(self, request):
		code = 0
		code_msg = "ok"
		data = self.list_application_groups()
		return Response(
			data={
				"code": code,
				"code_msg": code_msg,
				"application_groups": data["application_groups"],
				"headers": data["headers"]
			}
		)

	@action(detail=True, methods=["get"])
	@auth_required()
	def fetch(self, request, pk):
		code = 0
		code_msg = "ok"
		application_group_id = int(pk)
		return Response(
			data={
				"code": code,
				"code_msg": code_msg
			}
		)

	@auth_required()
	def update(self, request, pk):
		data: dict = request.data
		code = 0
		code_msg = "ok"
		application_group_id = int(pk)
		return Response(
			data={
				"code": code,
				"code_msg": code_msg
			}
		)
