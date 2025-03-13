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
from core.models.application import Application, ApplicationSecurityGroup

# Mixins
from core.views.mixins.application_group import ApplicationSecurityGroupViewMixin

# REST Framework
from rest_framework.response import Response
from rest_framework.decorators import action

# Exceptions
from core.exceptions.application_group import (
	ApplicationGroupExists,
	ApplicationGroupDoesNotExist
)
from core.exceptions.base import BadRequest

# Others
from core.decorators.login import auth_required, admin_required
from django.db import transaction
import logging
################################################################################
logger = logging.getLogger(__name__)


class ApplicationGroupViewSet(BaseViewSet, ApplicationSecurityGroupViewMixin):

	@action(detail=False, methods=["post"])
	@auth_required
	@admin_required
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
			users = list(self.user_queryset.filter(
				pk__in=serializer.data["users"]))
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
	@auth_required
	@admin_required
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

	@auth_required
	@admin_required
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

	@auth_required
	@admin_required
	def retrieve(self, request, pk):
		code = 0
		code_msg = "ok"
		pk = int(pk)
		if not self.queryset.filter(id=pk).exists():
			raise ApplicationGroupDoesNotExist
		application_group = self.queryset.get(id=pk)
		data_users = []
		for user in application_group.users.all():
			data_users.append(user.id)
		return Response(
			data={
				"code": code,
				"code_msg": code_msg,
				"data": {
					"id": application_group.id,
					"application": {
						"id": application_group.application.id,
						"name": application_group.application.name
					},
					"enabled": application_group.enabled,
					"users": data_users,
					"ldap_objects": application_group.ldap_objects
				}
			}
		)

	@auth_required
	@admin_required
	def update(self, request, pk):
		data: dict = request.data
		code = 0
		code_msg = "ok"
		pk = int(pk)
		if not self.queryset.filter(id=pk).exists():
			raise ApplicationGroupDoesNotExist

		asg = self.queryset.get(id=pk)
		users = self.user_queryset.filter(
			pk__in=data["users"]).values_list("id", flat=True)
		data["users"] = users
		serializer = self.serializer_class(asg, data=data)
		if not serializer.is_valid():
			raise BadRequest(data={
				"errors": serializer.errors
			})

		with transaction.atomic():
			serializer.save()

		return Response(
			data={
				"code": code,
				"code_msg": code_msg
			}
		)

	@action(detail=True, methods=["patch"])
	@auth_required
	@admin_required
	def change_status(self, request, pk):
		data: dict = request.data
		code = 0
		code_msg = "ok"
		pk = int(pk)
		if not self.queryset.filter(id=pk).exists():
			raise ApplicationGroupDoesNotExist
		if not "enabled" in data:
			raise BadRequest(data={
				"errors": "Missing boolean field 'enabled' in data."
			})
		if not isinstance(data["enabled"], bool):
			raise BadRequest(data={
				"errors": "Field 'enabled' must be a boolean."
			})
		asg = self.queryset.get(id=pk)
		asg.enabled = data["enabled"]
		asg.save()
		return Response(
			data={
				"code": code,
				"code_msg": code_msg
			}
		)

	@action(detail=True, methods=["delete"])
	@auth_required
	@admin_required
	def delete(self, request, pk):
		data: dict = request.data
		code = 0
		code_msg = "ok"
		pk = int(pk)
		if not self.queryset.filter(id=pk).exists():
			raise ApplicationGroupDoesNotExist
		asg = self.queryset.get(id=pk)
		asg.delete_permanently()
		return Response(
			data={
				"code": code,
				"code_msg": code_msg
			}
		)
