################################################################################
#################### INTERLOCK IS LICENSED UNDER GNU AGPLv3 ####################
################## ORIGINAL PROJECT CREATED BY DYLAN BLANQUÉ ###################
########################## AND BR CONSULTING S.R.L. ############################
################################################################################
# Module: core.views.mixins.application_group
# Contains the mixin for SSO Application Group related operations

# ---------------------------------- IMPORTS -----------------------------------#
### Models
from core.models.user import User
from core.models.application import Application, ApplicationSecurityGroup

### Serializers
from core.serializers.application_group import (
	ApplicationSecurityGroupSerializer,
)

### Exceptions
from core.exceptions.base import BadRequest
from core.exceptions.application_group import (
	ApplicationGroupExists,
	ApplicationGroupDoesNotExist,
)
from core.exceptions.base import BadRequest

### ViewSets
from rest_framework import viewsets

### Others
from django.db import transaction
import logging

################################################################################
logger = logging.getLogger()


class ApplicationSecurityGroupViewMixin(viewsets.ViewSetMixin):
	serializer_class = ApplicationSecurityGroupSerializer
	app_queryset = Application.objects.all()
	user_queryset = User.objects.all()
	queryset = ApplicationSecurityGroup.objects.all()

	def insert_application_group(self, data: dict) -> None:
		serializer = self.serializer_class(data=data)
		application: Application = self.app_queryset.get(
			id=int(data["application"])
		)
		if self.queryset.filter(application=application.id).exists():
			raise ApplicationGroupExists

		if not serializer.is_valid():
			raise BadRequest(data={"errors": serializer.errors})
		with transaction.atomic():
			asg = ApplicationSecurityGroup.objects.create(
				application=application,
				ldap_objects=serializer.data["ldap_objects"],
			)
			users = list(
				self.user_queryset.filter(pk__in=serializer.data["users"])
			)
			for user in users:
				asg.users.add(user)
			asg.save()

	def list_application_groups(self):
		data = []
		for asg in list(self.queryset.all()):
			data.append(
				{
					"id": asg.id,
					"enabled": asg.enabled,
					"application": asg.application.name,
				}
			)
		return {
			"application_groups": data,
			"headers": [
				"application",
				"enabled",
			],
		}

	def retrieve_application(self, pk: int) -> dict:
		if not self.queryset.filter(id=pk).exists():
			raise ApplicationGroupDoesNotExist
		application_group = self.queryset.get(id=pk)
		data_users = []
		for user in application_group.users.all():
			data_users.append(user.id)
		return {
			"id": application_group.id,
			"application": {
				"id": application_group.application.id,
				"name": application_group.application.name,
			},
			"enabled": application_group.enabled,
			"users": data_users,
			"ldap_objects": application_group.ldap_objects,
		}

	def update_application_group(self, pk: int, data: dict) -> None:
		if not self.queryset.filter(id=pk).exists():
			raise ApplicationGroupDoesNotExist

		asg = self.queryset.get(id=pk)
		if not asg.application.id == data["application"]:
			raise BadRequest(
				data={
					"detail": "Application ID does not match "
					+ "with this Application Group"
				}
			)

		if "users" in data:
			users = self.user_queryset.filter(pk__in=data["users"]).values_list(
				"id", flat=True
			)
			data["users"] = users
		else:
			data["users"] = asg.users.values_list("id", flat=True)

		serializer = self.serializer_class(asg, data=data)
		if not serializer.is_valid():
			raise BadRequest(data={"errors": serializer.errors})

		with transaction.atomic():
			serializer.save()

	def change_application_group_status(self, pk: int, data: dict) -> None:
		if not self.queryset.filter(id=pk).exists():
			raise ApplicationGroupDoesNotExist
		if not "enabled" in data:
			raise BadRequest(
				data={"errors": "Missing boolean field 'enabled' in data."}
			)
		if not isinstance(data["enabled"], bool):
			raise BadRequest(
				data={"errors": "Field 'enabled' must be a boolean."}
			)
		asg = self.queryset.get(id=pk)
		asg.enabled = data["enabled"]
		asg.save()

	def delete_application_group(self, pk: int) -> None:
		if not self.queryset.filter(id=pk).exists():
			raise ApplicationGroupDoesNotExist
		asg = self.queryset.get(id=pk)
		asg.delete_permanently()
