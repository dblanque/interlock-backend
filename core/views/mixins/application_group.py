################################################################################
#################### INTERLOCK IS LICENSED UNDER GNU AGPLv3 ####################
################## ORIGINAL PROJECT CREATED BY DYLAN BLANQUÉ ###################
########################## AND BR CONSULTING S.R.L. ############################
################################################################################
# Module: core.views.mixins.application
# Contains the mixin for SSO Application related operations

# ---------------------------------- IMPORTS -----------------------------------#
### Models
from core.models.user import User, USER_TYPE_LOCAL
from core.models.application import Application, ApplicationSecurityGroup

### Serializers
from core.serializers.application_group import ApplicationSecurityGroupSerializer

### Exceptions
from core.exceptions.base import BadRequest

### ViewSets
from rest_framework import viewsets

### Others
from django.db.models.query import QuerySet
from django.db import transaction
from typing import Iterable
import logging

################################################################################
logger = logging.getLogger()


class ApplicationSecurityGroupViewMixin(viewsets.ViewSetMixin):
	serializer_class = ApplicationSecurityGroupSerializer
	app_queryset = Application.objects.all()
	user_queryset = User.objects.all()
	queryset = ApplicationSecurityGroup.objects.all()

	def list_application_groups(self):
		FIELDS = ("id", "enabled", "application")
		data = []
		for asg in list(self.queryset.all()):
			data.append({"id": asg.id, "enabled": asg.enabled, "application": asg.application.name})
		return {
			"application_groups": data,
			"headers": [
				"application",
				"enabled",
			],
		}

	def fetch_application(self, id: int) -> dict:
		pass

	def update_application_group(self, id: int, data: dict) -> None:
		pass
