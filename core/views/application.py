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
from core.exceptions.application import ApplicationExists

### Mixins
from .mixins.application import ApplicationViewMixin

### Serializers
from core.serializers.application import ApplicationSerializer
from django.core import serializers

### REST Framework
from rest_framework.response import Response
from rest_framework.decorators import action

### Others
from typing import Iterable
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
		code_msg = "ok"
		FIELDS_TO_SEND = [
			"name",
			"redirect_uris",
		]

		application_query =  Application.objects.all()
		application_data = []
		for app in application_query:
			_build_data = {}
			for field in FIELDS_TO_SEND:
				if not hasattr(app, field):
					raise Exception(f"Missing field ({field}) in queryset, is there a database issue?")
				_build_data[field] = getattr(app, field)
			application_data.append(_build_data)
		data = {
			"applications": application_data,
			"headers": FIELDS_TO_SEND
		}

		return Response(
			 data={
				"code": code,
				"code_msg": code_msg,
				"applications": data["applications"],
				"headers": data["headers"]
			 }
		)

	@action(detail=False,methods=["post"])
	@auth_required()
	def insert(self, request):
		user: User = request.user
		data: dict = request.data
		code = 0
		code_msg = "ok"
		FIELDS_DISALLOWED = [
			"client_id",
			"client_secret",
			"enabled"
		]
		for field in FIELDS_DISALLOWED:
			if field in data:
				data.pop(field)

		if not isinstance(data["scopes"], str) and isinstance(data["scopes"], Iterable):
			data["scopes"] = " ".join(data["scopes"])

		serializer = ApplicationSerializer(data=data)
		if not serializer.is_valid():
			raise BadRequest(data={
				"errors": serializer.errors
			})

		if Application.objects.filter(name=serializer.data["name"]).exists():
			raise ApplicationExists
		application = Application.objects.create(**serializer.data)
		application.save()

		return Response(
			 data={
				"code": code,
				"code_msg": code_msg,
				"application": {
					application.name,
					application.client_id,
					application.client_secret,
				}
			 }
		)