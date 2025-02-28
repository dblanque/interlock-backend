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
from oidc_provider.models import Client

### Exception
from core.exceptions.base import BadRequest
from core.exceptions.application import (
	ApplicationExists,
	ApplicationDoesNotExist,
	ApplicationFieldDoesNotExist,
	ApplicationOidcClientDoesNotExist
)

### Mixins
from .mixins.application import ApplicationViewMixin

### Serializers
from core.serializers.application import ApplicationSerializer
from django.core import serializers

### REST Framework
from rest_framework.response import Response
from rest_framework.decorators import action

### Others
from django.db import transaction, IntegrityError
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
			"id",
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
		data_headers: list = data["headers"]
		data_headers.remove("id")

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
		FIELDS_EXCLUDE = [
			"client_id",
			"client_secret",
			"enabled"
		]
		FIELDS_EXTRA = [
			"require_consent",
			"reuse_consent"
		]
		for field in FIELDS_EXCLUDE:
			if field in data:
				data.pop(field)

		extra_fields = {}
		for field in FIELDS_EXTRA:
			if field in data:
				extra_fields[field] = data.pop(field)

		if not isinstance(data["scopes"], str) and isinstance(data["scopes"], Iterable):
			data["scopes"] = " ".join(data["scopes"])

		serializer = ApplicationSerializer(data=data)
		if not serializer.is_valid():
			raise BadRequest(data={
				"errors": serializer.errors
			})

		if Application.objects.filter(name=serializer.data["name"]).exists():
			raise ApplicationExists

		with transaction.atomic():
			application = Application.objects.create(**serializer.data)
			client = Client.objects.create(
				name=application.name,
				client_id=application.client_id,
				client_secret=application.client_secret,
				redirect_uris=application.redirect_uris.split(','),
				scope=application.scopes.split(),
				require_consent=extra_fields["require_consent"] or False,
				reuse_consent=extra_fields["reuse_consent"] or False,
				# Other OIDC client settings (e.g., token expiration)
			)
			application.save()
			client.save()

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

	@action(detail=True, methods=["delete"], url_path="delete")
	@auth_required()
	def delete(self, request, pk):
		user: User = request.user
		data: dict = request.data
		code = 0
		code_msg = "ok"
		application_id = int(pk)

		if not Application.objects.filter(id=application_id).exists():
			raise ApplicationDoesNotExist

		with transaction.atomic():
			application = Application.objects.get(id=application_id)
			client_id = application.client_id
			if Client.objects.filter(client_id=client_id).exists():
				Client.objects.get(client_id=client_id).delete()
			application.delete_permanently()

		return Response(
			 data={
				"code": code,
				"code_msg": code_msg,
				"id": application_id
			 }
		)

	@action(detail=True, methods=["get"])
	@auth_required()
	def fetch(self, request, pk):
		user: User = request.user
		data: dict = request.data
		code = 0
		code_msg = "ok"
		application_id = int(pk)
		APPLICATION_FIELDS = [
			"id",
			"name",
			"client_id",
			"client_secret",
			"enabled",
		]
		CLIENT_FIELDS = [
			"require_consent",
			"reuse_consent",
		]

		if not Application.objects.filter(id=application_id).exists():
			raise ApplicationDoesNotExist

		data = {}
		application = Application.objects.get(id=application_id)
		client_id = application.client_id
		client = None
		if Client.objects.filter(client_id=client_id).exists():
			client = Client.objects.get(client_id=client_id)
		else:
			raise ApplicationOidcClientDoesNotExist

		for field in APPLICATION_FIELDS:
			if hasattr(application, field):
				data[field] = getattr(application, field)
			else:
				raise ApplicationFieldDoesNotExist(data={"field":field})

		for field in CLIENT_FIELDS:
			if hasattr(client, field):
				data[field] = getattr(client, field)
			else:
				raise ApplicationFieldDoesNotExist(data={"field":field})

		return Response(
			 data={
				"code": code,
				"code_msg": code_msg,
				"data": data
			 }
		)
