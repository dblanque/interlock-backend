################################################################################
#################### INTERLOCK IS LICENSED UNDER GNU AGPLv3 ####################
################## ORIGINAL PROJECT CREATED BY DYLAN BLANQUÉ ###################
########################## AND BR CONSULTING S.R.L. ############################
################################################################################
# Module: core.views.mixins.application
# Contains the mixin for SSO Application related operations

# ---------------------------------- IMPORTS -----------------------------------#
### Models
from core.models.application import Application
from oidc_provider.models import Client, ResponseType

### Exceptions
from core.exceptions.application import (
	ApplicationExists,
	ApplicationDoesNotExist,
	ApplicationOidcClientDoesNotExist,
)
from core.exceptions.base import BadRequest

### Serializers
from core.serializers.application import ApplicationSerializer
from core.serializers.oidc import ClientSerializer

### ViewSets
from rest_framework import viewsets

### Others
from django.db.models.query import QuerySet
from django.db import transaction
from typing import Iterable
import logging

################################################################################
logger = logging.getLogger()


class ApplicationViewMixin(viewsets.ViewSetMixin):
	application_serializer = ApplicationSerializer
	client_serializer = ClientSerializer

	def get_application_data(
		self, application_id: int
	) -> tuple[Application, Client]:
		"""Fetched Application with corresponding Client

		Args:
			application_id (int): The primary key for the application.

		Raises:
			ApplicationDoesNotExist: Raised if Application could not be fetched.
			ApplicationOidcClientDoesNotExist: Raised if Client could not be fetched.

		Returns:
			tuple[Application, Client]: Tuple containing Application and Client.
		"""
		if not Application.objects.filter(id=application_id).exists():
			raise ApplicationDoesNotExist

		application = Application.objects.get(id=application_id)
		client_id = application.client_id
		client = None
		if Client.objects.filter(client_id=client_id).exists():
			client = Client.objects.get(client_id=client_id)
		else:
			raise ApplicationOidcClientDoesNotExist

		return application, client

	@staticmethod
	def get_response_type_id_map():
		return {rt.value: rt.id for rt in ResponseType.objects.all()}

	@staticmethod
	def get_response_type_codes():
		return ResponseType.objects.all().values_list("value", flat=True)

	def set_client_response_types(self, new_response_types: dict, client: Client) -> None:
		RESPONSE_TYPE_ID_MAP = self.get_response_type_id_map()
		for key, value in new_response_types.items():
			if key in RESPONSE_TYPE_ID_MAP:
				# Add key if explicit True
				if value is True:
					client.response_types.add(RESPONSE_TYPE_ID_MAP[key])
				# Remove key if explicitly False
				elif value is False:
					client.response_types.remove(RESPONSE_TYPE_ID_MAP[key])
			else:
				logger.warning("Unknown response type key (%s)", key)

	def insert_clean_data(self, data: dict) -> tuple[ApplicationSerializer, dict]:
		FIELDS_EXCLUDE = (
			"client_id",
			"client_secret",
			"enabled",
		)
		FIELDS_EXTRA = ("require_consent", "reuse_consent", "response_types")
		for field in FIELDS_EXCLUDE:
			if field in data:
				del data[field]

		extra_fields = {}
		for field in FIELDS_EXTRA:
			if field in data:
				extra_fields[field] = data.pop(field)

		if not isinstance(data["scopes"], str) and isinstance(data["scopes"], Iterable):
			data["scopes"] = " ".join(data["scopes"])

		serializer = self.application_serializer(data=data)
		if not serializer.is_valid():
			raise BadRequest(data={"errors": serializer.errors})
		return serializer, extra_fields

	def insert_application(
		self, serializer: ApplicationSerializer, extra_fields: dict
	) -> Application:
		if Application.objects.filter(name=serializer.data["name"]).exists():
			raise ApplicationExists

		if "response_types" in extra_fields:
			new_response_types = extra_fields.pop("response_types")

		with transaction.atomic():
			# APPLICATION
			application = Application.objects.create(**serializer.data)
			application.save()

			# CLIENT
			client = Client.objects.create(
				name=application.name,
				client_id=application.client_id,
				client_secret=application.client_secret,
				redirect_uris=application.redirect_uris.split(","),
				scope=application.scopes.split(),
				**extra_fields,
				# Other OIDC client settings (e.g., token expiration)
			)
			if new_response_types:
				self.set_client_response_types(new_response_types, client)
			client.save()
		return application

	def list_applications(self):
		data = {}
		FIELDS_TO_SEND = [
			"id",
			"name",
			"redirect_uris",
			"enabled",
		]
		HEADERS_EXCLUDE = ("id",)

		application_query = Application.objects.all()
		application_data = []
		for app in application_query:
			_build_data = {}
			for field in FIELDS_TO_SEND:
				_build_data[field] = getattr(app, field)
			application_data.append(_build_data)
		data = {"applications": application_data, "headers": FIELDS_TO_SEND}
		data_headers: list = data["headers"]

		for field in HEADERS_EXCLUDE:
			data_headers.remove(field)
		data["headers"] = data_headers
		return data

	def fetch_application(self, application_id: int) -> dict:
		APPLICATION_FIELDS = (
			"id",
			"name",
			"redirect_uris",
			"client_id",
			"client_secret",
			"scopes",
			"enabled",
		)
		CLIENT_FIELDS = (
			"require_consent",
			"reuse_consent",
		)

		data = {}
		application, client = self.get_application_data(application_id=application_id)
		response_types: list[str] = client.response_type_values()

		for field in APPLICATION_FIELDS:
			if hasattr(application, field):
				data[field] = getattr(application, field)

		if isinstance(data["scopes"], str):
			data["scopes"] = data["scopes"].split()

		for field in CLIENT_FIELDS:
			if hasattr(client, field):
				data[field] = getattr(client, field)

		data["response_types"] = {}
		for r_type in self.get_response_type_codes():
			data["response_types"][r_type] = False
		if response_types:
			for r_type in response_types:
				data["response_types"][r_type] = True
		return data

	def update_application(self, application_id: int, data: dict) -> tuple[Application, Client]:
		APPLICATION_FIELDS = (
			"name",
			"redirect_uris",
			"scopes",
			"enabled",
		)
		CLIENT_FIELDS = (
			"require_consent",
			"reuse_consent",
		)
		FIELDS_EXCLUDE = (
			"id",
			"client_id",
			"client_secret",
		)

		for field in FIELDS_EXCLUDE:
			if field in data:
				del data[field]

		application, client = self.get_application_data(application_id=application_id)
		application: Application
		client: Client
		new_application = {}
		new_client = {}
		new_response_types = None
		if "response_types" in data:
			new_response_types: list = data.pop("response_types")

		### APPLICATION
		for field in APPLICATION_FIELDS:
			if hasattr(application, field) and field in data:
				new_application[field] = data.pop(field)

		if (
			"scopes" in new_application
			and not isinstance(new_application["scopes"], str)
			and isinstance(new_application["scopes"], Iterable)
		):
			new_application["scopes"] = " ".join(new_application["scopes"])

		serializer = self.application_serializer(data=new_application, partial=True)
		if not serializer.is_valid():
			raise BadRequest(data={"errors": serializer.errors})

		### CLIENT
		for field in CLIENT_FIELDS:
			if hasattr(client, field) and field in data:
				new_client[field] = data.pop(field)

		if "redirect_uris" in new_application:
			new_client["redirect_uris"] = new_application["redirect_uris"].split(",")
		c_serializer = self.client_serializer(data=new_client, partial=True)
		if not c_serializer.is_valid():
			raise BadRequest(data={"errors": c_serializer.errors})

		with transaction.atomic():
			# APPLICATION
			for attr in new_application:
				setattr(application, attr, new_application[attr])
			application.save()

			# CLIENT
			for attr in new_client:
				setattr(client, attr, new_client[attr])
			if new_response_types:
				self.set_client_response_types(new_response_types, client)
			client.save()
		return application, client

	def delete_application(self, application_id: int):
		if not Application.objects.filter(id=application_id).exists():
			raise ApplicationDoesNotExist

		with transaction.atomic():
			application = Application.objects.get(id=application_id)
			client_id = application.client_id
			if Client.objects.filter(client_id=client_id).exists():
				Client.objects.get(client_id=client_id).delete()
			application.delete_permanently()
