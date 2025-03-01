################################################################################
#################### INTERLOCK IS LICENSED UNDER GNU AGPLv3 ####################
################## ORIGINAL PROJECT CREATED BY DYLAN BLANQUÉ ###################
########################## AND BR CONSULTING S.R.L. ############################
################################################################################
# Module: core.views.mixins.application
# Contains the mixin for SSO Application related operations

#---------------------------------- IMPORTS -----------------------------------#
### Models
from core.models.application import Application
from oidc_provider.models import Client, ResponseType

### Exceptions
from core.exceptions.application import (
	ApplicationDoesNotExist,
	ApplicationOidcClientDoesNotExist
)

### ViewSets
from rest_framework import viewsets

### Others
import logging
################################################################################
logger = logging.getLogger()

class ApplicationViewMixin(viewsets.ViewSetMixin):

	def get_application_data(self, application_id: int) -> tuple[object]:
		"""
		:returns: (application, client, response_types)
		:rtype: Application, Client, ResponseType | None
		"""
		if not Application.objects.filter(id=application_id).exists():
			raise ApplicationDoesNotExist

		application = Application.objects.get(id=application_id)
		client_id = application.client_id
		client = None
		response_types = None
		if Client.objects.filter(client_id=client_id).exists():
			client = Client.objects.get(client_id=client_id)
		else:
			raise ApplicationOidcClientDoesNotExist

		if ResponseType.objects.filter(client=client.id).exists():
			response_types = ResponseType.objects.filter(client=client.id)

		return application, client, response_types

	def get_all_response_types(self):
		return ResponseType.objects.all()
