################################################################################
#################### INTERLOCK IS LICENSED UNDER GNU AGPLv3 ####################
################## ORIGINAL PROJECT CREATED BY DYLAN BLANQUÉ ###################
########################## AND BR CONSULTING S.R.L. ############################
################################################################################
# Module: core.views.base
# Contains a Basic Parent Class ViewSet and methods shared to all ViewSets

# ---------------------------------- IMPORTS --------------------------------- #
### REST Framework
from rest_framework import viewsets
from rest_framework.exceptions import NotFound
################################################################################


class BaseViewSet(viewsets.ViewSet):  # pragma: no cover
	"""
	Base ViewSet that disables all default endpoints unless implemented.
	"""

	def not_found(self, request, pk=None):
		raise NotFound

	def list(self, request, pk=None):
		raise NotFound

	def create(self, request, pk=None):
		raise NotFound

	def retrieve(self, request, pk=None):
		raise NotFound

	def update(self, request, pk=None):
		raise NotFound

	def partial_update(self, request, pk=None):
		raise NotFound

	def destroy(self, request, pk=None):
		raise NotFound

	def put(self, request, pk=None):
		raise NotFound

	def patch(self, request, pk=None):
		raise NotFound

	def delete(self, request, pk=None):
		raise NotFound
