################################################################################
#################### INTERLOCK IS LICENSED UNDER GNU AGPLv3 ####################
################## ORIGINAL PROJECT CREATED BY DYLAN BLANQUÉ ###################
########################## AND BR CONSULTING S.R.L. ############################
################################################################################
# Module: core.views.record
# Contains the ViewSet for DNS Record related operations

# ---------------------------------- IMPORTS -----------------------------------#
### Models
from core.models.types.ldap_dns_record import *
from core.models.user import User

### ViewSets
from core.views.base import BaseViewSet

### Exceptions
from core.exceptions import dns as exc_dns

### Mixins
from core.views.mixins.ldap.record import DNSRecordMixin
from core.views.mixins.ldap.domain import DomainViewMixin

### Serializers
from core.serializers.record import DNSRecordSerializer

### REST Framework
from rest_framework.response import Response
from rest_framework.decorators import action

### Others
from core.utils.dnstool import record_to_dict
from core.decorators.login import auth_required, admin_required
from core.ldap.connector import LDAPConnector
import logging
################################################################################

logger = logging.getLogger(__name__)


class LDAPRecordViewSet(BaseViewSet, DNSRecordMixin, DomainViewMixin):
	record_serializer = DNSRecordSerializer

	@action(detail=False, methods=["post"])
	@auth_required
	@admin_required
	def insert(self, request):
		user: User = request.user
		data: dict = request.data
		code = 0
		record_data = data.get("record", None)
		if not record_data:
			raise exc_dns.DNSRecordNotInRequest

		self.record_serializer(data=record_data).is_valid(raise_exception=True)

		# ! Test record validation with the Mix-in
		self.validate_record_data(record_data=record_data)

		# Open LDAP Connection
		with LDAPConnector(user) as ldc:
			self.ldap_connection = ldc.connection
			record_result_data = self.create_record(record_data=record_data)

		return Response(
			data={
				"code": code,
				"code_msg": "ok",
				"data": record_to_dict(record_result_data, ts=False),
			}
		)

	@auth_required
	@admin_required
	def update(self, request, pk=None):
		user: User = request.user
		data: dict = request.data
		code = 0

		old_record_data: dict = data.get("oldRecord", None)
		record_data: dict = data.get("record", None)
		if not old_record_data or not record_data:
			raise exc_dns.DNSRecordNotInRequest

		# Basic Serializer Validation
		self.record_serializer(data=old_record_data).is_valid(raise_exception=True)
		self.record_serializer(data=record_data).is_valid(raise_exception=True)

		# Regex Validate Old Record Data
		self.validate_record_data(record_data=old_record_data, add_required_keys=["serial"])
		# Regex Validate New Record Data
		self.validate_record_data(record_data=record_data, add_required_keys=["serial"])

		# TODO - Maybe implement crosschecking with server-side Old Record Bytes Data?

		# Open LDAP Connection
		with LDAPConnector(user) as ldc:
			self.ldap_connection = ldc.connection
			record_result_data = self.update_record(
				record_data=record_data, old_record_data=old_record_data
			)

		return Response(
			data={
				"code": code,
				"code_msg": "ok",
				"data": record_to_dict(record_result_data, ts=False),
			}
		)

	@action(detail=False, methods=["post"])
	@auth_required
	@admin_required
	def delete(self, request):
		user: User = request.user
		data: dict = request.data
		code = 0
		record_delete = data.get("record", None)
		multi_record_delete = data.get("records", None)

		if not record_delete and not multi_record_delete:
			raise exc_dns.DNSRecordNotInRequest
		elif record_delete and multi_record_delete:
			raise exc_dns.DNSRecordOperationConflict

		# Data Validation
		# Single Record Delete
		if record_delete:
			if not isinstance(record_delete, dict):
				raise exc_dns.DNSRecordDataMalformed
			self.record_serializer(data=record_delete).is_valid(raise_exception=True)
			self.validate_record_data(record_data=record_delete)
		# Multi Record Delete
		if multi_record_delete:
			if not isinstance(multi_record_delete, list):
				raise exc_dns.DNSRecordDataMalformed
			for _record in multi_record_delete:
				if not isinstance(_record, dict):
					raise exc_dns.DNSRecordDataMalformed
				self.record_serializer(data=_record).is_valid(raise_exception=True)
				self.validate_record_data(record_data=_record)

		# Open LDAP Connection
		with LDAPConnector(user) as ldc:
			self.ldap_connection = ldc.connection
			# Single Record Delete
			if record_delete:
				logger.debug(record_delete)
				result = self.delete_record(record_delete)
			# Multi Record Delete
			if multi_record_delete:
				result = []
				for _record in multi_record_delete:
					logger.debug(_record)
					result.append(self.delete_record(_record))

		return Response(data={"code": code, "code_msg": "ok", "data": result})
