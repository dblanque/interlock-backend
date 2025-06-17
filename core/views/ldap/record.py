################################################################################
#################### INTERLOCK IS LICENSED UNDER GNU AGPLv3 ####################
################## ORIGINAL PROJECT CREATED BY DYLAN BLANQUÉ ###################
########################## AND BR CONSULTING S.R.L. ############################
################################################################################
# Module: core.views.ldap.record
# Contains the ViewSet for DNS Record related operations

# ---------------------------------- IMPORTS --------------------------------- #
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

### REST Framework
from rest_framework.response import Response
from rest_framework.decorators import action

### Others
from core.decorators.login import auth_required, admin_required
from core.decorators.intercept import ldap_backend_intercept
from core.ldap.connector import LDAPConnector
import logging
################################################################################

logger = logging.getLogger(__name__)


class LDAPRecordViewSet(BaseViewSet, DNSRecordMixin, DomainViewMixin):
	@auth_required
	@admin_required
	@ldap_backend_intercept
	def create(self, request):
		user: User = request.user
		data: dict = request.data
		code = 0
		record_data: dict = data.get("record", None)
		if not record_data:
			raise exc_dns.DNSRecordNotInRequest

		# Serialize Data
		validated_data = self.validate_record(record_data=record_data)

		# Open LDAP Connection
		with LDAPConnector(user) as ldc:
			self.ldap_connection = ldc.connection
			record_result_data = self.create_record(record_data=validated_data)

		return Response(
			data={
				"code": code,
				"code_msg": "ok",
				"data": record_result_data,
			}
		)

	@auth_required
	@admin_required
	@ldap_backend_intercept
	def update(self, request, pk=None):
		user: User = request.user
		data: dict = request.data
		code = 0

		old_record_data: dict = data.get("oldRecord", None)
		record_data: dict = data.get("record", None)
		if not old_record_data or not record_data:
			raise exc_dns.DNSRecordNotInRequest

		# New Record Data Validation
		validated_record_data = self.validate_record(record_data=record_data)
		# Old Record Data Validation
		validated_old_record_data = self.validate_record(
			record_data=old_record_data
		)

		# Open LDAP Connection
		with LDAPConnector(user) as ldc:
			self.ldap_connection = ldc.connection
			record_result_data = self.update_record(
				record_data=validated_record_data,
				old_record_data=validated_old_record_data,
			)

		return Response(
			data={
				"code": code,
				"code_msg": "ok",
				"data": record_result_data,
			}
		)

	@auth_required
	@admin_required
	@ldap_backend_intercept
	def destroy(self, request):
		user: User = request.user
		data: dict = request.data
		code = 0
		result = None
		record_delete = data.get("record", None)
		multi_record_delete = data.get("records", None)

		if not record_delete and not multi_record_delete:
			raise exc_dns.DNSRecordNotInRequest
		elif record_delete and multi_record_delete:
			raise exc_dns.DNSRecordOperationConflict

		# Open LDAP Connection
		with LDAPConnector(user) as ldc:
			self.ldap_connection = ldc.connection

			# Data Validation
			# Single Record Delete
			if record_delete:
				if not isinstance(record_delete, dict):
					raise exc_dns.DNSRecordDataMalformed
				# Record Data Validation
				validated_record_data = self.validate_record(
					record_data=record_delete
				)
				result = self.delete_record(record_data=validated_record_data)
			# Multi Record Delete
			if multi_record_delete:
				result = []
				if not isinstance(multi_record_delete, list):
					raise exc_dns.DNSRecordDataMalformed
				for _record in multi_record_delete:
					if not isinstance(_record, dict):
						raise exc_dns.DNSRecordDataMalformed
					validated_record_data = self.validate_record(
						record_data=_record
					)

					result.append(
						self.delete_record(record_data=validated_record_data)
					)

		return Response(data={"code": code, "code_msg": "ok", "data": result})
