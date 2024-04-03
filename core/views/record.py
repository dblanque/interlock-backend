################################################################################
#################### INTERLOCK IS LICENSED UNDER GNU AGPLv3 ####################
################## ORIGINAL PROJECT CREATED BY DYLAN BLANQUÉ ###################
########################## AND BR CONSULTING S.R.L. ############################
################################################################################
# Module: core.views.record
# Contains the ViewSet for DNS Record related operations

#---------------------------------- IMPORTS -----------------------------------#
### Models
from core.models.dnsRecordTypes import *

### ViewSets
from core.views.base import BaseViewSet

### Exceptions
from core.exceptions import (
	ldap as exc_ldap,
	dns as exc_dns
)

### Mixins
from .mixins.record import DNSRecordMixin
from .mixins.domain import DomainViewMixin

### Serializers
from core.serializers.record import DNSRecordSerializer

### REST Framework
from rest_framework.response import Response
from rest_framework.decorators import action

### Others
from core.utils.dnstool import record_to_dict
from core.decorators.login import auth_required
from core.models.ldap_settings_db import *
from interlock_backend.ldap.connector import LDAPConnector
import logging
################################################################################

logger = logging.getLogger(__name__)

class RecordViewSet(BaseViewSet, DNSRecordMixin, DomainViewMixin):

	@action(detail=False,methods=['post'])
	@auth_required()
	def insert(self, request):
		user = request.user
		data = {}
		code = 0
		required_values = [
			'name',
			'type',
			'zone',
			'ttl'
		]

		if 'record' not in request.data:
			raise exc_dns.DNSRecordNotInRequest

		record_data = request.data['record']
		DNSRecordSerializer(self, record_data).is_valid(raise_exception=True)

		# ! Test record validation with the Mix-in
		DNSRecordMixin.validate_record_data(
			self,
			record_data=record_data,
			required_values=required_values
		)

		# Open LDAP Connection
		with LDAPConnector(user.dn, user.encryptedPassword, request.user) as ldc:
			self.ldap_connection = ldc.connection
			record_result_data = self.create_record(record_data=record_data)

		return Response(
			 data={
				'code': code,
				'code_msg': 'ok',
				'data' : record_to_dict(record_result_data, ts=False)
			 }
		)

	@auth_required()
	def update(self, request, pk=None):
		user = request.user
		data = {}
		code = 0
		required_values = [
			'name',
			'serial',
			'type',
			'zone',
			'ttl',
			'index',
			'record_bytes'
		]

		if 'record' not in request.data or 'oldRecord' not in request.data:
			raise exc_dns.DNSRecordNotInRequest

		old_record_data = request.data['oldRecord']
		record_data = request.data['record']

		# Basic Serializer Validation
		DNSRecordSerializer(self, old_record_data).is_valid(raise_exception=True)
		DNSRecordSerializer(self, record_data).is_valid(raise_exception=True)

		# Regex Validate Old Record Data
		DNSRecordMixin.validate_record_data(
			self, 
			record_data=old_record_data, 
			required_values=required_values
		)
		# Regex Validate New Record Data
		DNSRecordMixin.validate_record_data(
			self, 
			record_data=record_data, 
			required_values=required_values
		)

		# Open LDAP Connection
		with LDAPConnector(user.dn, user.encryptedPassword, request.user) as ldc:
			self.ldap_connection = ldc.connection
			record_result_data = self.update_record(record_data=record_data, old_record_data=old_record_data)

		return Response(
			 data={
				'code': code,
				'code_msg': 'ok',
				'data' : record_to_dict(record_result_data, ts=False)
			 }
		)

	@action(detail=False, methods=['post'])
	@auth_required()
	def delete(self, request):
		user = request.user
		data = {}
		code = 0
		required_values = [
			'name',
			'type',
			'zone',
			'ttl',
			'index',
			'record_bytes'
		]

		key = 'record'
		if 'records' in request.data:
			key = f"{key}s"
		elif 'record' not in request.data:
			raise exc_dns.DNSRecordNotInRequest

		record_data = request.data[key]
		if key == 'record':
			if not isinstance(request.data[key], dict):
				data = {
					'data': request.data[key]
				}
				raise exc_dns.DNSRecordDataMalformed(data=data)
			DNSRecordMixin.validate_record_data(self, record_data=record_data, required_values=required_values.copy())
		elif key == 'records':
			if not isinstance(request.data[key], list):
				data = {
					'data': request.data[key]
				}
				raise exc_dns.DNSRecordDataMalformed
			for r in record_data:
				DNSRecordMixin.validate_record_data(self, record_data=r, required_values=required_values.copy())

		# Open LDAP Connection
		with LDAPConnector(user.dn, user.encryptedPassword, request.user) as ldc:
			self.ldap_connection = ldc.connection
			if isinstance(record_data, dict):
				logger.debug(record_data)
				result = self.delete_record(record_data, user)
			elif isinstance(record_data, list):
				result = list()
				for r in record_data:
					logger.debug(r)
					result.append(self.delete_record(r, user))

		return Response(
			 data={
				'code': code,
				'code_msg': 'ok',
				'data' : result
			 }
		)
