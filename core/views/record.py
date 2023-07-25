################################################################################
#################### INTERLOCK IS LICENSED UNDER GNU AGPLv3 ####################
################## ORIGINAL PROJECT CREATED BY DYLAN BLANQUÉ ###################
########################## AND BR CONSULTING S.R.L. ############################
################################################################################
# Module: core.views.record
# Contains the ViewSet for DNS Record related operations

#---------------------------------- IMPORTS -----------------------------------#
### Models
from core.models.log import logToDB
from core.models.dns import LDAPRecord
from core.models.dnsRecordTypes import *
from core.models.dnsRecordClasses import RECORD_MAPPINGS

### ViewSets
from core.views.base import BaseViewSet

### Exceptions
from django.core.exceptions import PermissionDenied
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
from rest_framework.exceptions import NotFound
from rest_framework.decorators import action

### Others
from core.utils import dnstool
import traceback
from ldap3 import (
	MODIFY_ADD,
	MODIFY_DELETE,
	MODIFY_INCREMENT,
	MODIFY_REPLACE
)
from core.utils.dnstool import record_to_dict
from core.views.mixins.utils import convert_string_to_bytes
from core.models.dnsRecordFieldValidators import FIELD_VALIDATORS as DNS_FIELD_VALIDATORS
from core.models import dnsRecordFieldValidators as dnsValidators
from interlock_backend.ldap.adsi import search_filter_add
from core.decorators.login import auth_required
from interlock_backend.ldap.constants_cache import *
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

		if 'record' not in request.data:
			raise exc_dns.DNSRecordNotInRequest

		record_data = request.data['record']
		DNSRecordSerializer(self, record_data).is_valid(raise_exception=True)

		if 'type' not in record_data:
			raise exc_dns.DNSRecordTypeMissing

		requiredAttributes = [
			'name',
			'type',
			'zone',
			'ttl'
		]
		# Add the necessary fields for this Record Type to Required Fields
		requiredAttributes.extend(RECORD_MAPPINGS[record_data['type']]['fields'])

		for a in requiredAttributes:
			if a not in record_data:
				exception = exc_dns.DNSRecordDataMissing
				data = {
					"code": exception.default_code,
					"attribute": a,
				}
				exception.set_detail(exception, data)
				raise exception

		record_name = record_data.pop('name').lower()
		record_type = record_data.pop('type')
		record_zone = record_data.pop('zone').lower()

		if record_zone == 'Root DNS Servers':
			raise exc_dns.DNSRootServersOnlyCLI

		# ! Test record validation with the Mix-in
		DNSRecordMixin.validate_record_data(self, record_data=record_data)

		if 'serial' in record_data and isinstance(record_data['serial'], str):
			record_data.pop('serial')

		if record_type == DNS_RECORD_TYPE_SOA and record_name != "@":
			raise exc_dns.SOARecordRootOnly

		if 'stringData' in record_data:
			if len(record_data['stringData']) > 255:
				raise exc_dns.DNSStringDataLimit

		if 'nameNode' in record_data:
			label = str(record_data['nameNode'])
			split_labels = label.split('.')
			if len(split_labels[-1]) > 1:
				raise exc_dns.DNSRecordTypeConflict
			if record_zone not in label:
				print(record_zone)
				raise exc_dns.DNSZoneNotInRequest

		# Open LDAP Connection
		try:
			connector = LDAPConnector(user.dn, user.encryptedPassword, request.user)
			ldapConnection = connector.connection
		except Exception as e:
			print(e)
			raise exc_ldap.CouldNotOpenConnection

		dnsRecord = LDAPRecord(
			connection=ldapConnection,
			rName=record_name,
			rZone=record_zone,
			rType=record_type
		)

		dnsRecord.create(values=record_data)

		#########################################
		# Update Start of Authority Record Serial
		if record_type != DNS_RECORD_TYPE_SOA:
			try:
				self.increment_soa_serial(dnsRecord.soa_object, dnsRecord.serial)
			except:
				logger.error(traceback.format_exc())
				raise exc_dns.DNSCouldNotIncrementSOA

		# result = dnsRecord.structure.getData()
		# dr = dnstool.DNS_RECORD(result)

		ldapConnection.unbind()

		if record_name == "@":
			affectedObject = record_zone + " (" + RECORD_MAPPINGS[record_type]['name'] + ")"
		else:
			affectedObject = record_name + "." + record_zone + " (" + RECORD_MAPPINGS[record_type]['name'] + ")"

		if LDAP_LOG_CREATE == True:
			# Log this action to DB
			logToDB(
				user_id=request.user.id,
				actionType="CREATE",
				objectClass="DNSR",
				affectedObject=affectedObject
			)

		return Response(
			 data={
				'code': code,
				'code_msg': 'ok',
				# 'data' : record_to_dict(dr, ts=False)
			 }
		)

	@auth_required()
	def update(self, request, pk=None):
		user = request.user
		data = {}
		code = 0

		if 'record' not in request.data or 'oldRecord' not in request.data:
			raise exc_dns.DNSRecordNotInRequest

		old_record_data = request.data['oldRecord']
		record_data = request.data['record']

		DNSRecordSerializer(self, old_record_data).is_valid(raise_exception=True)
		DNSRecordSerializer(self, record_data).is_valid(raise_exception=True)

		if 'type' not in record_data:
			raise exc_dns.DNSRecordTypeMissing

		required_values = [
			'name',
			'serial',
			'type',
			'zone',
			'ttl',
			'index',
			'record_bytes'
		]
		# Add the necessary fields for this Record Type to Required Fields
		required_values.extend(RECORD_MAPPINGS[record_data['type']]['fields'])

		for a in required_values:
			if a not in record_data:
				exception = exc_dns.DNSRecordDataMissing
				data = {
					"code": exception.default_code,
					"attribute": a,
				}
				exception.set_detail(exception, data)
				raise exception

		old_record_name = old_record_data['name'].lower()
		record_name = record_data.pop('name').lower()
		record_type = record_data.pop('type')
		record_zone = record_data.pop('zone').lower()
		record_index = record_data.pop('index')
		record_bytes = record_data.pop('record_bytes')
		record_bytes = convert_string_to_bytes(record_bytes)

		if record_zone == 'Root DNS Servers':
			raise exc_dns.DNSRootServersOnlyCLI

		# ! Test record validation with the Mix-in
		DNSRecordMixin.validate_record_data(self, record_data=old_record_data)
		DNSRecordMixin.validate_record_data(self, record_data=record_data)

		if (
			isinstance(record_data['serial'], str)
			or 
      		record_data['serial'] == old_record_data['serial']
		):
			record_data.pop('serial')

		# Open LDAP Connection
		try:
			connector = LDAPConnector(user.dn, user.encryptedPassword, request.user)
			ldapConnection = connector.connection
		except Exception as e:
			print(e)
			raise exc_ldap.CouldNotOpenConnection

		# ! If Record Name is being changed create the new one and delete the old.
		if old_record_name != record_name:
			dnsRecord = LDAPRecord(
				connection=ldapConnection,
				rName=record_name,
				rZone=record_zone,
				rType=record_type
			)
			# Create new Record
			result = dnsRecord.create(values=record_data)
			if result['result'] == 0:
				# Delete old DNSR after new one is created
				dnsRecord.connection.modify(old_record_data['distinguishedName'], {'dnsRecord': [( MODIFY_DELETE, record_bytes )]})
			else:
				raise exc_dns.BaseException
		else:
			dnsRecord = LDAPRecord(
				connection=ldapConnection,
				rName=record_name,
				rZone=record_zone,
				rType=record_type
			)
			result = dnsRecord.update(
				values=record_data,
				old_record_values=old_record_data,
				old_record_bytes=record_bytes
			)

		#########################################
		# Update Start of Authority Record Serial
		if record_type != DNS_RECORD_TYPE_SOA:
			try:
				self.increment_soa_serial(dnsRecord.soa_object, dnsRecord.serial)
			except:
				logger.error(traceback.format_exc())
				raise exc_dns.DNSCouldNotIncrementSOA

		ldapConnection.unbind()

		result = dnsRecord.structure.getData()
		dr = dnstool.DNS_RECORD(result)

		if record_name == "@":
			affectedObject = record_zone + " (" + RECORD_MAPPINGS[record_type]['name'] + ")"
		else:
			affectedObject = record_name + "." + record_zone + " (" + RECORD_MAPPINGS[record_type]['name'] + ")"

		if LDAP_LOG_UPDATE == True:
			# Log this action to DB
			logToDB(
				user_id=request.user.id,
				actionType="UPDATE",
				objectClass="DNSR",
				affectedObject=affectedObject
			)

		return Response(
			 data={
				'code': code,
				'code_msg': 'ok',
				'data' : record_to_dict(dr, ts=False)
			 }
		)

	@action(detail=False, methods=['post'])
	@auth_required()
	def delete(self, request):
		user = request.user
		data = {}
		code = 0

		if 'record' in request.data:
			mode = 'single'
		elif 'records' in request.data:
			mode = 'multiple'
		else:
			raise exc_dns.DNSRecordNotInRequest

		if mode == 'single':
			if isinstance(request.data['record'], dict):
				recordValues = request.data['record']
			else:
				data = {
					'mode': mode,
					'data': request.data['record']
				}
				raise exc_dns.DNSRecordDataMalformed(data=data)
		elif mode == 'multiple':
			if isinstance(request.data['records'], list):
				recordValues = request.data['records']
			else:
				data = {
					'mode': mode,
					'data': request.data['records']
				}
				raise exc_dns.DNSRecordDataMalformed

		if isinstance(recordValues, dict):
			logger.debug(recordValues)
			result = self.delete_record(recordValues, user)
		elif isinstance(recordValues, list):
			result = list()
			for r in recordValues:
				logger.debug(r)
				result.append(self.delete_record(r, user))

		return Response(
			 data={
				'code': code,
				'code_msg': 'ok',
				'data' : result
			 }
		)
