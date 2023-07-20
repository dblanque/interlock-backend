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

### REST Framework
from rest_framework.response import Response
from rest_framework.exceptions import NotFound
from rest_framework.decorators import action

### Others
from core.utils import dnstool
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

class RecordViewSet(BaseViewSet, DNSRecordMixin):

	@action(detail=False,methods=['post'])
	@auth_required()
	def insert(self, request):
		user = request.user
		data = {}
		code = 0

		if 'record' not in request.data:
			raise exc_dns.DNSRecordNotInRequest

		recordValues = request.data['record']

		if 'type' not in recordValues:
			raise exc_dns.DNSRecordTypeMissing

		requiredAttributes = [
			'name',
			'type',
			'zone',
			'ttl'
		]
		# Add the necessary fields for this Record Type to Required Fields
		requiredAttributes.extend(RECORD_MAPPINGS[recordValues['type']]['fields'])

		for a in requiredAttributes:
			if a not in recordValues:
				exception = exc_dns.DNSRecordDataMissing
				data = {
					"code": exception.default_code,
					"attribute": a,
				}
				exception.set_detail(exception, data)
				raise exception

		record_name = recordValues.pop('name').lower()
		record_type = recordValues.pop('type')
		record_zone = recordValues.pop('zone').lower()

		if record_zone == 'Root DNS Servers':
			raise exc_dns.DNSRootServersOnlyCLI

		# ! Test record validation with the Mix-in
		DNSRecordMixin.validate_record_data(self, record_data=recordValues)

		if record_type == DNS_RECORD_TYPE_SOA and record_name != "@":
			raise exc_dns.SOARecordRootOnly

		if 'stringData' in recordValues:
			if len(recordValues['stringData']) > 255:
				raise exc_dns.DNSStringDataLimit
			
		if 'nameNode' in recordValues:
			label = str(recordValues['nameNode'])
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

		dnsRecord.create(values=recordValues)

		# Update Start of Authority Record Serial
		if record_type != DNS_RECORD_TYPE_SOA:
			self.incrementSOASerial(ldapConnection=ldapConnection, record_zone=record_zone)

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

		old_record_values = request.data['oldRecord']
		recordValues = request.data['record']

		if 'type' not in recordValues:
			raise exc_dns.DNSRecordTypeMissing

		requiredAttributes = [
			'name',
			'type',
			'zone',
			'ttl',
			'index',
			'record_bytes'
		]
		# Add the necessary fields for this Record Type to Required Fields
		requiredAttributes.extend(RECORD_MAPPINGS[recordValues['type']]['fields'])

		for a in requiredAttributes:
			if a not in recordValues:
				exception = exc_dns.DNSRecordDataMissing
				data = {
					"code": exception.default_code,
					"attribute": a,
				}
				exception.set_detail(exception, data)
				raise exception

		old_record_name = old_record_values.pop('name').lower()
		record_name = recordValues.pop('name').lower()

		record_type = recordValues.pop('type')
		record_zone = recordValues.pop('zone').lower()
		record_index = recordValues.pop('index')
		record_bytes = recordValues.pop('record_bytes')
		record_bytes = convert_string_to_bytes(record_bytes)

		if record_zone == 'Root DNS Servers':
			raise exc_dns.DNSRootServersOnlyCLI

		for f in recordValues.keys():
			if f in DNS_FIELD_VALIDATORS:
				if DNS_FIELD_VALIDATORS[f] is not None:
					validator = DNS_FIELD_VALIDATORS[f] + "_validator"
					if getattr(dnsValidators, validator)(recordValues[f]) == False:
						data = {
							'field': f,
							'value': recordValues[f]
						}
						raise exc_dns.DNSFieldValidatorFailed(data=data)

		if 'stringData' in recordValues:
			if len(recordValues['stringData']) > 255:
				raise exc_dns.DNSStringDataLimit

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
			result = dnsRecord.create(values=recordValues)
			if result['result'] == 0:
				# Delete old DNSR after new one is created
				dnsRecord.connection.modify(old_record_values['distinguishedName'], {'dnsRecord': [( MODIFY_DELETE, record_bytes )]})
			else:
				raise exc_dns.BaseException
		else:
			dnsRecord = LDAPRecord(
				connection=ldapConnection,
				rName=record_name,
				rZone=record_zone,
				rType=record_type
			)
			result = dnsRecord.update(values=recordValues, oldRecordBytes=record_bytes)

		#########################################
		# Update Start of Authority Record Serial
		if record_type != DNS_RECORD_TYPE_SOA:
			self.incrementSOASerial(ldapConnection=ldapConnection, record_zone=record_zone)

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
			result = self.delete_record(recordValues, user)
		elif isinstance(recordValues, list):
			result = list()
			for r in recordValues:
				print(r)
				result.append(self.delete_record(r, user))

		return Response(
			 data={
				'code': code,
				'code_msg': 'ok',
				'data' : result
			 }
		)
