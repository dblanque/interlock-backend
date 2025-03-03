################################################################################
#################### INTERLOCK IS LICENSED UNDER GNU AGPLv3 ####################
################## ORIGINAL PROJECT CREATED BY DYLAN BLANQUÉ ###################
########################## AND BR CONSULTING S.R.L. ############################
################################################################################
# Module: core.views.organizational_unit
# Contains the ViewSet for Directory Tree and Organizational Unit
# related operations

#---------------------------------- IMPORTS -----------------------------------#
### Exceptions
from core.exceptions import (
	base as exc_base,
	ldap as exc_ldap,
	dirtree as exc_dirtree,
	organizational_unit as exc_ou
)

### ViewSets
from .base import BaseViewSet

### Models
from core.views.mixins.logs import LogMixin
from core.models.ldap_tree import LDAPTree, LDAPTreeOptions
from core.models.user import User

### Mixins
from .mixins.organizational_unit import OrganizationalUnitMixin

### REST Framework
from rest_framework.response import Response
from rest_framework.decorators import action

### Others
from time import perf_counter
from interlock_backend.ldap.connector import LDAPConnector
from interlock_backend.ldap.adsi import search_filter_from_dict
from core.decorators.login import auth_required
from core.models.ldap_settings_runtime import RunningSettings
import logging
################################################################################

DBLogMixin = LogMixin()
logger = logging.getLogger(__name__)

class OrganizationalUnitViewSet(BaseViewSet, OrganizationalUnitMixin):

	@auth_required()
	def list(self, request):
		user: User = request.user
		data = request.data
		code = 0
		code_msg = 'ok'

		# Open LDAP Connection
		with LDAPConnector(user) as ldc:
			self.ldap_connection = ldc.connection

			attributesToSearch = [
				# User Attrs
				'objectClass',
				'objectCategory',
				RunningSettings.LDAP_OU_FIELD,

				# Group Attrs
				'cn',
				'member',
				'distinguishedName',
				'groupType',
				'objectSid'
			]

			# Read-only end-point, build filters from default dictionary
			filterDict = RunningSettings.LDAP_DIRTREE_OU_FILTER
			ldapFilter = search_filter_from_dict(filterDict)
			ldap_tree_options: LDAPTreeOptions = {
				"connection": self.ldap_connection,
				"recursive": True,
				"ldapFilter": ldapFilter,
				"ldapAttributes": attributesToSearch,
			}

			try:
				debugTimerStart = perf_counter()
				dirList = LDAPTree(**ldap_tree_options)
				debugTimerEnd = perf_counter()
				logger.info("Dirtree Fetch Time Elapsed: " + str(round(debugTimerEnd - debugTimerStart, 3)))
			except Exception as e:
				print(e)
				raise exc_ldap.CouldNotFetchDirtree

			if RunningSettings.LDAP_LOG_READ == True:
				# Log this action to DB
				DBLogMixin.log(
					user_id=request.user.id,
					actionType="READ",
					objectClass="OU",
					affectedObject="ALL - List Query"
				)

		return Response(
				data={
				'code': code,
				'code_msg': code_msg,
				'ldapObjectList': dirList.children,
				}
		)

	@action(detail=False,methods=['post'])
	@auth_required()
	def dirtree(self, request):
		user: User = request.user
		data = request.data
		code = 0
		code_msg = 'ok'

		try:
			ldap_filter_object = self.processFilter(data)
		except Exception as e:
			print(e)
			raise exc_dirtree.DirtreeFilterBad

		# Open LDAP Connection
		with LDAPConnector(user) as ldc:
			self.ldap_connection = ldc.connection

			ldap_filter_attr = [
				# User Attrs
				'objectClass',
				'objectCategory',
				RunningSettings.LDAP_OU_FIELD,

				# Group Attrs
				'cn',
				'member',
				'distinguishedName',
				'groupType',
				'objectSid'
			]
			ldap_tree_options: LDAPTreeOptions = {
				"connection": self.ldap_connection,
				"recursive": True,
				"ldapFilter": ldap_filter_object,
				"ldapAttributes": ldap_filter_attr,
			}

			# Should have:
			# Filter by Object DN
			# Filter by Attribute
			try:
				debugTimerStart = perf_counter()
				dirList = LDAPTree(**ldap_tree_options)
				debugTimerEnd = perf_counter()
				logger.info("Dirtree Fetch Time Elapsed: " + str(round(debugTimerEnd - debugTimerStart, 3)))
			except Exception as e:
				print(e)
				raise exc_ldap.CouldNotFetchDirtree

			if RunningSettings.LDAP_LOG_READ == True:
				# Log this action to DB
				DBLogMixin.log(
					user_id=request.user.id,
					actionType="READ",
					objectClass="LDAP",
					affectedObject="ALL - Full Dirtree Query"
				)

		return Response(
				data={
				'code': code,
				'code_msg': code_msg,
				'ldapObjectList': dirList.children,
				}
		)

	@action(detail=False,methods=['post'])
	@auth_required()
	def move(self, request):
		user: User = request.user
		data = request.data
		code = 0
		code_msg = 'ok'

		ldap_object = data['ldapObject']
		ldap_path = ldap_object['destination']
		distinguished_name = ldap_object['distinguishedName']

		# Open LDAP Connection
		with LDAPConnector(user) as ldc:
			self.ldap_connection = ldc.connection
			self.move_or_rename_object(distinguished_name=distinguished_name, ldap_path=ldap_path)

		return Response(
				data={
				'code': code,
				'code_msg': code_msg,
				# 'user': username,
				}
		)

	@action(detail=False,methods=['post'])
	@auth_required()
	def rename(self, request):
		user: User = request.user
		data = request.data
		code = 0
		code_msg = 'ok'

		ldap_object = data['ldapObject']
		distinguished_name = ldap_object['distinguishedName']
		new_rdn = ldap_object['newRDN']

		# Open LDAP Connection
		with LDAPConnector(user) as ldc:
			self.ldap_connection = ldc.connection
			self.move_or_rename_object(distinguished_name=distinguished_name, relative_dn=new_rdn)

		return Response(
				data={
				'code': code,
				'code_msg': code_msg,
				# 'user': username,
				}
		)

	@action(detail=False,methods=['post'])
	@auth_required()
	def insert(self, request):
		user: User = request.user
		data = request.data
		code = 0
		code_msg = 'ok'

		ldap_object = data['ldapObject']

		fields = [
			'name',
			'path',
			'type'
		]
		for f in fields:
			if f not in ldap_object:
				print(f + "not in LDAP Object")
				print(data)
				raise exc_ou.MissingField

		object_name: str = ldap_object['name']
		object_path: str = ldap_object['path']
		object_type: str = ldap_object['type']

		attributes = {
			"name": object_name
		}

		if not object_type or object_type.lower() == 'ou':
			object_dn = "OU=" + object_name + "," + object_path
			object_main = ldap_object['ou']
			object_type = "organizationalUnit"
			attributes["ou"] = object_main
		else:
			object_dn = "CN=" + object_name + "," + object_path

		# Open LDAP Connection
		with LDAPConnector(user) as ldc:
			self.ldap_connection = ldc.connection

			try:
				self.ldap_connection.add(object_dn, object_type, attributes=attributes)
			except Exception as e:
				print(f'Could not Add LDAP Object: {object_dn}')
				print(ldap_object)
				print(e)
				data = {
					"ldap_response": self.ldap_connection.result,
					"ldapObject": object_name,
				}
				if self.ldap_connection.result.description == "entryAlreadyExists":
					data["code"] = 409
				self.ldap_connection.unbind()
				raise exc_ou.OUCreate(data=data)

			if RunningSettings.LDAP_LOG_CREATE == True:
				# Log this action to DB
				DBLogMixin.log(
					user_id=request.user.id,
					actionType="CREATE",
					objectClass="OU",
					affectedObject=object_name
				)

		return Response(
				data={
				'code': code,
				'code_msg': code_msg,
				# 'user': username,
				}
		)

	@action(detail=False, methods=['post'])
	@auth_required()
	def delete(self, request, pk=None):
		user: User = request.user
		code = 0
		code_msg = 'ok'
		data = request.data

		# Open LDAP Connection
		with LDAPConnector(user) as ldc:
			self.ldap_connection = ldc.connection

			object_dn = data['distinguishedName']

			if not object_dn or object_dn == "":
				self.ldap_connection.unbind()
				raise exc_ldap.LDAPObjectDoesNotExist
			try:
				self.ldap_connection.delete(object_dn)
			except Exception as e:
				self.ldap_connection.unbind()
				print(e)
				print(f'Could not delete LDAP Object: {object_dn}')
				data = {
					"ldap_response": self.ldap_connection.result
				}
				raise exc_base.CoreException(data=data)

			if RunningSettings.LDAP_LOG_DELETE == True:
				# Log this action to DB
				DBLogMixin.log(
					user_id=request.user.id,
					actionType="DELETE",
					objectClass="LDAP",
					affectedObject=data['name']
				)

		return Response(
			 data={
				'code': code,
				'code_msg': code_msg,
				'data': data
			 }
		)
