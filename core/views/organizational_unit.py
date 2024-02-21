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
	ldap as exc_ldap,
	dirtree as exc_dirtree,
	organizational_unit as exc_ou
)

### ViewSets
from .base import BaseViewSet

### Models
from core.models.log import logToDB
from core.models.ldapTree import LDAPTree

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
from interlock_backend.ldap.constants_cache import *
from ldap3.utils.dn import safe_rdn
import logging
################################################################################

logger = logging.getLogger(__name__)

class OrganizationalUnitViewSet(BaseViewSet, OrganizationalUnitMixin):

	@auth_required()
	def list(self, request):
		user = request.user
		data = request.data
		code = 0
		code_msg = 'ok'

		# Open LDAP Connection
		try:
			c = LDAPConnector(user.dn, user.encryptedPassword, request.user).connection
		except Exception as e:
			print(e)
			raise exc_ldap.CouldNotOpenConnection

		attributesToSearch = [
			# User Attrs
			'objectClass',
			'objectCategory',
			LDAP_OU_FIELD,

			# Group Attrs
			'cn',
			'member',
			'distinguishedName',
			'groupType',
			'objectSid'
		]

		# Read-only end-point, build filters from default dictionary
		filterDict = LDAP_DIRTREE_OU_FILTER
		ldapFilter = search_filter_from_dict(filterDict)

		try:
			debugTimerStart = perf_counter()
			dirList = LDAPTree(**{
				"connection": c,
				"recursive": True,
				"ldapFilter": ldapFilter,
				"ldapAttributes": attributesToSearch,
			})
			debugTimerEnd = perf_counter()
			logger.info("Dirtree Fetch Time Elapsed: " + str(round(debugTimerEnd - debugTimerStart, 3)))
		except Exception as e:
			print(e)
			raise exc_ldap.CouldNotFetchDirtree

		if LDAP_LOG_READ == True:
			# Log this action to DB
			logToDB(
				user_id=request.user.id,
				actionType="READ",
				objectClass="OU",
				affectedObject="ALL - List Query"
			)

		# Close / Unbind LDAP Connection
		c.unbind()
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
		user = request.user
		data = request.data
		code = 0
		code_msg = 'ok'

		try:
			ldap_filter_object = self.processFilter(data)
		except Exception as e:
			print(e)
			raise exc_dirtree.DirtreeFilterBad

		# Open LDAP Connection
		try:
			c = LDAPConnector(user.dn, user.encryptedPassword, request.user).connection
		except Exception as e:
			print(e)
			raise exc_ldap.CouldNotOpenConnection

		ldap_filter_attr = [
			# User Attrs
			'objectClass',
			'objectCategory',
			LDAP_OU_FIELD,

			# Group Attrs
			'cn',
			'member',
			'distinguishedName',
			'groupType',
			'objectSid'
		]

		# Should have:
		# Filter by Object DN
		# Filter by Attribute
		try:
			debugTimerStart = perf_counter()
			dirList = LDAPTree(**{
				"connection": c,
				"recursive": True,
				"ldapFilter": ldap_filter_object,
				"ldapAttributes": ldap_filter_attr,
			})
			debugTimerEnd = perf_counter()
			logger.info("Dirtree Fetch Time Elapsed: " + str(round(debugTimerEnd - debugTimerStart, 3)))
		except Exception as e:
			print(e)
			c.unbind()
			raise exc_ldap.CouldNotFetchDirtree

		if LDAP_LOG_READ == True:
			# Log this action to DB
			logToDB(
				user_id=request.user.id,
				actionType="READ",
				objectClass="LDAP",
				affectedObject="ALL - Full Dirtree Query"
			)

		# Close / Unbind LDAP Connection
		c.unbind()
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
		user = request.user
		data = request.data
		code = 0
		code_msg = 'ok'

		ldap_object = data['ldapObject']
		ldap_path = ldap_object['destination']
		distinguishedName = ldap_object['distinguishedName']
		
		if 'name' in ldap_object:
			objectName = ldap_object['name']
		else:
			objectName = distinguishedName

		relativeDistinguishedName = distinguishedName.split(",")[0]

		if relativeDistinguishedName == distinguishedName:
			raise exc_dirtree.DirtreeDistinguishedNameConflict

		# Open LDAP Connection
		try:
			self.ldap_connection = LDAPConnector(user.dn, user.encryptedPassword, request.user).connection
		except Exception as e:
			print(e)
			raise exc_ldap.CouldNotOpenConnection
	
		try:
			self.ldap_connection.modify_dn(distinguishedName, relativeDistinguishedName, new_superior=ldap_path)
		except Exception as e:
			print(e)
			data = {
				"ldap_response": self.ldap_connection.result,
				"ldapObject": objectName,
			}
			if self.ldap_connection.result.description == "entryAlreadyExists":
				data[''] = 409
			self.ldap_connection.unbind()
			raise exc_dirtree.DirtreeMove(data=data)

		if LDAP_LOG_UPDATE == True:
			# Log this action to DB
			logToDB(
				user_id=request.user.id,
				actionType="UPDATE",
				objectClass="LDAP",
				affectedObject=objectName,
				extraMessage="MOVE"
			)

		# Close / Unbind LDAP Connection
		self.ldap_connection.unbind()
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
		user = request.user
		data = request.data
		code = 0
		code_msg = 'ok'

		ldap_object = data['ldapObject']
		distinguished_name = ldap_object['distinguishedName']
		
		if 'name' in ldap_object:
			objectName = ldap_object['name']
		else:
			objectName = distinguished_name

		relative_distinguished_name = distinguished_name.split(",")[0]
		new_rdn = ldap_object['newRDN']

		if relative_distinguished_name == new_rdn:
			raise exc_dirtree.DirtreeDistinguishedNameConflict

		new_rdn = str(distinguished_name).split("=")[0].lower() + "=" + new_rdn

		# Open LDAP Connection
		try:
			self.ldap_connection = LDAPConnector(user.dn, user.encryptedPassword, request.user).connection
		except Exception as e:
			print(e)
			raise exc_ldap.CouldNotOpenConnection

		try:
			self.ldap_connection.modify_dn(distinguished_name, new_rdn)
		except Exception as e:
			print(e)
			data = {
				"ldap_response": self.ldap_connection.result,
				"ldapObject": objectName,
			}
			if self.ldap_connection.result.description == "entryAlreadyExists":
				data['code'] = 409
			self.ldap_connection.unbind()
			raise exc_dirtree.DirtreeMove(data=data)

		if LDAP_LOG_UPDATE == True:
			if objectName != ldap_object['name']:
				affected_object = "%s -> %s" % (objectName, ldap_object['name'])
			else:
				affected_object = objectName
			# Log this action to DB
			logToDB(
				user_id=request.user.id,
				actionType="UPDATE",
				objectClass="LDAP",
				affectedObject=affected_object,
				extraMessage="RENAME"
			)

		# Close / Unbind LDAP Connection
		self.ldap_connection.unbind()
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
		user = request.user
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

		object_name = ldap_object['name']
		object_path = ldap_object['path']
		object_type = ldap_object['type']

		attributes = {
			"name": object_name
		}

		if object_type == 'ou' or object_type is None:
			object_dn = "OU=" + object_name + "," + object_path
			object_main = ldap_object['ou']
			object_type = "organizationalUnit"
			attributes["ou"] = object_main
		else:
			object_dn = "CN=" + object_name + "," + object_path

		# Open LDAP Connection
		try:
			self.ldap_connection = LDAPConnector(user.dn, user.encryptedPassword, request.user).connection
		except Exception as e:
			print(e)
			raise exc_ldap.CouldNotOpenConnection

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

		if LDAP_LOG_CREATE == True:
			# Log this action to DB
			logToDB(
				user_id=request.user.id,
				actionType="CREATE",
				objectClass="OU",
				affectedObject=object_name
			)

		# Close / Unbind LDAP Connection
		self.ldap_connection.unbind()
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
		user = request.user
		code = 0
		code_msg = 'ok'
		data = request.data

		# Open LDAP Connection
		try:
			self.ldap_connection = LDAPConnector(user.dn, user.encryptedPassword, request.user).connection
		except Exception as e:
			print(e)
			raise exc_ldap.CouldNotOpenConnection

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
			raise exc_ldap.BaseException(data=data)

		if LDAP_LOG_DELETE == True:
			# Log this action to DB
			logToDB(
				user_id=request.user.id,
				actionType="DELETE",
				objectClass="LDAP",
				affectedObject=data['name']
			)

		# Unbind the connection
		self.ldap_connection.unbind()
		return Response(
			 data={
				'code': code,
				'code_msg': code_msg,
				'data': data
			 }
		)
