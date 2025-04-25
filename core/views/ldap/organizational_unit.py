################################################################################
#################### INTERLOCK IS LICENSED UNDER GNU AGPLv3 ####################
################## ORIGINAL PROJECT CREATED BY DYLAN BLANQUÉ ###################
########################## AND BR CONSULTING S.R.L. ############################
################################################################################
# Module: core.views.organizational_unit
# Contains the ViewSet for Directory Tree and Organizational Unit
# related operations

# ---------------------------------- IMPORTS -----------------------------------#
### Exceptions
from core.exceptions import (
	base as exc_base,
	ldap as exc_ldap,
	dirtree as exc_dirtree,
	organizational_unit as exc_ou,
)

### ViewSets
from core.views.base import BaseViewSet

### Models
from core.views.mixins.logs import LogMixin
from core.models.ldap_tree import LDAPTree, LDAPTreeOptions
from core.models.user import User
from core.models.choices.log import (
	LOG_ACTION_READ,
	LOG_ACTION_CREATE,
	LOG_ACTION_DELETE,
	LOG_CLASS_OU,
	LOG_CLASS_LDAP,
	LOG_TARGET_ALL,
)

### Mixins
from core.views.mixins.ldap.organizational_unit import OrganizationalUnitMixin

### REST Framework
from rest_framework.response import Response
from rest_framework.decorators import action

### Others
from time import perf_counter
from core.ldap.connector import LDAPConnector
from core.ldap.adsi import search_filter_from_dict
from core.decorators.login import auth_required, admin_required
from core.decorators.intercept import ldap_backend_intercept
from core.config.runtime import RuntimeSettings
from interlock_backend.settings import PERF_LOGGING_ROUND, DIRTREE_PERF_LOGGING
import logging
################################################################################

DBLogMixin = LogMixin()
logger = logging.getLogger(__name__)


class LDAPOrganizationalUnitViewSet(BaseViewSet, OrganizationalUnitMixin):
	@auth_required
	@admin_required
	@ldap_backend_intercept
	def list(self, request):
		user: User = request.user
		data = request.data
		code = 0
		code_msg = "ok"

		# Open LDAP Connection
		with LDAPConnector(user) as ldc:
			self.ldap_connection = ldc.connection

			search_attrs = [
				# User Attrs
				"objectClass",
				"objectCategory",
				RuntimeSettings.LDAP_OU_FIELD,
				# Group Attrs
				"cn",
				"member",
				"distinguishedName",
				"groupType",
				"objectSid",
			]

			# Read-only end-point, build filters from default dictionary
			filter_dict = RuntimeSettings.LDAP_DIRTREE_OU_FILTER
			search_filter = search_filter_from_dict(filter_dict)
			ldap_tree_options: LDAPTreeOptions = {
				"connection": self.ldap_connection,
				"recursive": True,
				"ldap_filter": search_filter,
				"ldap_attrs": search_attrs,
			}

			try:
				if DIRTREE_PERF_LOGGING:
					debugTimerStart = perf_counter()
				dirtree = LDAPTree(**ldap_tree_options)
				if DIRTREE_PERF_LOGGING:
					debugTimerEnd = perf_counter()
					logger.info(
						"Dirtree Fetch Time Elapsed: "
						+ str(
							round(
								debugTimerEnd - debugTimerStart,
								PERF_LOGGING_ROUND,
							)
						)
					)
			except Exception as e:
				print(e)
				raise exc_ldap.CouldNotFetchDirtree

			DBLogMixin.log(
				user=request.user.id,
				operation_type=LOG_ACTION_READ,
				log_target_class=LOG_CLASS_OU,
				log_target=LOG_TARGET_ALL,
			)

		return Response(
			data={
				"code": code,
				"code_msg": code_msg,
				"ldapObjectList": dirtree.children,
			}
		)

	@action(detail=False, methods=["post"])
	@auth_required
	@admin_required
	@ldap_backend_intercept
	def dirtree(self, request):
		user: User = request.user
		data: dict = request.data
		code = 0
		code_msg = "ok"

		data_filter: dict = data.get("filter", None)
		data_filter_use_defaults = (
			data_filter.pop("use_defaults", None) if data_filter else None
		)
		try:
			ldap_filter_object = self.process_ldap_filter(
				data_filter, default_filter=data_filter_use_defaults
			).to_string()
		except Exception as e:
			logger.exception(e)
			raise exc_dirtree.DirtreeFilterBad

		logger.debug("LDAP Filter constructed.")
		# Open LDAP Connection
		with LDAPConnector(user) as ldc:
			self.ldap_connection = ldc.connection

			ldap_filter_attr = [
				# User Attrs
				"objectClass",
				"objectCategory",
				RuntimeSettings.LDAP_OU_FIELD,
				# Group Attrs
				"cn",
				"member",
				"distinguishedName",
				"groupType",
				# "objectSid",
			]
			ldap_tree_options: LDAPTreeOptions = {
				"connection": self.ldap_connection,
				"recursive": True,
				"ldap_filter": ldap_filter_object,
				"ldap_attrs": ldap_filter_attr,
			}

			# Should have:
			# Filter by Object DN
			# Filter by Attribute
			try:
				if DIRTREE_PERF_LOGGING:
					debugTimerStart = perf_counter()
				dirList = LDAPTree(**ldap_tree_options)
				if DIRTREE_PERF_LOGGING:
					debugTimerEnd = perf_counter()
					logger.info(
						"Dirtree Fetch Time Elapsed: "
						+ str(
							round(
								debugTimerEnd - debugTimerStart,
								PERF_LOGGING_ROUND,
							)
						)
					)
			except Exception as e:
				print(e)
				raise exc_ldap.CouldNotFetchDirtree

			DBLogMixin.log(
				user=request.user.id,
				operation_type=LOG_ACTION_READ,
				log_target_class=LOG_CLASS_LDAP,
				log_target=LOG_TARGET_ALL,
			)

		return Response(
			data={
				"code": code,
				"code_msg": code_msg,
				"ldapObjectList": dirList.children,
			}
		)

	@action(detail=False, methods=["post"])
	@auth_required
	@admin_required
	@ldap_backend_intercept
	def move(self, request):
		user: User = request.user
		data = request.data
		code = 0
		code_msg = "ok"

		ldap_object = data["ldapObject"]
		ldap_path = ldap_object["destination"]
		distinguished_name = ldap_object["distinguishedName"]

		# Open LDAP Connection
		with LDAPConnector(user) as ldc:
			self.ldap_connection = ldc.connection
			self.move_or_rename_object(
				distinguished_name=distinguished_name, target_path=ldap_path
			)

		return Response(
			data={
				"code": code,
				"code_msg": code_msg,
				# 'user': username,
			}
		)

	@action(detail=False, methods=["post"])
	@auth_required
	@admin_required
	@ldap_backend_intercept
	def rename(self, request):
		user: User = request.user
		data = request.data
		code = 0
		code_msg = "ok"

		ldap_object = data["ldapObject"]
		distinguished_name = ldap_object["distinguishedName"]
		new_rdn = ldap_object["newRDN"]

		# Open LDAP Connection
		with LDAPConnector(user) as ldc:
			self.ldap_connection = ldc.connection
			self.move_or_rename_object(
				distinguished_name=distinguished_name, target_rdn=new_rdn
			)

		return Response(
			data={
				"code": code,
				"code_msg": code_msg,
				# 'user': username,
			}
		)

	@action(detail=False, methods=["post"])
	@auth_required
	@admin_required
	@ldap_backend_intercept
	def insert(self, request):
		user: User = request.user
		data = request.data
		code = 0
		code_msg = "ok"

		ldap_object = data["ldapObject"]

		fields = ["name", "path", "type"]
		for f in fields:
			if f not in ldap_object:
				print(f + "not in LDAP Object")
				print(data)
				raise exc_ou.MissingField

		object_name: str = ldap_object["name"]
		object_path: str = ldap_object["path"]
		object_type: str = ldap_object["type"]

		attributes = {"name": object_name}

		if not object_type or object_type.lower() == "ou":
			object_dn = "OU=" + object_name + "," + object_path
			object_main = ldap_object["ou"]
			object_type = "organizationalUnit"
			attributes["ou"] = object_main
		else:
			object_dn = "CN=" + object_name + "," + object_path

		# Open LDAP Connection
		with LDAPConnector(user) as ldc:
			self.ldap_connection = ldc.connection

			try:
				self.ldap_connection.add(
					object_dn, object_type, attributes=attributes
				)
			except Exception as e:
				print(f"Could not Add LDAP Object: {object_dn}")
				print(ldap_object)
				print(e)
				data = {
					"ldap_response": self.ldap_connection.result,
					"ldapObject": object_name,
				}
				if (
					self.ldap_connection.result.description
					== "entryAlreadyExists"
				):
					data["code"] = 409
				self.ldap_connection.unbind()
				raise exc_ou.OUCreate(data=data)

			DBLogMixin.log(
				user=request.user.id,
				operation_type=LOG_ACTION_CREATE,
				log_target_class=LOG_CLASS_OU,
				log_target=object_name,
			)

		return Response(
			data={
				"code": code,
				"code_msg": code_msg,
				# 'user': username,
			}
		)

	@action(detail=False, methods=["post"])
	@auth_required
	@admin_required
	@ldap_backend_intercept
	def delete(self, request, pk=None):
		user: User = request.user
		code = 0
		code_msg = "ok"
		data = request.data

		# Open LDAP Connection
		with LDAPConnector(user) as ldc:
			self.ldap_connection = ldc.connection

			object_dn = data["distinguishedName"]

			if not object_dn or object_dn == "":
				self.ldap_connection.unbind()
				raise exc_ldap.LDAPObjectDoesNotExist
			try:
				self.ldap_connection.delete(object_dn)
			except Exception as e:
				self.ldap_connection.unbind()
				print(e)
				print(f"Could not delete LDAP Object: {object_dn}")
				data = {"ldap_response": self.ldap_connection.result}
				raise exc_base.CoreException(data=data)

			DBLogMixin.log(
				user=request.user.id,
				operation_type=LOG_ACTION_DELETE,
				log_target_class=LOG_CLASS_LDAP,
				log_target=data["name"],
			)

		return Response(data={"code": code, "code_msg": code_msg, "data": data})
