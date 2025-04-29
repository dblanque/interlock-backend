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
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.decorators import action

### Others
from time import perf_counter
from core.ldap.filter import LDAPFilter
from core.ldap.connector import LDAPConnector
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
	def list(self, request: Request):
		user: User = request.user
		code = 0
		code_msg = "ok"

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
		search_filter = LDAPFilter.or_(
			LDAPFilter.eq("objectCategory", "organizationalUnit"),
			LDAPFilter.eq("objectCategory", "top"),
			LDAPFilter.eq("objectCategory", "container"),
			LDAPFilter.eq("objectClass", "builtinDomain"),
		).to_string()

		# Open LDAP Connection
		with LDAPConnector(user) as ldc:
			self.ldap_connection = ldc.connection

			ldap_tree_options: LDAPTreeOptions = {
				"connection": self.ldap_connection,
				"recursive": True,
				"ldap_filter": search_filter,
				"ldap_attrs": search_attrs,
			}
			try:
				if DIRTREE_PERF_LOGGING:
					perf_c_start = perf_counter()
				dirtree = LDAPTree(**ldap_tree_options)
				if DIRTREE_PERF_LOGGING:
					perf_c_end = perf_counter()
					logger.info(
						"Dirtree Fetch Time Elapsed: "
						+ str(
							round(
								perf_c_end - perf_c_start,
								PERF_LOGGING_ROUND,
							)
						)
					)
			except Exception as e:
				print(e)
				raise exc_ldap.CouldNotFetchDirtree

		DBLogMixin.log(
			user=user.id,
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
	def dirtree(self, request: Request):
		user: User = request.user
		data: dict = request.data
		code = 0
		code_msg = "ok"

		data_filter: dict = data.get("filter", {})
		data_filter_use_defaults = (
			data_filter.pop("use_defaults", None) if data_filter else None
		)
		try:
			ldap_filter_object = self.process_ldap_filter(
				data_filter=data_filter,
				default_filter=data_filter_use_defaults
			).to_string()
		except Exception as e:
			logger.exception(e)
			raise exc_dirtree.DirtreeFilterBad

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

		logger.debug("LDAP Filter constructed.")
		# Open LDAP Connection
		with LDAPConnector(user) as ldc:
			self.ldap_connection = ldc.connection

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
					perf_c_start = perf_counter()
				dir_list = LDAPTree(**ldap_tree_options)
				if DIRTREE_PERF_LOGGING:
					perf_c_end = perf_counter()
					logger.info(
						"Dirtree Fetch Time Elapsed: "
						+ str(
							round(
								perf_c_end - perf_c_start,
								PERF_LOGGING_ROUND,
							)
						)
					)
			except Exception as e:
				print(e)
				raise exc_ldap.CouldNotFetchDirtree

		DBLogMixin.log(
			user=user.id,
			operation_type=LOG_ACTION_READ,
			log_target_class=LOG_CLASS_LDAP,
			log_target=LOG_TARGET_ALL,
		)
		return Response(
			data={
				"code": code,
				"code_msg": code_msg,
				"ldapObjectList": dir_list.children,
			}
		)

	@action(detail=False, methods=["post"])
	@auth_required
	@admin_required
	@ldap_backend_intercept
	def move(self, request: Request):
		user: User = request.user
		data = request.data
		code = 0
		code_msg = "ok"

		ldap_object: dict = data.get("ldapObject", {})
		if not ldap_object:
			raise exc_base.BadRequest(data={"detail":"ldapObject dict is required in data."})
		ldap_path: str = ldap_object.get("destination", None)
		distinguished_name: str = ldap_object.get("distinguishedName", None)

		if not ldap_path:
			raise exc_base.BadRequest(data={"detail":"destination is required."})
		if not distinguished_name:
			raise exc_base.BadRequest(data={"detail":"distinguishedName is required."})

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
	def rename(self, request: Request):
		user: User = request.user
		data = request.data
		code = 0
		code_msg = "ok"

		ldap_object: dict = data.get("ldapObject", {})
		if not ldap_object:
			raise exc_base.BadRequest(data={"detail":"ldapObject dict is required in data."})
		distinguished_name: str = ldap_object.get("distinguishedName", None)
		new_rdn: str = ldap_object.get("newRDN", None)

		if not distinguished_name:
			raise exc_base.BadRequest(data={"detail":"distinguishedName is required."})
		if not new_rdn:
			raise exc_base.BadRequest(data={"detail":"newRDN is required."})

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
			}
		)

	@action(detail=False, methods=["post"])
	@auth_required
	@admin_required
	@ldap_backend_intercept
	def insert(self, request: Request):
		user: User = request.user
		data = request.data
		code = 0
		code_msg = "ok"

		ldap_object = data["ldapObject"]

		fields = ["name", "path", "type"]
		for f in fields:
			if f not in ldap_object:
				logger.error(f + " not in LDAP Object")
				logger.error(data)
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
				logger.exception(e)
				logger.error(f"Could not Add LDAP Object: {object_dn}")
				logger.error(ldap_object)
				data = {
					"ldap_response": self.ldap_connection.result,
					"ldapObject": object_name,
				}
				if (
					self.ldap_connection.result.description
					== "entryAlreadyExists"
				):
					data["code"] = 409
				raise exc_ou.OUCreate(data=data)

		DBLogMixin.log(
			user=user.id,
			operation_type=LOG_ACTION_CREATE,
			log_target_class=LOG_CLASS_OU,
			log_target=object_name,
		)
		return Response(
			data={
				"code": code,
				"code_msg": code_msg,
			}
		)

	@action(detail=False, methods=["post"])
	@auth_required
	@admin_required
	@ldap_backend_intercept
	def delete(self, request: Request, pk=None):
		user: User = request.user
		code = 0
		code_msg = "ok"
		data = request.data

		# Open LDAP Connection
		with LDAPConnector(user) as ldc:
			self.ldap_connection = ldc.connection
			object_dn = data["distinguishedName"]

			if not object_dn:
				raise exc_ldap.LDAPObjectDoesNotExist
			try:
				self.ldap_connection.delete(object_dn)
			except Exception as e:
				logger.exception(e)
				logger.error(f"Could not delete LDAP Object: {object_dn}")
				data = {"ldap_response": self.ldap_connection.result}
				raise exc_base.CoreException(data=data)

		DBLogMixin.log(
			user=user.id,
			operation_type=LOG_ACTION_DELETE,
			log_target_class=LOG_CLASS_LDAP,
			log_target=data["name"],
		)
		return Response(data={"code": code, "code_msg": code_msg, "data": data})
