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
from core.models.ldap_tree import LDAPTree
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
from core.constants.attrs import *
from rest_framework import status
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


class LdapDirtreeViewSet(BaseViewSet, OrganizationalUnitMixin):
	@auth_required
	@admin_required
	@ldap_backend_intercept
	@action(
		detail=False,
		methods=["get"],
		url_name="organizational-units",
		url_path="organizational-units",
	)
	def get_organizational_units(self, request: Request):
		user: User = request.user
		code = 0
		code_msg = "ok"

		search_attrs = [
			v
			for v in (
				# User Attrs
				LDAP_ATTR_OBJECT_CLASS,
				LDAP_ATTR_OBJECT_CATEGORY,
				RuntimeSettings.LDAP_OU_FIELD,
				# Group Attrs
				LDAP_ATTR_COMMON_NAME,
				LDAP_ATTR_GROUP_MEMBERS,
				LDAP_ATTR_DN,
				LDAP_ATTR_GROUP_TYPE,
				LDAP_ATTR_SECURITY_ID,
			)
			if v
		]

		# Read-only end-point, build filters from default dictionary
		search_filter = LDAPFilter.or_(
			LDAPFilter.eq(LDAP_ATTR_OBJECT_CATEGORY, "organizationalUnit"),
			LDAPFilter.eq(LDAP_ATTR_OBJECT_CATEGORY, "top"),
			LDAPFilter.eq(LDAP_ATTR_OBJECT_CATEGORY, "container"),
			LDAPFilter.eq(LDAP_ATTR_OBJECT_CLASS, "builtinDomain"),
		).to_string()

		# Open LDAP Connection
		with LDAPConnector(user) as ldc:
			self.ldap_connection = ldc.connection

			try:
				if DIRTREE_PERF_LOGGING:
					perf_c_start = perf_counter()
				dirtree = LDAPTree(
					connection=self.ldap_connection,
					recursive=True,
					search_filter=search_filter,
					search_attrs=search_attrs,
				)
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

	@auth_required
	@admin_required
	@ldap_backend_intercept
	def list(self, request: Request):
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
				data_filter=data_filter, default_filter=data_filter_use_defaults
			).to_string()
		except Exception as e:
			logger.exception(e)
			raise exc_dirtree.DirtreeFilterBad

		ldap_filter_attr = [
			# User Attrs
			LDAP_ATTR_OBJECT_CLASS,
			LDAP_ATTR_OBJECT_CATEGORY,
			RuntimeSettings.LDAP_OU_FIELD,
			# Group Attrs
			LDAP_ATTR_COMMON_NAME,
			LDAP_ATTR_GROUP_MEMBERS,
			LDAP_ATTR_DN,
			LDAP_ATTR_GROUP_TYPE,
		]

		logger.debug("LDAP Filter constructed.")
		# Open LDAP Connection
		with LDAPConnector(user) as ldc:
			self.ldap_connection = ldc.connection

			# Should have:
			# Filter by Object DN
			# Filter by Attribute
			try:
				if DIRTREE_PERF_LOGGING:
					perf_c_start = perf_counter()
				dir_list = LDAPTree(
					connection=self.ldap_connection,
					recursive=True,
					search_filter=ldap_filter_object,
					search_attrs=ldap_filter_attr,
				)
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

	@auth_required
	@admin_required
	@ldap_backend_intercept
	@action(detail=False, methods=["post"])
	def move(self, request: Request):
		user: User = request.user
		data = request.data
		code = 0
		code_msg = "ok"

		ldap_object: dict = data.get("ldapObject", {})
		if not ldap_object:
			raise exc_base.BadRequest(
				data={"detail": "ldapObject dict is required in data."}
			)
		ldap_path: str = ldap_object.get("destination", None)
		distinguished_name: str = ldap_object.get(LOCAL_ATTR_DN, None)

		if not ldap_path:
			raise exc_base.BadRequest(
				data={"detail": "destination is required."}
			)
		if not distinguished_name:
			raise exc_base.BadRequest(
				data={"detail": "distinguished_name is required."}
			)

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

	@auth_required
	@admin_required
	@ldap_backend_intercept
	@action(detail=False, methods=["post"])
	def rename(self, request: Request):
		user: User = request.user
		data = request.data
		code = 0
		code_msg = "ok"

		ldap_object: dict = data.get("ldapObject", {})
		if not ldap_object:
			raise exc_base.BadRequest(
				data={"detail": "ldapObject dict is required in data."}
			)
		distinguished_name: str = ldap_object.get(LOCAL_ATTR_DN, None)
		new_rdn: str = ldap_object.get("newRDN", None)

		if not distinguished_name:
			raise exc_base.BadRequest(
				data={"detail": "distinguished_name is required."}
			)
		if not new_rdn:
			raise exc_base.BadRequest(data={"detail": "newRDN is required."})

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

	@auth_required
	@admin_required
	@ldap_backend_intercept
	def create(self, request: Request):
		user: User = request.user
		data = request.data
		code = 0
		code_msg = "ok"

		ldap_object: dict = data.get("ldapObject", {})
		if not ldap_object:
			raise exc_base.BadRequest(
				data={"detail": "ldapObject dict is required in data."}
			)

		fields = (
			LOCAL_ATTR_NAME,
			LOCAL_ATTR_PATH,
			LOCAL_ATTR_TYPE,
		)
		for _fld in fields:
			if _fld not in ldap_object:
				logger.error(_fld + " not in LDAP Object.")
				raise exc_ou.MissingField(data={"field": _fld})

		object_name: str = ldap_object[LOCAL_ATTR_NAME]
		object_path: str = ldap_object[LOCAL_ATTR_PATH]
		object_type: str = ldap_object[LOCAL_ATTR_TYPE]

		# Validate object type
		if ldap_object.get(LOCAL_ATTR_TYPE) not in (
			"ou",
			"computer",
			"printer",
		):
			raise exc_base.BadRequest(
				data={
					"detail": "object type must be one of (ou, computer, printer)."
				}
			)

		attributes = {LOCAL_ATTR_NAME: object_name}

		if not object_type or object_type.lower() == "ou":
			object_dn = f"OU={object_name},{object_path}"
			object_type = "organizationalUnit"
			attributes["ou"] = ldap_object.get("ou", object_name)
		else:
			object_dn = f"CN={object_name},{object_path}"

		# Open LDAP Connection
		with LDAPConnector(user) as ldc:
			self.ldap_connection = ldc.connection

			try:
				self.ldap_connection.add(
					dn=object_dn,
					object_class=object_type,
					attributes=attributes,
				)
			except Exception as e:
				logger.exception(e)
				logger.error(f"Could not Add LDAP Object: {object_dn}")
				result_description = getattr(
					self.ldap_connection.result,
					"description",
					"unhandledLdapException",
				)
				code = status.HTTP_500_INTERNAL_SERVER_ERROR
				if result_description.lower() == "entryalreadyexists":
					code = status.HTTP_409_CONFLICT
				raise exc_ou.OUCreate(
					data={
						"ldap_response": result_description,
						"ldapObject": object_name,
						"code": code,
					}
				)

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

	@auth_required
	@admin_required
	@ldap_backend_intercept
	def destroy(self, request: Request, pk=None):
		user: User = request.user
		code = 0
		code_msg = "ok"
		data = request.data

		object_name = data.get(LOCAL_ATTR_NAME)
		object_dn = data.get(LOCAL_ATTR_DN, None)
		if not object_dn:
			raise exc_ldap.LDAPObjectDoesNotExist

		# Open LDAP Connection
		with LDAPConnector(user) as ldc:
			self.ldap_connection = ldc.connection
			try:
				self.ldap_connection.delete(dn=object_dn)
			except Exception as e:
				logger.exception(e)
				logger.error(f"Could not delete LDAP Object: {object_dn}")
				raise exc_base.LDAPBackendException(
					data={
						"ldap_response": getattr(
							self.ldap_connection.result,
							"description",
							"unhandledLdapException",
						)
					}
				)

		DBLogMixin.log(
			user=user.id,
			operation_type=LOG_ACTION_DELETE,
			log_target_class=LOG_CLASS_LDAP,
			log_target=object_name,
		)
		return Response(data={"code": code, "code_msg": code_msg, "data": data})
