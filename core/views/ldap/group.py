################################################################################
#################### INTERLOCK IS LICENSED UNDER GNU AGPLv3 ####################
################## ORIGINAL PROJECT CREATED BY DYLAN BLANQUÉ ###################
########################## AND BR CONSULTING S.R.L. ############################
################################################################################
# Module: core.views.groups
# Contains the ViewSet for Group related operations

# ---------------------------------- IMPORTS -----------------------------------#
### Models
from core.models.user import User

### Mixins
from core.views.mixins.ldap.group import GroupViewMixin

### Exceptions
from core.exceptions import groups as exc_groups, base as exc_base

### ViewSets
from core.views.base import BaseViewSet

### REST Framework
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.decorators import action

### Others
from core.constants.attrs import (
	LDAP_ATTR_OBJECT_CLASS,
	LDAP_ATTR_DN,
	LDAP_ATTR_GROUP_TYPE,
	LDAP_ATTR_COMMON_NAME,
	LOCAL_ATTR_NAME,
)
from core.serializers.group import LDAPGroupSerializer
from core.constants.group import GroupViewsetFilterAttributeBuilder
from core.decorators.login import auth_required, admin_required
from core.decorators.intercept import ldap_backend_intercept
from core.ldap.connector import LDAPConnector
from core.ldap.filter import LDAPFilter
from core.config.runtime import RuntimeSettings
import logging
################################################################################

logger = logging.getLogger(__name__)


class LDAPGroupsViewSet(BaseViewSet, GroupViewMixin):
	filter_attr_builder = GroupViewsetFilterAttributeBuilder

	@auth_required
	@admin_required
	@ldap_backend_intercept
	def list(self, request: Request):
		user: User = request.user
		data = []
		code = 0
		code_msg = "ok"

		# Open LDAP Connection
		with LDAPConnector(user) as ldc:
			self.ldap_connection = ldc.connection

			self.ldap_filter_object = LDAPFilter.eq(
				LDAP_ATTR_OBJECT_CLASS, "group"
			).to_string()
			self.ldap_filter_attr = self.filter_attr_builder(
				RuntimeSettings
			).get_list_filter()

			data, valid_attributes = self.list_groups()

		return Response(
			data={
				"code": code,
				"code_msg": code_msg,
				"groups": data,
				"headers": valid_attributes,
			}
		)

	@action(detail=False, methods=["post"])
	@auth_required
	@admin_required
	@ldap_backend_intercept
	def fetch(self, request: Request):
		user: User = request.user
		code = 0
		code_msg = "ok"

		########################################################################
		# Check group and distinguishedName keys
		group_search = request.data.get(
			"group", request.data.get(LDAP_ATTR_DN, None)
		)
		if not group_search:
			raise exc_groups.GroupDistinguishedNameMissing

		self.ldap_filter_attr = self.filter_attr_builder(
			RuntimeSettings
		).get_fetch_filter()
		self.ldap_filter_object = LDAPFilter.and_(
			LDAPFilter.eq(LDAP_ATTR_OBJECT_CLASS, "group"),
			LDAPFilter.eq(LDAP_ATTR_DN, group_search),
		).to_string()
		########################################################################

		# Open LDAP Connection
		with LDAPConnector(user) as ldc:
			self.ldap_connection = ldc.connection
			group_dict = self.fetch_group()

		return Response(
			data={
				"code": code,
				"code_msg": code_msg,
				"data": group_dict,
			}
		)

	@action(detail=False, methods=["post"])
	@auth_required
	@admin_required
	@ldap_backend_intercept
	def insert(self, request: Request):
		user: User = request.user
		code = 0
		code_msg = "ok"
		data = request.data

		# Get Group Data
		group_data: dict = data.get("group", None)
		if not group_data or not isinstance(group_data, dict):
			raise exc_base.BadRequest(data={"detail": "group dict is required"})

		# Get Group CN
		group_cn = group_data.get(LOCAL_ATTR_NAME, None)
		if not group_cn or not isinstance(group_cn, str):
			raise exc_base.BadRequest(
				data={
					"detail": "group dict requires a name key containing the Group Common Name."
				}
			)

		# Filter to check Group doesn't exist check with CN, and user field
		self.ldap_filter_object = LDAPFilter.or_(
			LDAPFilter.eq(LDAP_ATTR_COMMON_NAME, group_cn),
			LDAPFilter.eq(
				RuntimeSettings.LDAP_FIELD_MAP["username"],
				group_cn,
			),
		).to_string()

		# Send LDAP Query for user being created to see if it exists
		self.ldap_filter_attr = self.filter_attr_builder(
			RuntimeSettings
		).get_insert_filter()

		# Open LDAP Connection
		with LDAPConnector(user) as ldc:
			self.ldap_connection = ldc.connection
			self.create_group(group_data=group_data)

		return Response(data={"code": code, "code_msg": code_msg, "data": data})

	@auth_required
	@admin_required
	@ldap_backend_intercept
	def update(self, request: Request, pk=None):
		user: User = request.user
		code = 0
		code_msg = "ok"
		data = request.data

		group_data = data.get("group", None)
		if not group_data or not isinstance(group_data, dict):
			raise exc_base.BadRequest(data={"detail": "group dict is required"})
		self.ldap_filter_attr = list(group_data.keys())

		# Open LDAP Connection
		with LDAPConnector(user) as ldc:
			self.ldap_connection = ldc.connection
			self.update_group(data=group_data)

		return Response(data={"code": code, "code_msg": code_msg})

	@action(detail=False, methods=["post"])
	@auth_required
	@admin_required
	@ldap_backend_intercept
	def delete(self, request: Request, pk=None):
		user: User = request.user
		code = 0
		code_msg = "ok"
		data = request.data
		group_data = data.get("group", None)
		if not group_data or not isinstance(group_data, dict):
			raise exc_base.BadRequest(data={"detail": "group dict is required"})

		self.ldap_filter_attr = [LDAP_ATTR_COMMON_NAME, LDAP_ATTR_GROUP_TYPE]

		# Open LDAP Connection
		with LDAPConnector(user) as ldc:
			self.ldap_connection = ldc.connection
			self.delete_group(group_data=group_data)

		return Response(
			data={"code": code, "code_msg": code_msg, "data": group_data}
		)
