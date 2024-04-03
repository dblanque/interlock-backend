################################################################################
#################### INTERLOCK IS LICENSED UNDER GNU AGPLv3 ####################
################## ORIGINAL PROJECT CREATED BY DYLAN BLANQUÉ ###################
########################## AND BR CONSULTING S.R.L. ############################
################################################################################
# Module: core.views.groups
# Contains the ViewSet for Group related operations

#---------------------------------- IMPORTS -----------------------------------#
### Exceptions
from core.exceptions import ldap as exc_ldap

### Mixins
from .mixins.group import GroupViewMixin

### ViewSets
from .base import BaseViewSet

### REST Framework
from rest_framework.response import Response
from rest_framework.decorators import action

### Others
from core.decorators.login import auth_required
from interlock_backend.ldap.connector import LDAPConnector
from interlock_backend.ldap.adsi import search_filter_add
from core.models.ldap_settings_db import *
import logging
################################################################################

logger = logging.getLogger(__name__)

class GroupsViewSet(BaseViewSet, GroupViewMixin):

	@auth_required()
	def list(self, request):
		user = request.user
		data = []
		code = 0
		code_msg = 'ok'

		# Open LDAP Connection
		with LDAPConnector(user.dn, user.encryptedPassword, request.user) as ldc:
			self.ldap_connection = ldc.connection

			self.ldap_filter_object = search_filter_add("", "objectclass=" + 'group')
			self.ldap_filter_attr = [
				'cn',
				'distinguishedName',
				'groupType',
				'member'
			]

			data, valid_attributes = self.list_groups()

		return Response(
			 data={
				'code': code,
				'code_msg': code_msg,
				'groups': data,
				'headers': valid_attributes
			 }
		)

	@action(detail=False,methods=['post'])
	@auth_required()
	def fetch(self, request):
		user = request.user
		data = []
		code = 0
		code_msg = 'ok'

		########################################################################
		group_search = request.data['group']
		group_object_class = 'group'
		self.ldap_filter_attr = [
			'cn',
			'mail',
			'member',
			'distinguishedName',
			'groupType',
			'objectSid'
		]
		self.ldap_filter_object = ""
		self.ldap_filter_object = search_filter_add(self.ldap_filter_object, f"objectclass={group_object_class}")
		self.ldap_filter_object = search_filter_add(self.ldap_filter_object, f"distinguishedName={group_search}")
		########################################################################

		# Open LDAP Connection
		with LDAPConnector(user.dn, user.encryptedPassword, request.user) as ldc:
			self.ldap_connection = ldc.connection
			group_dict, valid_attributes = self.fetch_group()

		return Response(
			 data={
				'code': code,
				'code_msg': code_msg,
				'data': group_dict,
				'headers': valid_attributes
			 }
		)

	@action(detail=False,methods=['post'])
	@auth_required()
	def insert(self, request):
		user = request.user
		code = 0
		code_msg = 'ok'
		data = request.data

		# Open LDAP Connection
		with LDAPConnector(user.dn, user.encryptedPassword, request.user) as ldc:
			self.ldap_connection = ldc.connection

			group_data = data['group']
			# Make sure Group doesn't exist check with CN and authUserField
			self.ldap_filter_object = search_filter_add("", "cn="+group_data['cn'])
			self.ldap_filter_object = search_filter_add(self.ldap_filter_object, LDAP_AUTH_USER_FIELDS["username"]+"="+group_data['cn'], "|")

			# Send LDAP Query for user being created to see if it exists
			self.ldap_filter_attr = [
				'cn',
				'distinguishedName',
				'userPrincipalName',
			]
			self.create_group(group_data=group_data)

		return Response(
			 data={
				'code': code,
				'code_msg': code_msg,
				'data': data
			 }
		)

	@auth_required()
	def update(self, request, pk=None):
		user = request.user
		code = 0
		code_msg = 'ok'
		data = request.data

		# Open LDAP Connection
		with LDAPConnector(user.dn, user.encryptedPassword, request.user) as ldc:
			self.ldap_connection = ldc.connection
			group_data = data['group']
			self.ldap_filter_attr = list(group_data.keys())
			self.update_group(group_data=group_data)

		return Response(
			 data={
				'code': code,
				'code_msg': code_msg
			 }
		)

	@action(detail=False, methods=['post'])
	@auth_required()
	def delete(self, request, pk=None):
		user = request.user
		code = 0
		code_msg = 'ok'
		data = request.data
		group_data = data['group']

		# Open LDAP Connection
		with LDAPConnector(user.dn, user.encryptedPassword, request.user) as ldc:
			self.ldap_connection = ldc.connection
			self.delete_group(group_data=group_data)

		return Response(
			 data={
				'code': code,
				'code_msg': code_msg,
				'data': group_data
			 }
		)
