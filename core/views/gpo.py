################################################################################
#################### INTERLOCK IS LICENSED UNDER GNU AGPLv3 ####################
################## ORIGINAL PROJECT CREATED BY DYLAN BLANQUÉ ###################
########################## AND BR CONSULTING S.R.L. ############################
################################################################################
# Module: core.views.gpo
# Contains the ViewSet for Group Policy Object related operations

# Work in Progress
# src: https://github.com/samba-team/samba/blob/master/python/samba/netcmd/gpo.py
#---------------------------------- IMPORTS -----------------------------------#
### Exceptions
from core.exceptions.base import PermissionDenied, BadRequest
from core.exceptions import (
	ldap as exc_ldap
)

### REST Framework
from rest_framework.response import Response

### ViewSets
from .base import BaseViewSet

### Interlock
from interlock_backend.ldap.connector import LDAPConnector
from core.models.ldap_settings_runtime import RunningSettings

### Others
import struct
from ldap3 import ALL_OPERATIONAL_ATTRIBUTES, ALL_ATTRIBUTES
from core.decorators.login import auth_required
from interlock_backend.ldap.guid import GUID
from interlock_backend.ldap.securityIdentifier import SID
from interlock_backend.ldap import adsi as ldap_adsi
import logging
################################################################################

logger = logging.getLogger(__name__)

class GPOViewSet(BaseViewSet):
	@auth_required()
	def list(self, request):
		user = request.user
		data = dict()
		code = 0
		code_msg = 'ok'

		# Open LDAP Connection
		with LDAPConnector(user.dn, user.encryptedPassword, request.user) as ldc:
			self.ldap_connection = ldc.connection

			# TODO - Make Configuration Page for GPO Sysvol Integration (Mounting system)
			# TODO - Check interaction between actual Policy Data Structure
			# in Sysvol and LDAP GPO Object
			# ! Might have to add cifs-utils as a dependency

			### List GPOs here
			self.ldap_filter_object = ldap_adsi.search_filter_from_dict({
				"*":["gpLink", "objectClass"],
			}, operator="&", reverse_key=False)
			try:
				self.ldap_connection.search(
					RunningSettings.LDAP_AUTH_SEARCH_BASE,
					self.ldap_filter_object,
					attributes=ALL_ATTRIBUTES
				)
			except:
				self.ldap_connection.unbind()
				raise
			data['gpos'] = list()
			data['headers'] = [
				'displayName',
				'gPCFileSysPath',
				'dn',
				'flags'
			]
			for i in self.ldap_connection.entries:
				data['gpos'].append(i.entry_attributes_as_dict)

			for gpo in data['gpos']:
				if 'objectGUID' in gpo:
					try:
						guid_bytes = gpo['objectGUID']
						gpo['objectGUID'] = GUID(guid_bytes).__str__()
					except: raise
				if 'objectSid' in gpo:
					try: gpo['objectSid'] = SID(gpo['objectSid']).__str__()
					except: raise

			self.ldap_filter_object = ldap_adsi.search_filter_from_dict({
				"*":"objectClass",
				"CN={6AC1786C-016F-11D2-945F-00C04FB984F9},CN=Policies,CN=System,DC=brconsulting":"distinguishedName"
			}, operator="&", reverse_key=False)
			try:
				self.ldap_connection.search(
					"CN=Policies,CN=System,DC=brconsulting",
					self.ldap_filter_object,
					attributes=ALL_ATTRIBUTES
				)
			except:
				self.ldap_connection.unbind()
				raise

			print(gpo)
			print(self.ldap_connection.entries)

		return Response(
			 data={
				'code': code,
				'code_msg': code_msg,
				# 'gpos': data['gpos'],
				# 'headers': data['headers']
			 }
		)