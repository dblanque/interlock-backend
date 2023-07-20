################################################################################
#################### INTERLOCK IS LICENSED UNDER GNU AGPLv3 ####################
################## ORIGINAL PROJECT CREATED BY DYLAN BLANQUÉ ###################
########################## AND BR CONSULTING S.R.L. ############################
################################################################################
# Module: core.views.user
# Contains the ViewSet for User related operations

#---------------------------------- IMPORTS -----------------------------------#
### Exceptions
from django.core.exceptions import PermissionDenied
from core.exceptions import (
	base as exc_base,
	users as exc_user, 
	ldap as exc_ldap
)
from interlock_backend.settings import SIMPLE_JWT

### Models
from core.models import User
from core.models.log import logToDB

### Mixins
from .mixins.user import UserViewMixin, UserViewLDAPMixin

### Serializers / Validators
from core.serializers import user as UserValidators

### ViewSets
from .base import BaseViewSet

### REST Framework
from rest_framework.response import Response
from rest_framework.decorators import action

### Others
from interlock_backend.ldap.connector import LDAPConnector
from interlock_backend.ldap.constants_cache import *
from interlock_backend.ldap import adsi as ldap_adsi
from interlock_backend.ldap.countries import LDAP_COUNTRIES
from interlock_backend.ldap import user as ldap_user
from core.decorators.login import auth_required
from ldap3 import (
	MODIFY_ADD,
	MODIFY_DELETE,
	MODIFY_INCREMENT,
	MODIFY_REPLACE
)
import ldap3
import traceback
import logging
################################################################################

logger = logging.getLogger(__name__)

class UserViewSet(BaseViewSet, UserViewMixin, UserViewLDAPMixin):
	queryset = User.objects.all()

	@auth_required()
	def list(self, request):
		user = request.user
		data = []
		code = 0
		code_msg = 'ok'

		self.ldap_filter_object = "(objectclass=" + LDAP_AUTH_OBJECT_CLASS + ")"
		self.ldap_filter_attr = [
			"givenName",
			"sn",
			"displayName",
			LDAP_AUTH_USERNAME_IDENTIFIER,
			"mail",
			"distinguishedName",
			"userAccountControl"
		]

		# Open LDAP Connection
		try:
			self.ldap_connection = LDAPConnector(user.dn, user.encryptedPassword, request.user).connection
		except Exception as e:
			print(e)
			raise exc_ldap.CouldNotOpenConnection

		try:
			data = self.ldap_user_list()
		except:
			raise

		# Close / Unbind LDAP Connection
		self.ldap_connection.unbind()
		return Response(
			 data={
				'code': code,
				'code_msg': code_msg,
				'users': data['users'],
				'headers': data['headers']
			 }
		)

	@action(detail=False,methods=['post'])
	@auth_required()
	def fetch(self, request):
		user = request.user
		code = 0
		code_msg = 'ok'
		data = request.data
		user_search = data["username"]

		self.ldap_filter_object = "(objectclass=" + LDAP_AUTH_OBJECT_CLASS + ")"
		self.ldap_filter_attr = [
			'givenName', 
			'sn', 
			'displayName', 
			LDAP_AUTH_USERNAME_IDENTIFIER, 
			'mail',
			'telephoneNumber',
			'streetAddress',
			'postalCode',
			'l', # Local / City
			'st', # State/Province
			'countryCode', # INT
			'co', # 2 Letter Code for Country
			'c', # Full Country Name
			'wWWHomePage',
			'distinguishedName',
			'userPrincipalName',
			'userAccountControl', # Permission ACLs
			'whenCreated',
			'whenChanged',
			'lastLogon',
			'badPwdCount',
			'pwdLastSet',
			'primaryGroupID',
			'objectClass',
			'objectCategory',
			'objectSid',
			'sAMAccountType',
			'memberOf',
		]

		# Open LDAP Connection
		try:
			self.ldap_connection = LDAPConnector(user.dn, user.encryptedPassword, request.user).connection
		except Exception as e:
			print(e)
			raise exc_ldap.CouldNotOpenConnection

		user_data = self.ldap_user_fetch(user_search=user_search)

		# Close / Unbind LDAP Connection
		self.ldap_connection.unbind()
		return Response(
			 data={
				'code': code,
				'code_msg': code_msg,
				'data': user_data
			 }
		)

	@action(detail=False,methods=['post'])
	@auth_required()
	def insert(self, request):
		user = request.user
		code = 0
		code_msg = 'ok'
		data = request.data

		if "username" not in data:
			raise exc_base.MissingDataKey.set_detail({ "key": "username" })

		if data['password'] != data['passwordConfirm']:
			exception = exc_user.UserPasswordsDontMatch
			data = {
				"code": "user_passwords_dont_match",
				"user": data['username']
			}
			exception.set_detail(exception, data)
			raise exception

		user_search = data["username"]

		# Open LDAP Connection
		try:
			self.ldap_connection = LDAPConnector(user.dn, user.encryptedPassword, request.user).connection
		except Exception as e:
			print(e)
			raise exc_ldap.CouldNotOpenConnection

		self.ldap_user_exists(user_search=user_search)

		user_dn = self.ldap_user_insert(data=data)
		user_pwd = data['password']

		self.set_ldap_password(user_dn=user_dn, user_pwd=user_pwd)

		if LDAP_LOG_CREATE == True:
			# Log this action to DB
			logToDB(
				user_id=request.user.id,
				actionType="CREATE",
				objectClass="USER",
				affectedObject=data['username']
			)

		# Unbind the connection
		self.ldap_connection.unbind()
		return Response(
			 data={
				'code': code,
				'code_msg': code_msg,
				'data': data['username']
			 }
		)

	@action(detail=False,methods=['post'])
	@auth_required()
	def bulkInsert(self, request):
		user = request.user
		code = 0
		code_msg = 'ok'
		data = request.data
		data_keys = ["headers", "users", "path", "mapping"]
		imported_users = list()
		skipped_users = list()
		failed_users = list()

		for k in data_keys:
			if k not in data:
				raise exc_base.MissingDataKey.set_detail({ "key": k })

		user_headers = data['headers']
		user_list = data['users']
		user_path = data['path']
		user_placeholder_password = None
		header_mapping = data['mapping']

		# Check if data has a requested placeholder_password
		required_fields = ['username']
		if 'placeholder_password' in data and data['placeholder_password']:
			if len(data['placeholder_password']) > 0:
				user_placeholder_password = data['placeholder_password']

		# Use CSV column if placeholder not requested
		if not user_placeholder_password:
			required_fields.append('password')

		# Validate Front-end mapping with CSV Headers
		for k in required_fields:
			if k not in header_mapping:
				exception = exc_user.UserBulkInsertMappingError
				data = {
					"key": k
				}
				exception.set_detail(exception, data)
				raise exception

		# Validate all usernames before opening connection
		for row in user_list:
			mapped_user_key = header_mapping[ldap_user.USERNAME]
			if user_placeholder_password:
				mapped_pwd_key = ldap_user.PASSWORD
			else:
				mapped_pwd_key = header_mapping[ldap_user.PASSWORD]

			if len(row) != len(user_headers):
				exception = exc_user.UserBulkInsertLengthError
				data = {
					"user": row[mapped_user_key]
				}
				exception.set_detail(exception, data)
				raise exception

			for f in row.keys():
				if f in UserValidators.FIELD_VALIDATORS:
					if UserValidators.FIELD_VALIDATORS[f] is not None:
						validator = UserValidators.FIELD_VALIDATORS[f] + "_validator"
						if getattr(UserValidators, validator)(row[f]) == False:
							if len(user_list) > 1:
								failed_users.append({'username': row[mapped_user_key], 'stage': 'validation'})
								user_list.remove(row)
							else:
								data = {
									'field': f,
									'value': row[f]
								}
								raise exc_user.UserFieldValidatorFailed(data=data)

		# Open LDAP Connection
		try:
			self.ldap_connection = LDAPConnector(user.dn, user.encryptedPassword, request.user).connection
		except Exception as e:
			print(e)
			raise exc_ldap.CouldNotOpenConnection

		for row in user_list:
			userToSearch = row[mapped_user_key]

			# Send LDAP Query for user being created to see if it exists
			attributes = [
				LDAP_AUTH_USERNAME_IDENTIFIER,
				'distinguishedName',
				'userPrincipalName',
			]
			self.get_user_object(userToSearch, attributes=attributes)
			user = self.ldap_connection.entries

			# If user exists, move to next user
			if user != []:
				skipped_users.append(row[mapped_user_key])
				continue

			if user_path is not None and user_path != "":
				userDN = f"CN={row[mapped_user_key]},{user_path}"
			else:
				userDN = f"CN={row[mapped_user_key]},OU=Users,{LDAP_AUTH_SEARCH_BASE}"
			userPermissions = 0

			# Add permissions selected in user creation
			if 'permission_list' in row:
				for perm in row['permission_list']:
					permValue = int(ldap_adsi.LDAP_PERMS[perm]['value'])
					try:
						userPermissions += permValue
						logger.debug("Located in: "+__name__+".insert")
						logger.debug("Permission Value added (cast to string): " + str(permValue))
					except Exception as error:
						if len(user_list) > 1:
							failed_users.append({'username': row[mapped_user_key], 'stage': 'permission'})
							continue
						else: # If there's an error unbind the connection and print traceback
							self.ldap_connection.unbind()
							print(traceback.format_exc())
							raise exc_user.UserPermissionError # Return error code to client

			# Add Normal Account permission to list
			userPermissions += ldap_adsi.LDAP_PERMS['LDAP_UF_NORMAL_ACCOUNT']['value']
			logger.debug("Final User Permissions Value: " + str(userPermissions))

			arguments = dict()
			arguments['userAccountControl'] = userPermissions
			arguments[LDAP_AUTH_USERNAME_IDENTIFIER] = str(row[mapped_user_key]).lower()
			arguments['objectClass'] = ['top', 'person', 'organizationalPerson', 'user']
			arguments['userPrincipalName'] = row[mapped_user_key] + '@' + LDAP_DOMAIN

			excludeKeys = [
				mapped_user_key, # LDAP Uses sAMAccountName
				mapped_pwd_key,
				'permission_list', # This array was parsed and calculated, then changed to userAccountControl
				'distinguishedName', # We don't want the front-end generated DN
			]
			for key in row:
				if key not in excludeKeys and len(row[key]) > 0:
					logger.debug("Key in data: " + key)
					logger.debug("Value for key above: " + row[key])
					if key in header_mapping.values():
						ldap_key = list(header_mapping.keys())[list(header_mapping.values()).index(key)]
						arguments[ldap_key] = row[key]
					else:
						arguments[key] = row[key]

			if 'co' in arguments and arguments['co'] != "" and arguments['co'] != 0:
				try:
					# Set numeric country code (DCC Standard)
					arguments['countryCode'] = LDAP_COUNTRIES[arguments['co']]['dccCode']
					# Set ISO Country Code
					arguments['c'] = LDAP_COUNTRIES[arguments['co']]['isoCode']
				except Exception as e:
					if len(user_list) > 1:
						failed_users.append({'username': row[mapped_user_key], 'stage': 'country'})
						continue
					else:
						self.ldap_connection.unbind()
						print(data)
						print(e)
						raise exc_user.UserCountryUpdateError

			logger.debug('Creating user in DN Path: ' + userDN)
			try:
				self.ldap_connection.add(userDN, LDAP_AUTH_OBJECT_CLASS, attributes=arguments)
			except Exception as e:
				if len(user_list) > 1:
					failed_users.append({'username': row[mapped_user_key], 'stage': 'create'})
					continue
				else:
					self.ldap_connection.unbind()
					print(e)
					print(f'Could not create User: {userDN}')
					row = {
						"ldap_response": self.ldap_connection.result
					}
					raise exc_user.UserCreate(data=row)

			if user_placeholder_password:
				row[mapped_pwd_key] = user_placeholder_password

			try:
				self.ldap_connection.extend.microsoft.modify_password(
					user=userDN, 
					new_password=row[mapped_pwd_key]
				)
			except Exception as e:
				if len(user_list) > 1:
					failed_users.append({'username': row[mapped_user_key], 'stage': 'password'})
					continue
				else:
					self.ldap_connection.unbind()
					print(f'Could not update password for User DN: {userDN}')
					row = {
						"ldap_response": self.ldap_connection.result
					}
					raise exc_user.UserUpdateError(data=row)

			imported_users.append(row[mapped_user_key])
			if LDAP_LOG_CREATE == True:
				# Log this action to DB
				logToDB(
					user_id=request.user.id,
					actionType="CREATE",
					objectClass="USER",
					affectedObject=row[mapped_user_key]
				)

		# Unbind the connection
		self.ldap_connection.unbind()
		return Response(
			 status=200,
			 data={
				'code': code,
				'code_msg': code_msg,
				'imported_users': imported_users,
				'skipped_users': skipped_users,
				'failed_users': failed_users
			 }
		)

	@auth_required()
	def update(self, request, pk=None):
		user = request.user
		code = 0
		code_msg = 'ok'
		data = request.data
		data = data['user']

		######################## Set LDAP Attributes ###########################
		self.ldap_filter_attr = [
			LDAP_AUTH_USERNAME_IDENTIFIER,
			'distinguishedName',
			'userPrincipalName',
			'userAccountControl',
		]
		########################################################################

		excludeKeys = [
			# Added keys for front-end normalization
			'name',
			'type',

			# Samba keys to intentionally exclude
			'password', 
			'passwordConfirm',
			'path',
			'permission_list', # This array is parsed and calculated later
			'distinguishedName', # We don't want the front-end generated DN
			'username', # LDAP Uses sAMAccountName
			'whenChanged',
			'whenCreated',
			'lastLogon',
			'badPwdCount',
			'pwdLastSet',
			'is_enabled',
			'sAMAccountType',
			'objectCategory',
			'objectSid',
			'objectRid'
		]

		user_to_update = data['username']
		permList = data['permission_list']
		for key in excludeKeys:
			if key in data:
				del data[key]

		# Open LDAP Connection
		try:
			self.ldap_connection = LDAPConnector(user.dn, user.encryptedPassword, request.user).connection
		except Exception as e:
			print(e)
			raise exc_ldap.CouldNotOpenConnection

		self.get_user_object(user_to_update, attributes=ldap3.ALL_ATTRIBUTES)
		user_entry = self.ldap_connection.entries[0]
		user_dn = str(user_entry.distinguishedName)

		self.ldap_user_update(
			user_dn=user_dn,
			user_name=user_to_update,
			user_data=data,
			permissions_list=permList
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

	@action(detail=False,methods=['post'])
	@auth_required()
	def bulkAccountStatusChange(self, request):
		user = request.user
		code = 0
		code_msg = 'ok'
		request_data = request.data
		disable_users = request_data["disable"]
		data = request_data["users"]

		if not isinstance(disable_users, bool) or not isinstance(data, list):
			raise exc_base.BaseException

		######################## Set LDAP Attributes ###########################
		self.ldap_filter_object = "(objectclass=" + LDAP_AUTH_OBJECT_CLASS + ")"
		self.ldap_filter_attr = [
			LDAP_AUTH_USERNAME_IDENTIFIER,
			'distinguishedName',
			'userPrincipalName',
			'userAccountControl',
		]
		########################################################################

		# Open LDAP Connection
		try:
			self.ldap_connection = LDAPConnector(user.dn, user.encryptedPassword, request.user).connection
		except Exception as e:
			print(e)
			raise exc_ldap.CouldNotOpenConnection

		success = list()
		for user_object in data:
			if disable_users and user_object["is_enabled"]:
				try:
					self.ldap_user_disable(user_object=user_object)
					success.append(user_object["username"])
				except:
					self.ldap_connection.unbind()
					raise
			elif not disable_users and not user_object["is_enabled"]:
				try:
					self.ldap_user_enable(user_object=user_object)
					success.append(user_object["username"])
				except:
					self.ldap_connection.unbind()
					raise
			else: continue

		# Unbind the connection
		self.ldap_connection.unbind()
		return Response(
			 data={
				'code': code,
				'code_msg': code_msg,
				'data': success
			 }
		)

	@action(detail=False,methods=['post'])
	@auth_required()
	def disable(self, request):
		user = request.user
		code = 0
		code_msg = 'ok'
		data = request.data

		######################## Set LDAP Attributes ###########################
		self.ldap_filter_object = "(objectclass=" + LDAP_AUTH_OBJECT_CLASS + ")"
		self.ldap_filter_attr = [
			LDAP_AUTH_USERNAME_IDENTIFIER,
			'distinguishedName',
			'userPrincipalName',
			'userAccountControl'
		]
		########################################################################

		# Open LDAP Connection
		try:
			self.ldap_connection = LDAPConnector(user.dn, user.encryptedPassword, request.user).connection
		except Exception as e:
			print(e)
			raise exc_ldap.CouldNotOpenConnection

		try:
			self.ldap_user_disable(user_object=data)
		except:
			self.ldap_connection.unbind()
			raise

		# Unbind the connection
		self.ldap_connection.unbind()
		return Response(
			 data={
				'code': code,
				'code_msg': code_msg
			 }
		)

	@action(detail=False,methods=['post'])
	@auth_required()
	def enable(self, request):
		user = request.user
		code = 0
		code_msg = 'ok'
		data = request.data

		######################## Set LDAP Attributes ###########################
		self.ldap_filter_object = "(objectclass=" + LDAP_AUTH_OBJECT_CLASS + ")"
		self.ldap_filter_attr = [
			LDAP_AUTH_USERNAME_IDENTIFIER,
			'distinguishedName',
			'userPrincipalName',
			'userAccountControl'
		]
		########################################################################

		# Open LDAP Connection
		try:
			self.ldap_connection = LDAPConnector(user.dn, user.encryptedPassword, request.user).connection
		except Exception as e:
			print(e)
			raise exc_ldap.CouldNotOpenConnection

		try:
			self.ldap_user_enable(user_object=data)
		except:
			self.ldap_connection.unbind()
			raise

		# Unbind the connection
		self.ldap_connection.unbind()
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

		if not isinstance(data, dict):
			raise exc_base.BaseException

		# Open LDAP Connection
		try:
			self.ldap_connection = LDAPConnector(user.dn, user.encryptedPassword, request.user).connection
		except Exception as e:
			print(e)
			raise exc_ldap.CouldNotOpenConnection
			
		try:
			self.ldap_user_delete(user_object=data)
		except:
			self.ldap_connection.unbind()
			raise

		username = data['username']
		if LDAP_AUTH_USERNAME_IDENTIFIER in data:
			username = data[LDAP_AUTH_USERNAME_IDENTIFIER]
		
		userToDelete = None
		try:
			userToDelete = User.objects.get(username=username)
		except:
			self.ldap_connection.unbind()
			pass
		if userToDelete:
			userToDelete.delete_permanently()

		# Unbind the connection
		self.ldap_connection.unbind()
		return Response(
			 data={
				'code': code,
				'code_msg': code_msg,
				'data': data
			 }
		)

	@action(detail=False, methods=['post'])
	@auth_required()
	def bulkDelete(self, request, pk=None):
		user = request.user
		code = 0
		code_msg = 'ok'
		data = request.data

		if not isinstance(data, list):
			raise exc_base.BaseException

		self.ldap_settings = {
			"authUsernameIdentifier": LDAP_AUTH_USERNAME_IDENTIFIER
		}

		# Open LDAP Connection
		try:
			self.ldap_connection = LDAPConnector(user.dn, user.encryptedPassword, request.user).connection
		except Exception as e:
			print(e)
			raise exc_ldap.CouldNotOpenConnection

		for user in data:
			try:
				self.ldap_user_delete(user_object=user)
			except:
				self.ldap_connection.unbind()
				raise

		# Unbind the connection
		self.ldap_connection.unbind()
		return Response(
			 data={
				'code': code,
				'code_msg': code_msg,
				'data': data
			 }
		)

	@action(detail=False, methods=['post'])
	@auth_required()
	def changePassword(self, request, pk=None):
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

		userToUpdate = data['username']

		# If data request for deletion has user DN
		if 'distinguishedName' in data.keys() and data['distinguishedName'] != "":
			logger.debug('Updating with distinguishedName obtained from front-end')
			logger.debug(data['distinguishedName'])
			dn = data['distinguishedName']
		# Else, search for username dn
		else:
			logger.debug('Updating with user dn search method')
			self.get_user_object(userToUpdate)
			
			user = self.ldap_connection.entries
			dn = str(user[0].distinguishedName)
			logger.debug(dn)

		if dn is None or dn == "":
			self.ldap_connection.unbind()
			raise exc_user.UserDoesNotExist

		if data['password'] != data['passwordConfirm']:
			self.ldap_connection.unbind()
			raise exc_user.UserPasswordsDontMatch

		if LDAP_LOG_UPDATE == True:
			# Log this action to DB
			logToDB(
				user_id=request.user.id,
				actionType="UPDATE",
				objectClass="USER",
				affectedObject=userToUpdate,
				extraMessage="CHANGED_PASSWORD"
			)

		try:
			# ! ADDS does not handle password changing without ldaps
			# enc_pwd = '"{}"'.format(data['password']).encode('utf-16-le')
			# c.modify(dn, {'unicodePwd': [(MODIFY_REPLACE, [enc_pwd] )]})
			# ldap3.extend.microsoft.modifyPassword.ad_modify_password(conn, user_dn, new_password, old_password=None)
			self.ldap_connection.extend.microsoft.modify_password(
				user=dn, 
				new_password=data['password']
			)
		except Exception as e:
			self.ldap_connection.unbind()
			print(e)
			print(f'Could not update password for User DN: {dn}')
			data = {
				"ldap_response": self.ldap_connection.result
			}
			raise exc_user.UserUpdateError(data=data)

		# Unbind the connection
		self.ldap_connection.unbind()
		return Response(
			 data={
				'code': code,
				'code_msg': code_msg,
				'data': data
			 }
		)

	@action(detail=False, methods=['post'])
	@auth_required()
	def unlock(self, request, pk=None):
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

		try:
			self.ldap_user_unlock(user_object=data)
		except:
			self.ldap_connection.unbind()
			raise

		result = self.ldap_connection.result
		if result['description'] == 'success':
			response_result = data['username']
		else:
			self.ldap_connection.unbind()
			raise exc_user.CouldNotUnlockUser

		# Unbind the connection
		self.ldap_connection.unbind()
		return Response(
			 data={
				'code': code,
				'code_msg': code_msg,
				'data': response_result
			 }
		)

	@action(detail=False, methods=['post'])
	@auth_required()
	def bulkUnlock(self, request, pk=None):
		user = request.user
		code = 0
		code_msg = 'ok'
		data = request.data

		if not isinstance(data, list):
			raise exc_base.BaseException

		# Open LDAP Connection
		try:
			self.ldap_connection = LDAPConnector(user.dn, user.encryptedPassword, request.user).connection
		except Exception as e:
			print(e)
			raise exc_ldap.CouldNotOpenConnection

		success = list()
		for user_object in data:
			try:
				self.ldap_user_unlock(user_object=user_object)
				success.append(user_object['username'])
			except:
				self.ldap_connection.unbind()
				raise

		result = self.ldap_connection.result
		if result['description'] == 'success':
			response_result = success
		else:
			self.ldap_connection.unbind()
			raise exc_user.CouldNotUnlockUser

		# Unbind the connection
		self.ldap_connection.unbind()
		return Response(
			 data={
				'code': code,
				'code_msg': code_msg,
				'data': response_result
			 }
		)

	@action(detail=False, methods=['post'])
	@auth_required(require_admin=False)
	def changePasswordSelf(self, request, pk=None):
		user = request.user
		code = 0
		code_msg = 'ok'
		data = request.data

		if data['username'] != user.username:
			raise PermissionDenied

		# Open LDAP Connection
		try:
			self.ldap_connection = LDAPConnector().connection
		except Exception as e:
			print(e)
			raise exc_ldap.CouldNotOpenConnection

		userToUpdate = user.username
		self.get_user_object(userToUpdate, attributes=[LDAP_AUTH_USERNAME_IDENTIFIER, 'distinguishedName', 'userAccountControl'])
		ldapUser = self.ldap_connection.entries

		if 'distinguishedName' in data.keys() and data['distinguishedName'] != "":
			logger.debug('Updating with distinguishedName obtained from front-end')
			logger.debug(data['distinguishedName'])
			distinguishedName = data['distinguishedName']
		else:
			logger.debug('Updating with user dn search method')

			distinguishedName = str(ldapUser[0].distinguishedName)
			logger.debug(distinguishedName)

		if ldap_adsi.list_user_perms(ldapUser[0], permissionToSearch="LDAP_UF_PASSWD_CANT_CHANGE"):
			raise PermissionDenied

		if not distinguishedName or distinguishedName == "":
			self.ldap_connection.unbind()
			raise exc_user.UserDoesNotExist

		if data['password'] != data['passwordConfirm']:
			self.ldap_connection.unbind()
			raise exc_user.UserPasswordsDontMatch

		try:
			self.ldap_connection.extend.microsoft.modify_password(
				user=distinguishedName, 
				new_password=data['password']
			)
		except Exception as e:
			self.ldap_connection.unbind()
			print(e)
			print(f'Could not update password for User DN: {distinguishedName}')
			data = {
				"ldap_response": self.ldap_connection.result
			}
			raise exc_user.UserUpdateError(data=data)

		if LDAP_LOG_UPDATE == True:
			# Log this action to DB
			logToDB(
				user_id=request.user.id,
				actionType="UPDATE",
				objectClass="USER",
				affectedObject=userToUpdate,
				extraMessage="CHANGED_PASSWORD"
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

	@action(detail=False, methods=['put', 'post'])
	@auth_required(require_admin=False)
	def updateSelf(self, request, pk=None):
		user = request.user
		code = 0
		code_msg = 'ok'
		data = request.data

		if data['username'] != user.username:
			raise PermissionDenied

		excludeKeys = [
			'can_change_pwd',
			'password', 
			'passwordConfirm',
			'path',
			'permission_list', # This array is parsed and calculated later
			'distinguishedName', # We don't want the front-end generated DN
			'username', # LDAP Uses sAMAccountName
			'whenChanged',
			'whenCreated',
			'lastLogon',
			'badPwdCount',
			'pwdLastSet',
			'is_enabled',
			'sAMAccountType',
			'objectCategory',
			'userAccountControl',
			'objectClass',
			'primaryGroupID'
		]

		userToUpdate = data['username']
		for key in excludeKeys:
			if key in data:
				del data[key]

		# Open LDAP Connection
		try:
			self.ldap_connection = LDAPConnector().connection
		except Exception as e:
			print(e)
			raise exc_ldap.CouldNotOpenConnection

		# Get basic attributes for this user from AD to compare query and get dn
		attributes = [
			LDAP_AUTH_USERNAME_IDENTIFIER,
			'distinguishedName',
			'userPrincipalName',
			'userAccountControl',
		]
		self.get_user_object(userToUpdate, attributes=ldap3.ALL_ATTRIBUTES)

		user = self.ldap_connection.entries
		dn = str(user[0].distinguishedName)

		if data['co'] != "":
			# Set numeric country code (DCC Standard)
			data['countryCode'] = LDAP_COUNTRIES[data['co']]['dccCode']
			# Set ISO Country Code
			data['c'] = LDAP_COUNTRIES[data['co']]['isoCode']

		# We need to check if the attributes exist in the LDAP Object already
		# To know what operation to apply. This is VERY important.
		arguments = dict()
		for key in data:
				try:
					if key in user[0].entry_attributes and data[key] == "":
						operation = MODIFY_DELETE
						self.ldap_connection.modify(
							dn,
							{key: [( operation ), []]},
						)
					elif data[key] != "":
						operation = MODIFY_REPLACE
						if isinstance(data[key], list):
							self.ldap_connection.modify(
								dn,
								{key: [( operation, data[key])]},
							)
						else:
							self.ldap_connection.modify(
								dn,
								{key: [( operation, [ data[key] ])]},
							)
					else:
						logger.info("No suitable operation for attribute " + key)
						pass
				except:
					print(traceback.format_exc())
					logger.warn("Unable to update user '" + userToUpdate + "' with attribute '" + key + "'")
					logger.warn("Attribute Value:" + str(data[key]))
					logger.warn("Operation Type: " + operation)
					self.ldap_connection.unbind()
					raise exc_user.UserUpdateError

		logger.debug(self.ldap_connection.result)

		if LDAP_LOG_UPDATE == True:
			# Log this action to DB
			logToDB(
				user_id=request.user.id,
				actionType="UPDATE",
				objectClass="USER",
				affectedObject=userToUpdate,
				extraMessage="END_USER_UPDATED"
			)

		try:
			django_user = User.objects.get(username=userToUpdate)
		except:
			django_user = None
			pass

		if django_user:
			for key in LDAP_AUTH_USER_FIELDS:
				mapped_key = LDAP_AUTH_USER_FIELDS[key]
				if mapped_key in data:
					setattr(django_user, key, data[mapped_key])
				if 'mail' not in data:
					django_user.email = None
			django_user.save()

		# Unbind the connection
		self.ldap_connection.unbind()
		return Response(
			 data={
				'code': code,
				'code_msg': code_msg,
				'data': data
			 }
		)

	@action(detail=False, methods=['get'])
	@auth_required(require_admin=False)
	def me(self, request):
		user = request.user
		data = {}
		code = 0
		data["username"] = request.user.username or ""
		data["first_name"] = request.user.first_name or ""
		data["last_name"] = request.user.last_name or ""
		data["email"] = request.user.email or ""
		if request.user.is_superuser:
			data["admin_allowed"] = True
		data["access_token_lifetime"] = SIMPLE_JWT["ACCESS_TOKEN_LIFETIME"].total_seconds()
		data["refresh_token_lifetime"] = SIMPLE_JWT["REFRESH_TOKEN_LIFETIME"].total_seconds()
		return Response(
			 data={
				'code': code,
				'code_msg': 'ok',
				'user': data
			 }
		)

	@action(detail=False,methods=['get'])
	@auth_required(require_admin=False)
	def fetchme(self, request):
		user = request.user
		code = 0
		code_msg = 'ok'
		data = request.data
		userToSearch = user.username

		# Open LDAP Connection
		try:
			c = LDAPConnector(user.dn, user.encryptedPassword, request.user).connection
		except Exception as e:
			print(e)
			raise exc_ldap.CouldNotOpenConnection
		attributes = [ 
			'givenName', 
			'sn', 
			'displayName', 
			LDAP_AUTH_USERNAME_IDENTIFIER, 
			'mail',
			'telephoneNumber',
			'streetAddress',
			'postalCode',
			'l', # Local / City
			'st', # State/Province
			'countryCode', # INT
			'co', # 2 Letter Code for Country
			'c', # Full Country Name
			'wWWHomePage',
			'distinguishedName',
			'userPrincipalName',
			'whenCreated',
			'whenChanged',
			'lastLogon',
			'badPwdCount',
			'pwdLastSet',
			'userAccountControl'
		]

		objectClassFilter = "(objectclass=" + LDAP_AUTH_OBJECT_CLASS + ")"

		# Add filter for username
		objectClassFilter = ldap_adsi.search_filter_add(objectClassFilter, LDAP_AUTH_USERNAME_IDENTIFIER + "=" + userToSearch)
		c.search(
			LDAP_AUTH_SEARCH_BASE,
			objectClassFilter,
			attributes=attributes
		)
		user = c.entries

		attributes.remove('userAccountControl')

		# For each attribute in user object attributes
		user_dict = {}
		for attr_key in attributes:
			if attr_key in attributes:
				str_key = str(attr_key)
				str_value = str(getattr(user[0],attr_key))
				if str_value == "[]":
					user_dict[str_key] = ""
				else:
					user_dict[str_key] = str_value
			if attr_key == LDAP_AUTH_USERNAME_IDENTIFIER:
				user_dict['username'] = str_value

			# Check if user can change password based on perms
			user_dict['can_change_pwd'] = False
			if not ldap_adsi.list_user_perms(user[0], permissionToSearch="LDAP_UF_PASSWD_CANT_CHANGE"):
				user_dict['can_change_pwd'] = True

		# Close / Unbind LDAP Connection
		c.unbind()
		return Response(
			 data={
				'code': code,
				'code_msg': code_msg,
				'data': user_dict
			 }
		)

	@action(detail=False,methods=['get'])
	@auth_required(require_admin=False)
	def logout(self, request):
		user = request.user
		code = 0
		code_msg = 'ok'

		if LDAP_LOG_LOGOUT == True:
			# Log this action to DB
			logToDB(
				user_id=request.user.id,
				actionType="LOGOUT",
				objectClass="USER",
			)

		return Response(
			 data={
				'code': code,
				'code_msg': code_msg,
			 }
		)
