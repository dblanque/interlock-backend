################################################################################
#################### INTERLOCK IS LICENSED UNDER GNU AGPLv3 ####################
################## ORIGINAL PROJECT CREATED BY DYLAN BLANQUÉ ###################
########################## AND BR CONSULTING S.R.L. ############################
################################################################################
# Module: core.views.user
# Contains the ViewSet for User related operations

#---------------------------------- IMPORTS -----------------------------------#
### Exceptions
from core.exceptions.base import PermissionDenied, BadRequest
from core.exceptions import (
	base as exc_base,
	users as exc_user, 
	ldap as exc_ldap
)
from interlock_backend.ldap.encrypt import encrypt

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
from interlock_backend.settings import SIMPLE_JWT as JWT_SETTINGS
from interlock_backend.ldap.connector import LDAPConnector
from interlock_backend.ldap.constants_cache import *
from interlock_backend.ldap import adsi as ldap_adsi
from interlock_backend.ldap import user as ldap_user
from core.decorators.login import auth_required
import ldap3
import logging
################################################################################

logger = logging.getLogger(__name__)

class UserViewSet(BaseViewSet, UserViewMixin, UserViewLDAPMixin):
	queryset = User.objects.all()

	@auth_required()
	def list(self, request):
		user = request.user
		data = dict()
		code = 0
		code_msg = 'ok'

		self.ldap_filter_object = "(objectclass=" + LDAP_AUTH_OBJECT_CLASS + ")"
		self.ldap_filter_attr = [
			"givenName",
			"sn",
			"displayName",
			LDAP_AUTH_USER_FIELDS["username"],
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
			LDAP_AUTH_USER_FIELDS["username"], 
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

		user_dn = self.ldap_user_insert(user_data=data)
		user_pwd = data['password']

		self.set_ldap_password(user_dn=user_dn, user_pwd=user_pwd)

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

		######################## Set LDAP Attributes ###########################
		self.ldap_filter_attr = [
			LDAP_AUTH_USER_FIELDS["username"],
			'distinguishedName',
			'userPrincipalName',
		]

		# Check if data has a requested placeholder_password
		required_fields = ['username']
		if 'placeholder_password' in data and data['placeholder_password']:
			if len(data['placeholder_password']) > 0:
				user_placeholder_password = data['placeholder_password']

		# Use CSV column if placeholder not requested
		if not user_placeholder_password:
			required_fields.append('password')

		mapped_user_key = header_mapping[ldap_user.USERNAME]
		if user_placeholder_password:
			mapped_pwd_key = ldap_user.PASSWORD
		else:
			mapped_pwd_key = header_mapping[ldap_user.PASSWORD]
		exclude_keys = [
			mapped_user_key, # LDAP Uses sAMAccountName
			mapped_pwd_key,
			'permission_list', # This array was parsed and calculated, then changed to userAccountControl
			'distinguishedName', # We don't want the front-end generated DN
		]
		########################################################################

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
			user_search = row[mapped_user_key]
			row['path'] = user_path

			if self.ldap_user_exists(user_search=user_search, return_exception=False):
				skipped_users.append(row[mapped_user_key])
				continue

			user_dn = self.ldap_user_insert(
				user_data=row,
				exclude_keys=exclude_keys,
				return_exception=False,
				key_mapping=header_mapping
			)
			if not user_dn:
				failed_users.append({'username': row[mapped_user_key], 'stage': 'permission'})
				continue

			set_pwd = False
			if user_placeholder_password:
				row[mapped_pwd_key] = user_placeholder_password
				set_pwd = True
			elif 'password' in data and len(data['password']) > 0:
				row[mapped_pwd_key] = data['password']
				set_pwd = True

			if set_pwd:
				try:
					self.set_ldap_password(user_dn=user_dn, user_pwd=row[mapped_pwd_key])
				except:
					failed_users.append({'username': row[mapped_user_key], 'stage': 'password'})

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
			LDAP_AUTH_USER_FIELDS["username"],
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

		user_to_update = data[LDAP_AUTH_USER_FIELDS["username"]]
		if 'permission_list' in data: permission_list = data['permission_list']
		else: permission_list = None
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
			permissions_list=permission_list
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
	def bulkUpdate(self, request, pk=None):
		user = request.user
		code = 0
		code_msg = 'ok'
		data = request.data

		# ######################## Set LDAP Attributes ###########################
		# self.ldap_filter_attr = [
		# 	LDAP_AUTH_USER_FIELDS["username"],
		# 	'distinguishedName',
		# 	'userPrincipalName',
		# 	'userAccountControl',
		# ]
		# ########################################################################

		# excludeKeys = [
		# 	# Added keys for front-end normalization
		# 	'name',
		# 	'type',

		# 	# Samba keys to intentionally exclude
		# 	'password', 
		# 	'passwordConfirm',
		# 	'path',
		# 	'permission_list', # This array is parsed and calculated later
		# 	'distinguishedName', # We don't want the front-end generated DN
		# 	'username', # LDAP Uses sAMAccountName
		# 	'whenChanged',
		# 	'whenCreated',
		# 	'lastLogon',
		# 	'badPwdCount',
		# 	'pwdLastSet',
		# 	'is_enabled',
		# 	'sAMAccountType',
		# 	'objectCategory',
		# 	'objectSid',
		# 	'objectRid'
		# ]

		# user_to_update = data['username']
		# permission_list = data['permission_list']
		# for key in excludeKeys:
		# 	if key in data:
		# 		del data[key]

		# # Open LDAP Connection
		# try:
		# 	self.ldap_connection = LDAPConnector(user.dn, user.encryptedPassword, request.user).connection
		# except Exception as e:
		# 	print(e)
		# 	raise exc_ldap.CouldNotOpenConnection

		# self.get_user_object(user_to_update, attributes=ldap3.ALL_ATTRIBUTES)
		# user_entry = self.ldap_connection.entries[0]
		# user_dn = str(user_entry.distinguishedName)

		# self.ldap_user_update(
		# 	user_dn=user_dn,
		# 	user_name=user_to_update,
		# 	user_data=data,
		# 	permissions_list=permission_list
		# )

		# # Unbind the connection
		# self.ldap_connection.unbind()
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
			raise BadRequest

		######################## Set LDAP Attributes ###########################
		self.ldap_filter_object = "(objectclass=" + LDAP_AUTH_OBJECT_CLASS + ")"
		self.ldap_filter_attr = [
			LDAP_AUTH_USER_FIELDS["username"],
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

		if 'username' not in data:
			raise BadRequest

		######################## Set LDAP Attributes ###########################
		self.ldap_filter_object = "(objectclass=" + LDAP_AUTH_OBJECT_CLASS + ")"
		self.ldap_filter_attr = [
			LDAP_AUTH_USER_FIELDS["username"],
			'distinguishedName',
			'userPrincipalName',
			'userAccountControl'
		]
		########################################################################

		if data['username'] == self.request.user: 
			raise exc_user.UserAntiLockout

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
			LDAP_AUTH_USER_FIELDS["username"],
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
		if LDAP_AUTH_USER_FIELDS["username"] in data:
			username = data[LDAP_AUTH_USER_FIELDS["username"]]
		
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
			"authUsernameIdentifier": LDAP_AUTH_USER_FIELDS["username"]
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

		ldap_user_search = data['username']

		# If data request for deletion has user DN
		if 'distinguishedName' in data.keys() and data['distinguishedName'] != "":
			logger.debug('Updating with distinguishedName obtained from front-end')
			logger.debug(data['distinguishedName'])
			dn = data['distinguishedName']
		# Else, search for username dn
		else:
			logger.debug('Updating with user dn search method')
			self.get_user_object(ldap_user_search)
			
			user = self.ldap_connection.entries
			dn = str(user[0].distinguishedName)
			logger.debug(dn)

		if dn is None or dn == "":
			self.ldap_connection.unbind()
			raise exc_user.UserDoesNotExist

		if data['password'] != data['passwordConfirm']:
			self.ldap_connection.unbind()
			raise exc_user.UserPasswordsDontMatch
		
		self.set_ldap_password(user_dn=dn, user_pwd=data['password'])

		# Unbind the connection
		self.ldap_connection.unbind()

		django_user = None
		try:
			django_user = User.objects.get(username=ldap_user_search)
		except Exception as e:
			logger.error(e)
			pass
		if django_user:
			encryptedPass = encrypt(data['password'])
			django_user.encryptedPassword = encryptedPass
			django_user.set_unusable_password()
			django_user.save()

		if LDAP_LOG_UPDATE == True:
			# Log this action to DB
			logToDB(
				user_id=request.user.id,
				actionType="UPDATE",
				objectClass="USER",
				affectedObject=ldap_user_search,
				extraMessage="CHANGED_PASSWORD"
			)

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
			self.ldap_connection = LDAPConnector(force_admin=True).connection
		except Exception as e:
			print(e)
			raise exc_ldap.CouldNotOpenConnection

		ldap_user_search = user.username
		self.get_user_object(ldap_user_search, attributes=[LDAP_AUTH_USER_FIELDS["username"], 'distinguishedName', 'userAccountControl'])
		ldapUser = self.ldap_connection.entries

		if 'distinguishedName' in data.keys() and data['distinguishedName'] != "":
			logger.debug('Updating with distinguishedName obtained from front-end')
			logger.debug(data['distinguishedName'])
			distinguishedName = data['distinguishedName']
		else:
			logger.debug('Updating with user dn search method')

			distinguishedName = str(ldapUser[0].distinguishedName)
			logger.debug(distinguishedName)

		if ldap_adsi.list_user_perms(user=ldapUser[0], perm_search="LDAP_UF_PASSWD_CANT_CHANGE"):
			raise PermissionDenied

		if not distinguishedName or distinguishedName == "":
			self.ldap_connection.unbind()
			raise exc_user.UserDoesNotExist

		if data['password'] != data['passwordConfirm']:
			self.ldap_connection.unbind()
			raise exc_user.UserPasswordsDontMatch
		
		self.set_ldap_password(user_dn=distinguishedName, user_pwd=data['password'])

		# Unbind the connection
		self.ldap_connection.unbind()

		django_user = None
		try:
			django_user = User.objects.get(username=ldap_user_search)
		except Exception as e:
			logger.error(e)
		if django_user:
			encryptedPass = encrypt(data['password'])
			django_user.encryptedPassword = encryptedPass
			django_user.set_unusable_password()
			django_user.save()

		if LDAP_LOG_UPDATE == True:
			# Log this action to DB
			logToDB(
				user_id=request.user.id,
				actionType="UPDATE",
				objectClass="USER",
				affectedObject=ldap_user_search,
				extraMessage="CHANGED_PASSWORD"
			)

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
		user_entry = request.user
		code = 0
		code_msg = 'ok'
		data = request.data

		if data['username'] != user_entry.username:
			raise PermissionDenied

		# Get basic attributes for this user from AD to compare query and get dn
		self.ldap_filter_attr = [
			LDAP_AUTH_USER_FIELDS["username"],
			'distinguishedName',
			'userPrincipalName',
			'userAccountControl',
		]
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

		user_search = data['username']
		for key in excludeKeys:
			if key in data:
				del data[key]

		# Open LDAP Connection
		try:
			self.ldap_connection = LDAPConnector(force_admin=True).connection
		except Exception as e:
			print(e)
			raise exc_ldap.CouldNotOpenConnection

		self.get_user_object(user_search, attributes=ldap3.ALL_ATTRIBUTES)

		user_entry = self.ldap_connection.entries
		user_dn = str(user_entry[0].distinguishedName)

		self.ldap_user_update(
			user_dn=user_dn,
			user_name=user_search,
			user_data=data
		)

		# Unbind the connection
		self.ldap_connection.unbind()

		logger.debug(self.ldap_connection.result)

		if LDAP_LOG_UPDATE == True:
			# Log this action to DB
			logToDB(
				user_id=request.user.id,
				actionType="UPDATE",
				objectClass="USER",
				affectedObject=user_search,
				extraMessage="END_USER_UPDATED"
			)

		try:
			django_user = User.objects.get(username=user_search)
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
		data["access_token_lifetime"] = JWT_SETTINGS["ACCESS_TOKEN_LIFETIME"].total_seconds()
		data["refresh_token_lifetime"] = JWT_SETTINGS["REFRESH_TOKEN_LIFETIME"].total_seconds()
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
		user_entry = request.user
		code = 0
		code_msg = 'ok'
		data = request.data
		user_search = user_entry.username

		# Open LDAP Connection
		try:
			self.ldap_connection = LDAPConnector(user_entry.dn, user_entry.encryptedPassword, request.user).connection
		except Exception as e:
			print(e)
			raise exc_ldap.CouldNotOpenConnection
		self.ldap_filter_attr = [ 
			'givenName', 
			'sn', 
			'displayName', 
			LDAP_AUTH_USER_FIELDS["username"], 
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

		self.ldap_filter_object = "(objectclass=" + LDAP_AUTH_OBJECT_CLASS + ")"

		# Add filter for username
		self.ldap_filter_object = ldap_adsi.search_filter_add(self.ldap_filter_object, LDAP_AUTH_USER_FIELDS["username"] + "=" + user_search)
		self.ldap_connection.search(
			LDAP_AUTH_SEARCH_BASE,
			self.ldap_filter_object,
			attributes=self.ldap_filter_attr
		)
		user_entry = self.ldap_connection.entries

		self.ldap_filter_attr.remove('userAccountControl')

		# For each attribute in user object attributes
		user_data = {}
		for attr_key in self.ldap_filter_attr:
			if attr_key in self.ldap_filter_attr:
				str_key = str(attr_key)
				str_value = str(getattr(user_entry[0],attr_key))
				if str_value == "[]":
					user_data[str_key] = ""
				else:
					user_data[str_key] = str_value
			if attr_key == LDAP_AUTH_USER_FIELDS["username"]:
				user_data['username'] = str_value

			# Check if user can change password based on perms
			user_data['can_change_pwd'] = False
			if not ldap_adsi.list_user_perms(user=user_entry[0], perm_search="LDAP_UF_PASSWD_CANT_CHANGE"):
				user_data['can_change_pwd'] = True

		# Close / Unbind LDAP Connection
		self.ldap_connection.unbind()
		return Response(
			 data={
				'code': code,
				'code_msg': code_msg,
				'data': user_data
			 }
		)
