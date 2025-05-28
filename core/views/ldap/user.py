################################################################################
#################### INTERLOCK IS LICENSED UNDER GNU AGPLv3 ####################
################## ORIGINAL PROJECT CREATED BY DYLAN BLANQUÉ ###################
########################## AND BR CONSULTING S.R.L. ############################
################################################################################
# Module: core.views.user
# Contains the ViewSet for User related operations

# ---------------------------------- IMPORTS -----------------------------------#
### Exceptions
from core.exceptions.base import PermissionDenied, BadRequest
from core.exceptions import base as exc_base, users as exc_user
from django.core.exceptions import ObjectDoesNotExist
from interlock_backend.encrypt import aes_encrypt, aes_decrypt

### Models
from core.models.user import (
	User,
	USER_PASSWORD_FIELDS,
	USER_TYPE_LDAP,
	USER_TYPE_LOCAL,
)
from core.views.mixins.logs import LogMixin
from core.models.choices.log import (
	LOG_ACTION_UPDATE,
	LOG_ACTION_CREATE,
	LOG_CLASS_USER,
	LOG_EXTRA_USER_CHANGE_PASSWORD,
	LOG_EXTRA_USER_END_USER_UPDATE,
)

### Mixins
from core.views.mixins.ldap.user import LDAPUserMixin

### Serializers / Validators
from core.serializers.user import LDAPUserSerializer

### ViewSets
from core.views.base import BaseViewSet

### REST Framework
from rest_framework import status
from rest_framework.serializers import ValidationError
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.decorators import action

### Auth
from core.decorators.login import auth_required, admin_required
from core.ldap import adsi as ldap_adsi
from core.constants.attrs import *
from core.ldap.connector import LDAPConnector
import ldap3

### Others
from core.ldap.filter import LDAPFilter
from core.decorators.intercept import ldap_backend_intercept
from core.constants.user import LOCAL_PUBLIC_FIELDS
from core.config.runtime import RuntimeSettings
import logging
################################################################################

DBLogMixin = LogMixin()
logger = logging.getLogger(__name__)


class LDAPUserViewSet(BaseViewSet, LDAPUserMixin):
	queryset = User.objects.all()
	serializer_cls = LDAPUserSerializer

	@auth_required
	@admin_required
	@ldap_backend_intercept
	def list(self, request):
		user: User = request.user
		data = {}
		code = 0
		code_msg = "ok"

		self.ldap_filter_object = LDAPFilter.eq(
			RuntimeSettings.LDAP_FIELD_MAP[LOCAL_ATTR_OBJECT_CLASS],
			RuntimeSettings.LDAP_AUTH_OBJECT_CLASS,
		)
		self.ldap_filter_attr = self.filter_attr_builder(
			RuntimeSettings
		).get_list_attrs()

		# Open LDAP Connection
		with LDAPConnector(user) as ldc:
			self.ldap_connection = ldc.connection
			data = self.ldap_user_list()

		return Response(
			data={
				"code": code,
				"code_msg": code_msg,
				"users": data["users"],
				"headers": data["headers"],
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
		data: dict = request.data

		# TODO - Add DN support?
		user_search = None
		for _k in (
			RuntimeSettings.LDAP_FIELD_MAP[LOCAL_ATTR_USERNAME],
			LOCAL_ATTR_USERNAME,
		):
			if not user_search:
				user_search = data.get(_k, None)

		if not user_search or not isinstance(user_search, str):
			raise exc_base.BadRequest

		# Open LDAP Connection
		with LDAPConnector(user) as ldc:
			self.ldap_connection = ldc.connection
			user_data = self.ldap_user_fetch(user_search=user_search)

		return Response(
			data={"code": code, "code_msg": code_msg, "data": user_data}
		)

	@action(detail=False, methods=["post"])
	@auth_required
	@admin_required
	@ldap_backend_intercept
	def insert(self, request):
		user: User = request.user
		code = 0
		code_msg = "ok"
		data: dict = request.data

		user_username = data.get(LOCAL_ATTR_USERNAME, None)
		if not user_username:
			raise exc_base.MissingDataKey(data={"key": LOCAL_ATTR_USERNAME})

		set_pwd = False
		user_pwd = data.get(LOCAL_ATTR_PASSWORD, None)
		user_pwd_confirm = data.get(LOCAL_ATTR_PASSWORD_CONFIRM, None)
		if user_pwd and user_pwd_confirm:
			set_pwd = True

		# Validate user data
		serializer = self.serializer_cls(data=data)
		if not serializer.is_valid():
			raise BadRequest(data={"errors": serializer.errors})
		data = serializer.validated_data

		# Open LDAP Connection
		with LDAPConnector(user) as ldc:
			self.ldap_connection = ldc.connection

			# User Exists check
			self.ldap_user_exists(
				username=user_username,
				email=data.get(
					RuntimeSettings.LDAP_FIELD_MAP[LOCAL_ATTR_EMAIL],
					None,
				),
			)

			if not set_pwd:
				permissions: list = data.get(LOCAL_ATTR_PERMISSIONS, [])
				permissions.append(ldap_adsi.LDAP_UF_ACCOUNT_DISABLE)
				data[LOCAL_ATTR_PERMISSIONS] = permissions
			user_dn = self.ldap_user_insert(data=data)
			if set_pwd:
				self.ldap_set_password(
					user_dn=user_dn,
					user_pwd_new=user_pwd,
					set_by_admin=True,
				)

		return Response(
			data={
				"code": code,
				"code_msg": code_msg,
				"data": data[LOCAL_ATTR_USERNAME],
			}
		)

	@auth_required
	@admin_required
	@ldap_backend_intercept
	def update(self, request: Request, pk=None):
		user: User = request.user
		code = 0
		code_msg = "ok"
		data: dict = request.data

		######################## Set LDAP Attributes ###########################
		self.ldap_filter_attr = self.filter_attr_builder(
			RuntimeSettings
		).get_update_attrs()
		########################################################################
		user_to_update = data.get(LOCAL_ATTR_USERNAME, None)
		EXCLUDE_KEYS = (
			LOCAL_ATTR_LAST_LOGIN_WIN32,
			LOCAL_ATTR_PWD_SET_AT,
		)
		for k in EXCLUDE_KEYS:
			data.pop(k, None)

		# Validate user data
		serializer = self.serializer_cls(data=data)
		if not serializer.is_valid():
			raise BadRequest(data={"errors": serializer.errors})
		data = serializer.validated_data

		if user_to_update == user.username:
			if ldap_adsi.LDAP_UF_ACCOUNT_DISABLE in data.get(
				LOCAL_ATTR_PERMISSIONS, []
			):
				raise exc_user.UserAntiLockout

		# Open LDAP Connection
		with LDAPConnector(user) as ldc:
			self.ldap_connection = ldc.connection

			# Check user exists and fetch it with minimal attributes
			if not self.ldap_user_exists(
				username=user_to_update,
				return_exception=False,
			):
				raise exc_user.UserDoesNotExist

			# Check if email overlaps with any other users
			user_email = data.get(LOCAL_ATTR_EMAIL, None)
			if user_email:
				self.ldap_user_exists(email=user_email)

			# Update
			self.ldap_user_update(data=data)

		return Response(data={"code": code, "code_msg": code_msg})

	@action(detail=False, methods=["post"])
	@auth_required
	@admin_required
	@ldap_backend_intercept
	def change_status(self, request: Request):
		user: User = request.user
		data: dict = request.data
		code = 0
		code_msg = "ok"

		for required_key in (
			LOCAL_ATTR_USERNAME,
			"enabled",
		):
			if required_key not in data or data.get(required_key, None) is None:
				raise BadRequest(
					data={
						"detail": f"{required_key} key must be in dictionary."
					}
				)
		username = data.pop(LOCAL_ATTR_USERNAME)
		enabled = data.pop("enabled")

		######################## Set LDAP Attributes ###########################
		self.ldap_filter_object = LDAPFilter.eq(
			RuntimeSettings.LDAP_FIELD_MAP[LOCAL_ATTR_OBJECT_CLASS],
			RuntimeSettings.LDAP_AUTH_OBJECT_CLASS
		).to_string()
		self.ldap_filter_attr = self.filter_attr_builder(
			RuntimeSettings
		).get_update_attrs()
		########################################################################

		if username == user.username:
			raise exc_user.UserAntiLockout

		# Open LDAP Connection
		with LDAPConnector(user) as ldc:
			self.ldap_connection = ldc.connection

			# Check user exists and fetch it with minimal attributes
			if not self.ldap_user_exists(
				username=username,
				return_exception=False,
			):
				raise exc_user.UserDoesNotExist

			self.ldap_user_change_status(
				username=username,
				enabled=enabled,
			)

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

		# Get username from data
		username = data.get(
			LOCAL_ATTR_USERNAME,
			data.get(RuntimeSettings.LDAP_FIELD_MAP[LOCAL_ATTR_USERNAME], None),
		)

		if not username:
			raise exc_base.BadRequest

		if username == user.username:
			raise exc_user.UserAntiLockout

		# Open LDAP Connection
		with LDAPConnector(user) as ldc:
			self.ldap_connection = ldc.connection

			# Check user exists and delete in LDAP Server
			if self.ldap_user_exists(username=username, return_exception=False):
				self.ldap_user_delete(username=username)

			try:
				django_user: User = User.objects.get(
					username=username, user_type=USER_TYPE_LDAP
				)
				django_user.delete_permanently()
			except ObjectDoesNotExist:
				pass

		return Response(data={"code": code, "code_msg": code_msg, "data": data})

	@action(detail=False, methods=["post"])
	@auth_required
	@admin_required
	@ldap_backend_intercept
	def change_password(self, request: Request, pk=None):
		user: User = request.user
		code = 0
		code_msg = "ok"
		data = request.data

		# Get username from data
		username = data.get(
			LOCAL_ATTR_USERNAME,
			data.get(RuntimeSettings.LDAP_FIELD_MAP[LOCAL_ATTR_USERNAME], None),
		)
		password = data.get(LOCAL_ATTR_PASSWORD, None)
		password_confirm = data.get(LOCAL_ATTR_PASSWORD_CONFIRM, None)

		if not username or not password:
			raise exc_base.BadRequest

		if password != password_confirm:
			raise exc_user.UserPasswordsDontMatch

		# Open LDAP Connection
		with LDAPConnector(user) as ldc:
			self.ldap_connection = ldc.connection

			# Check user exists and fetch it with minimal attributes
			if not self.ldap_user_exists(
				username=username,
				return_exception=False,
			):
				raise exc_user.UserDoesNotExist

			ldap_user_entry = self.get_user_object(username=username)
			if not ldap_user_entry.entry_dn:
				raise exc_user.UserDoesNotExist

			self.ldap_set_password(
				user_dn=ldap_user_entry.entry_dn,
				user_pwd_new=password,
				set_by_admin=True,
			)

		django_user = None
		try:
			django_user: User = User.objects.get(username=username)
		except ObjectDoesNotExist:
			pass
		if django_user:
			encrypted_data = aes_encrypt(password)
			for index, field in enumerate(USER_PASSWORD_FIELDS):
				setattr(django_user, field, encrypted_data[index])
			django_user.set_unusable_password()
			django_user.save()

		DBLogMixin.log(
			user=request.user.id,
			operation_type=LOG_ACTION_UPDATE,
			log_target_class=LOG_CLASS_USER,
			log_target=username,
			message=LOG_EXTRA_USER_CHANGE_PASSWORD,
		)

		return Response(data={"code": code, "code_msg": code_msg})

	@action(detail=False, methods=["post"])
	@auth_required
	@admin_required
	@ldap_backend_intercept
	def unlock(self, request: Request, pk=None):
		user: User = request.user
		code = 0
		code_msg = "ok"
		data = request.data

		# Get username from data
		username = data.get(
			LOCAL_ATTR_USERNAME,
			data.get(RuntimeSettings.LDAP_FIELD_MAP[LOCAL_ATTR_USERNAME], None),
		)
		if not username:
			raise exc_base.BadRequest

		# Open LDAP Connection
		with LDAPConnector(user) as ldc:
			self.ldap_connection = ldc.connection

			# Check user exists and fetch it with minimal attributes
			if not self.ldap_user_exists(
				username=username,
				return_exception=False,
			):
				raise exc_user.UserDoesNotExist

			try:
				self.ldap_user_unlock(username=username)
				result = self.ldap_connection.result
				if result["description"] == "success":
					response_result = username
				else:
					raise exc_user.CouldNotUnlockUser
			except:
				raise exc_user.CouldNotUnlockUser

		return Response(
			data={"code": code, "code_msg": code_msg, "data": response_result}
		)

	@action(detail=False, methods=["post"])
	@auth_required
	@admin_required
	@ldap_backend_intercept
	def bulk_insert(self, request: Request):
		user: User = request.user
		code = 0
		code_msg = "ok"
		data = request.data
		DATA_KEYS = (
			"headers",
			"users",
			LOCAL_ATTR_PATH,
			"mapping",
			"placeholder_password",
		)
		imported_users = []
		skipped_users = []
		failed_users = []

		for k in ("headers", "users",):
			if k not in data or not data.get(k, None):
				e = exc_base.MissingDataKey()
				e.set_detail({"key": k})
				raise e

		HEADERS: list = data["headers"]
		USER_LIST: list[dict] = data["users"]
		HEADER_COUNT = len(HEADERS)
		HEADER_MAPPING: dict = data.get("mapping", {})
		INSERTION_PATH: str = data.get(
			LOCAL_ATTR_PATH,
			f"CN=Users,{RuntimeSettings.LDAP_AUTH_SEARCH_BASE}",
		)
		MAPPED_USER_KEY = HEADER_MAPPING.get(
			LOCAL_ATTR_USERNAME, LOCAL_ATTR_USERNAME)
		MAPPED_EMAIL_KEY = HEADER_MAPPING.get(
			LOCAL_ATTR_EMAIL, LOCAL_ATTR_EMAIL)
		# Map Password Key
		MAPPED_PWD_KEY = HEADER_MAPPING.get(LOCAL_ATTR_PASSWORD, None)
		if any(LOCAL_ATTR_PASSWORD in user for user in USER_LIST):
			MAPPED_PWD_KEY = LOCAL_ATTR_PASSWORD
		placeholder_password = data.get("placeholder_password", None)

		# If all local aliases match with remote aliases, do not map
		if all(a == b for a, b in HEADER_MAPPING.items()) or not HEADER_MAPPING:
			HEADER_MAPPING = None

		######################## Set LDAP Attributes ###########################
		self.ldap_filter_attr = self.filter_attr_builder(
			RuntimeSettings
		).get_bulk_insert_attrs()

		required_fields = [LOCAL_ATTR_USERNAME]

		# Key exclusion
		exclude_keys = [
			LOCAL_ATTR_DN,  # We don't want any front-end generated DN
			LOCAL_ATTR_DN_SHORT,  # We don't want any front-end generated DN
		]
		if MAPPED_PWD_KEY:
			exclude_keys.insert(0, MAPPED_PWD_KEY)
		exclude_keys = tuple(exclude_keys)
		########################################################################

		_permissions = [ldap_adsi.LDAP_UF_NORMAL_ACCOUNT]
		if not MAPPED_PWD_KEY and not placeholder_password:
			_permissions.append(ldap_adsi.LDAP_UF_ACCOUNT_DISABLE)

		# Validate Front-end mapping with CSV Headers
		if HEADER_MAPPING:
			for k in required_fields:
				if k not in HEADER_MAPPING:
					raise exc_user.UserBulkInsertMappingError(data={"key": k})

		# Validate row lengths before opening connection
		for row in USER_LIST:
			if len(row) != HEADER_COUNT:
				raise exc_user.UserBulkInsertLengthError(
					data={"user": row[MAPPED_USER_KEY]}
				)

		# Open LDAP Connection
		with LDAPConnector(user) as ldc:
			self.ldap_connection = ldc.connection
			for row in USER_LIST:
				row: dict
				user_search = row.get(MAPPED_USER_KEY)

				# Check user existence
				if self.ldap_user_exists(
					username=user_search,
					email=row.get(MAPPED_EMAIL_KEY, None),
					return_exception=False,
				):
					skipped_users.append(row[MAPPED_USER_KEY])
					continue

				# Perform mapping if any header differs with local alias
				mapped_row = {} if HEADER_MAPPING else row
				if HEADER_MAPPING:
					for key, mapped_key in HEADER_MAPPING.items():
						mapped_row[key] = row[mapped_key]

				mapped_row[LOCAL_ATTR_PATH] = INSERTION_PATH
				mapped_row[LOCAL_ATTR_PERMISSIONS] = _permissions
					
				# Set password
				set_pwd = None
				if placeholder_password and not set_pwd:
					set_pwd = placeholder_password
				elif MAPPED_PWD_KEY in mapped_row:
					set_pwd = mapped_row[MAPPED_PWD_KEY]
					mapped_row[LOCAL_ATTR_PASSWORD_CONFIRM] = set_pwd

				# Serializer validation
				serializer = self.serializer_cls(data=mapped_row)
				if not serializer.is_valid():
					failed_users.append(
						{
							LOCAL_ATTR_USERNAME: user_search \
								if isinstance(user_search, str) \
								else "unknown",
							"stage": "serializer_validation",
							"detail": serializer.errors,
						}
					)
					continue
				_validated_row = serializer.validated_data
				_validated_row.pop(LOCAL_ATTR_PASSWORD, None)

				# Insert user
				user_dn = self.ldap_user_insert(
					data=_validated_row,
					exclude_keys=exclude_keys,
					return_exception=False,
				)
				if not user_dn:
					failed_users.append(
						{
							LOCAL_ATTR_USERNAME: user_search,
							"stage": "insert",
						}
					)
					continue

				if set_pwd:
					try:
						self.ldap_set_password(
							user_dn=user_dn,
							user_pwd_new=set_pwd,
							set_by_admin=True,
						)
					except:
						failed_users.append(
							{
								LOCAL_ATTR_USERNAME: user_search,
								"stage": LOCAL_ATTR_PASSWORD,
							}
						)

				imported_users.append(user_search)
				DBLogMixin.log(
					user=request.user.id,
					operation_type=LOG_ACTION_CREATE,
					log_target_class=LOG_CLASS_USER,
					log_target=user_search,
				)

		return Response(
			status=status.HTTP_200_OK,
			data={
				"code": code,
				"code_msg": code_msg,
				"imported_users": imported_users,
				"skipped_users": skipped_users,
				"failed_users": failed_users,
			},
		)

	@action(detail=False, methods=["post"])
	@auth_required
	@admin_required
	@ldap_backend_intercept
	def bulk_update(self, request: Request, pk=None):
		user: User = request.user
		code = 0
		code_msg = "ok"
		data = request.data

		# Validate data keys
		if any(
			v not in data for v in ("users", LOCAL_ATTR_PERMISSIONS, "values",)
		):
			raise exc_base.BadRequest

		values = data.get("values", {})
		permissions = data.get(LOCAL_ATTR_PERMISSIONS, [])

		EXCLUDE_KEYS = [
			LOCAL_ATTR_EMAIL
		]
		for k in EXCLUDE_KEYS:
			values.pop(k, None)

		if not values and not permissions:
			raise exc_base.BadRequest

		# Open LDAP Connection
		failed_users = []
		updated_users = []
		with LDAPConnector(user) as ldc:
			self.ldap_connection = ldc.connection
			for user_to_update in data["users"]:
				user_data = {}

				# Check that user exists and fetch it
				if not self.ldap_user_exists(
					username=user_to_update, return_exception=False
				):
					raise exc_user.UserDoesNotExist

				# Serializer validation
				user_data = {LOCAL_ATTR_USERNAME: user_to_update}
				if permissions:
					user_data[LOCAL_ATTR_PERMISSIONS] = permissions
				user_data = user_data | values
				serializer = self.serializer_cls(data=user_data)
				if not serializer.is_valid():
					if not isinstance(user_to_update, str):
						user_to_update = "unknown"
					failed_users.append(
						{
							LOCAL_ATTR_USERNAME: user_to_update,
							"stage": "serializer_validation",
							"detail": serializer.errors,
						}
					)
					continue
				validated_data = serializer.validated_data

				try:
					self.ldap_user_update(data=validated_data)
					updated_users.append(user_to_update)
				except:
					failed_users.append(
						{
							LOCAL_ATTR_USERNAME: user_to_update,
							"stage": "update",
						}
					)

		return Response(data={
			"code": code,
			"code_msg": code_msg,
			"updated_users": updated_users,
			"failed_users": failed_users,
		})

	@action(detail=False, methods=["post"])
	@auth_required
	@admin_required
	@ldap_backend_intercept
	def bulk_change_status(self, request: Request):
		user: User = request.user
		code = 0
		code_msg = "ok"
		request_data = request.data
		disable_users = request_data.get("disable", None)
		data: list[dict] | list[str] = request_data["users"]

		if disable_users is None:
			raise BadRequest
		if not isinstance(data, list) or not data:
			raise BadRequest
		if not all(isinstance(x, (dict, str)) for x in data):
			raise BadRequest

		######################## Set LDAP Attributes ###########################
		self.ldap_filter_object = LDAPFilter.eq(
			RuntimeSettings.LDAP_FIELD_MAP[LOCAL_ATTR_OBJECT_CLASS],
			RuntimeSettings.LDAP_AUTH_OBJECT_CLASS,
		).to_string()
		self.ldap_filter_attr = self.filter_attr_builder(
			RuntimeSettings
		).get_update_attrs()
		########################################################################

		# Open LDAP Connection
		with LDAPConnector(user) as ldc:
			self.ldap_connection = ldc.connection
			success = []
			for user_data in data:
				if isinstance(user_data, str):
					username = user_data
				else:
					username = user_data.get(LOCAL_ATTR_USERNAME, None)
				try:
					self.ldap_user_change_status(
						username=username,
						enabled=(not disable_users)
					)
					success.append(username)
				except:
					if isinstance(username, str):
						logger.error(
							"Could not change status for user %s" % (username)
						)
					pass

		return Response(
			data={"code": code, "code_msg": code_msg, "data": success}
		)

	@action(detail=False, methods=["post"])
	@auth_required
	@admin_required
	@ldap_backend_intercept
	def bulk_delete(self, request: Request, pk=None):
		user: User = request.user
		code = 0
		code_msg = "ok"
		data: list[dict] = request.data

		# Open LDAP Connection
		with LDAPConnector(user) as ldc:
			self.ldap_connection = ldc.connection
			deleted_users = []
			for user_data in data:
				if isinstance(user_data, str):
					username = user_data
				else:
					username = user_data.get(LOCAL_ATTR_USERNAME, None)
				if username:
					self.ldap_user_delete(username=username)
					deleted_users.append(username)

		return Response(
			data={"code": code, "code_msg": code_msg, "data": deleted_users}
		)

	@action(detail=False, methods=["post"])
	@auth_required
	@admin_required
	@ldap_backend_intercept
	def bulk_unlock(self, request: Request, pk=None):
		user: User = request.user
		code = 0
		code_msg = "ok"
		data: list[dict] = request.data

		if not isinstance(data, list):
			raise exc_base.BadRequest

		# Open LDAP Connection
		with LDAPConnector(user) as ldc:
			self.ldap_connection = ldc.connection
			success = []
			for user_object in data:
				if isinstance(user_object, str):
					username = user_object
				else:
					username = user_object.get(LOCAL_ATTR_USERNAME, None)
				if username:
					self.ldap_user_unlock(username=username)
					success.append(username)

			result = self.ldap_connection.result
			if result["description"] == "success":
				response_result = success
			else:
				raise exc_user.CouldNotUnlockUser

		return Response(
			data={"code": code, "code_msg": code_msg, "data": response_result}
		)

	@action(detail=False, methods=["post"])
	@auth_required
	@ldap_backend_intercept
	def self_change_password(self, request: Request, pk=None):
		user: User = request.user
		code = 0
		code_msg = "ok"
		data = request.data

		ALERT_KEYS = (
			LOCAL_ATTR_USERNAME,
			LOCAL_ATTR_DN,
			RuntimeSettings.LDAP_FIELD_MAP[LOCAL_ATTR_USERNAME],
			RuntimeSettings.LDAP_FIELD_MAP[LOCAL_ATTR_DN],
		)
		for k in ALERT_KEYS:
			if k in data:
				logger.warning(
					"User %s requested password with malformed data.",
					user.username,
				)
				raise exc_base.BadRequest

		# Open LDAP Connection
		# User doesn't have rights to change any data in LDAP Server
		# so admin must be forced, auth_required decorator with
		# require_admin flag is very important
		with LDAPConnector(force_admin=True) as ldc:
			self.ldap_connection = ldc.connection
			ldap_user_search = user.username
			ldap_user_entry = self.get_user_object(
				ldap_user_search,
				attributes=[
					RuntimeSettings.LDAP_FIELD_MAP[LOCAL_ATTR_USERNAME],
					RuntimeSettings.LDAP_FIELD_MAP[LOCAL_ATTR_DN],
					RuntimeSettings.LDAP_FIELD_MAP[LOCAL_ATTR_UAC],
				],
			)
			distinguished_name = str(ldap_user_entry.entry_dn)

			if ldap_adsi.list_user_perms(
				user=ldap_user_entry,
				perm_search=ldap_adsi.LDAP_UF_PASSWD_CANT_CHANGE,
			):
				raise PermissionDenied

			if not distinguished_name:
				raise exc_user.UserDoesNotExist

			if data[LOCAL_ATTR_PASSWORD] != data[LOCAL_ATTR_PASSWORD_CONFIRM]:
				raise exc_user.UserPasswordsDontMatch

			self.ldap_set_password(
				user_dn=distinguished_name,
				user_pwd_new=data[LOCAL_ATTR_PASSWORD],
				user_pwd_old=aes_decrypt(*user.encrypted_password),
			)

		django_user = None
		try:
			django_user = User.objects.get(username=ldap_user_search)
		except Exception as e:
			logger.error(e)
		if django_user:
			encrypted_data = aes_encrypt(data[LOCAL_ATTR_PASSWORD])
			for index, field in enumerate(USER_PASSWORD_FIELDS):
				setattr(django_user, field, encrypted_data[index])
			django_user.set_unusable_password()
			django_user.save()

		DBLogMixin.log(
			user=request.user.id,
			operation_type=LOG_ACTION_UPDATE,
			log_target_class=LOG_CLASS_USER,
			log_target=ldap_user_search,
			message=LOG_EXTRA_USER_CHANGE_PASSWORD,
		)

		return Response(data={"code": code, "code_msg": code_msg, "data": data})

	@action(detail=False, methods=["put", "post"])
	@auth_required
	@ldap_backend_intercept
	def self_update(self, request: Request, pk=None):
		user: User = request.user
		code = 0
		code_msg = "ok"
		data = request.data

		BAD_KEYS = [
			LOCAL_ATTR_USERNAME,
			RuntimeSettings.LDAP_FIELD_MAP[LOCAL_ATTR_USERNAME],
		]
		for k in BAD_KEYS:
			if k in data:
				raise exc_base.BadRequest

		# Get basic attributes for this user from AD to compare query and get dn
		self.ldap_filter_attr = self.filter_attr_builder(
			RuntimeSettings
		).get_update_attrs()
		EXCLUDE_KEYS = self.filter_attr_builder(
			RuntimeSettings
		).get_update_self_exclude_keys()

		for key in EXCLUDE_KEYS:
			if key in data:
				del data[key]

		# Open LDAP Connection
		# User doesn't have rights to change any data in LDAP Server
		# so admin must be forced, auth_required decorator with
		# require_admin flag is very important
		with LDAPConnector(force_admin=True) as ldc:
			self.ldap_connection = ldc.connection
			ldap_user_search = user.username
			self.ldap_user_update(username=ldap_user_search, user_data=data)

		logger.debug(self.ldap_connection.result)

		DBLogMixin.log(
			user=request.user.id,
			operation_type=LOG_ACTION_UPDATE,
			log_target_class=LOG_CLASS_USER,
			log_target=ldap_user_search,
			message=LOG_EXTRA_USER_END_USER_UPDATE,
		)

		django_user = None
		try:
			django_user = User.objects.get(username=ldap_user_search)
		except:
			pass

		if django_user:
			for key in RuntimeSettings.LDAP_FIELD_MAP:
				mapped_key = RuntimeSettings.LDAP_FIELD_MAP[key]
				if mapped_key in data:
					setattr(django_user, key, data[mapped_key])
				if "mail" not in data:
					django_user.email = None
			django_user.save()

		for k in EXCLUDE_KEYS:
			if k in data:
				del data[k]
		return Response(data={"code": code, "code_msg": code_msg, "data": data})

	@action(detail=False, methods=["get"])
	@auth_required
	def self_info(self, request):
		user: User = request.user
		data = {}
		code = 0
		data[LOCAL_ATTR_USERNAME] = user.username or ""
		data[LOCAL_ATTR_FIRST_NAME] = user.first_name or ""
		data[LOCAL_ATTR_LAST_NAME] = user.last_name or ""
		data[LOCAL_ATTR_EMAIL] = user.email or ""
		# This only informs the front-end it is admin capable
		# Validation is done on the back-end
		if user.is_superuser:
			data["admin_allowed"] = True
		return Response(data={"code": code, "code_msg": "ok", "user": data})

	@action(detail=False, methods=["get"])
	@auth_required
	@ldap_backend_intercept
	def self_fetch(self, request):
		user: User = request.user
		code = 0
		code_msg = "ok"
		user_search = user.username
		if user.user_type == USER_TYPE_LOCAL:
			user_data = {}
			for field in LOCAL_PUBLIC_FIELDS:
				user_data[field] = getattr(user, field)
		elif user.user_type == USER_TYPE_LDAP:
			# Open LDAP Connection
			with LDAPConnector(user, force_admin=True) as ldc:
				self.ldap_connection = ldc.connection
				self.ldap_filter_attr = self.filter_attr_builder(
					RuntimeSettings
				).get_fetch_me_attrs()

				self.ldap_filter_object = LDAPFilter.eq(
					RuntimeSettings.LDAP_FIELD_MAP[LOCAL_ATTR_OBJECT_CLASS],
					RuntimeSettings.LDAP_AUTH_OBJECT_CLASS,
				)

				# Add filter for username
				self.ldap_filter_object = LDAPFilter.and_(
					self.ldap_filter_object,
					LDAPFilter.eq(
						RuntimeSettings.LDAP_FIELD_MAP[LOCAL_ATTR_USERNAME],
						user_search,
					),
				).to_string()

				self.ldap_connection.search(
					RuntimeSettings.LDAP_AUTH_SEARCH_BASE,
					self.ldap_filter_object,
					attributes=self.ldap_filter_attr,
				)
				user_entry = self.ldap_connection.entries

				self.ldap_filter_attr.remove("userAccountControl")

				# For each attribute in user object attributes
				user_data = {}
				for attr_key in self.ldap_filter_attr:
					if attr_key in self.ldap_filter_attr:
						str_key = str(attr_key)
						str_value = str(getattr(user_entry[0], attr_key))
						if str_value == "[]":
							user_data[str_key] = ""
						else:
							user_data[str_key] = str_value
					if (
						attr_key
						== RuntimeSettings.LDAP_FIELD_MAP[LOCAL_ATTR_USERNAME]
					):
						user_data[LOCAL_ATTR_USERNAME] = str_value

					# Check if user can change password based on perms
					user_data["can_change_pwd"] = not ldap_adsi.list_user_perms(
						user=user_entry[0],
						perm_search=ldap_adsi.LDAP_UF_PASSWD_CANT_CHANGE,
					)

		return Response(
			data={"code": code, "code_msg": code_msg, "data": user_data}
		)
