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
			LDAP_ATTR_OBJECT_CLASS, RuntimeSettings.LDAP_AUTH_OBJECT_CLASS
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
			RuntimeSettings.LDAP_AUTH_USER_FIELDS[LOCAL_ATTR_USERNAME],
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

		if LDAP_ATTR_USERNAME_SAMBA_ADDS in data:
			data[LOCAL_ATTR_USERNAME] = data.pop(LDAP_ATTR_USERNAME_SAMBA_ADDS)
		user_username = data.get(LOCAL_ATTR_USERNAME, None)
		if not user_username:
			raise exc_base.MissingDataKey(data={"key": LOCAL_ATTR_USERNAME})

		set_pwd = False
		user_pwd = data.get(LOCAL_ATTR_PASSWORD, None)
		user_pwd_confirm = data.get(LOCAL_ATTR_PASSWORD_CONFIRM, None)
		if user_pwd and user_pwd_confirm:
			set_pwd = True
			if user_pwd != user_pwd_confirm:
				raise exc_user.UserPasswordsDontMatch

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
					RuntimeSettings.LDAP_AUTH_USER_FIELDS["email"],
					None,
				),
			)

			user_dn = self.ldap_user_insert(unmapped_data=data)
			if set_pwd:
				self.ldap_set_password(
					user_dn=user_dn,
					user_pwd_new=user_pwd,
					set_by_admin=True,
				)

		return Response(
			data={"code": code, "code_msg": code_msg, "data": data[LOCAL_ATTR_USERNAME]}
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
		EXCLUDE_KEYS = (LOCAL_ATTR_LAST_LOGIN, LOCAL_ATTR_PWD_SET_AT,)
		for k in EXCLUDE_KEYS:
			data.pop(k, None)

		# Validate user data
		serializer = self.serializer_cls(data=data)
		if not serializer.is_valid():
			raise BadRequest(data={"errors": serializer.errors})
		data = serializer.validated_data

		if user_to_update == user.username:
			if (ldap_adsi.LDAP_UF_ACCOUNT_DISABLE in
	   				data.get(LOCAL_ATTR_PERMISSIONS, [])):
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
			user_email = data.get(LDAP_ATTR_EMAIL, None)
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

		for required_key in (LOCAL_ATTR_USERNAME, "enabled",):
			if required_key not in data or data.get(required_key, None) is None:
				raise BadRequest(
					data={"detail":f"{required_key} key must be in dictionary."}
				)
		username = data.pop(LOCAL_ATTR_USERNAME)
		enabled = data.pop("enabled")

		######################## Set LDAP Attributes ###########################
		self.ldap_filter_object = LDAPFilter.eq(
			LDAP_ATTR_OBJECT_CLASS, RuntimeSettings.LDAP_AUTH_OBJECT_CLASS
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
			data.get(
				RuntimeSettings.LDAP_AUTH_USER_FIELDS[LOCAL_ATTR_USERNAME], None
			)
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
				django_user = User.objects.get(
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
			data.get(
				RuntimeSettings.LDAP_AUTH_USER_FIELDS[LOCAL_ATTR_USERNAME], None
			)
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
			django_user = User.objects.get(username=username)
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
			data.get(
				RuntimeSettings.LDAP_AUTH_USER_FIELDS[LOCAL_ATTR_USERNAME],
				None
			)
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
		DATA_HEADERS = ("headers", "users", "path", "mapping",)
		imported_users = []
		skipped_users = []
		failed_users = []

		for k in DATA_HEADERS:
			if k not in data or not data.get(k, None):
				e = exc_base.MissingDataKey()
				e.set_detail({"key": k})
				raise e

		HEADERS = data["headers"]
		HEADER_COUNT = len(HEADERS)
		HEADER_MAPPING = data["mapping"]
		INSERTION_PATH: str = data["path"]
		user_list: list = data["users"]
		user_placeholder_password = None

		######################## Set LDAP Attributes ###########################
		self.ldap_filter_attr = self.filter_attr_builder(
			RuntimeSettings
		).get_bulk_insert_attrs()

		# Check if data has a requested placeholder_password
		required_fields = [LOCAL_ATTR_USERNAME]
		if "placeholder_password" in data and data["placeholder_password"]:
			if len(data["placeholder_password"]) > 0:
				user_placeholder_password = data["placeholder_password"]

		# Use CSV column if placeholder not requested
		if not user_placeholder_password:
			required_fields.append(LOCAL_ATTR_PASSWORD)

		MAPPED_USER_KEY = HEADER_MAPPING[LDAP_ATTR_USERNAME_SAMBA_ADDS]
		MAPPED_EMAIL_KEY = HEADER_MAPPING[LDAP_ATTR_EMAIL]
		if user_placeholder_password:
			mapped_pwd_key = LOCAL_ATTR_PASSWORD
		else:
			mapped_pwd_key = HEADER_MAPPING[LOCAL_ATTR_PASSWORD]
		EXCLUDE_KEYS = [
			MAPPED_USER_KEY,  # LDAP Uses sAMAccountName
			mapped_pwd_key,
			"permission_list",  # This array should be parsed and calculated,
								# then changed to userAccountControl
			LDAP_ATTR_DN,  # We don't want the front-end generated DN
		]
		########################################################################

		# Validate Front-end mapping with CSV Headers
		for k in required_fields:
			if k not in HEADER_MAPPING:
				raise exc_user.UserBulkInsertMappingError(data={"key": k})

		# Validate row lengths before opening connection
		for row in user_list:
			if len(row) != HEADER_COUNT:
				raise exc_user.UserBulkInsertLengthError(
					data={"user": row[MAPPED_USER_KEY]}
				)

		# Open LDAP Connection
		with LDAPConnector(user) as ldc:
			self.ldap_connection = ldc.connection
			for row in user_list:
				row: dict
				user_search = row[MAPPED_USER_KEY]
				row["path"] = INSERTION_PATH

				if self.ldap_user_exists(
					username=user_search,
					email=row.get(MAPPED_EMAIL_KEY, None),
					return_exception=False,
				):
					skipped_users.append(row[MAPPED_USER_KEY])
					continue

				# Serializer validation
				serializer = self.serializer_cls(data=row)
				if not serializer.is_valid():
					failed_users.append(
						{
							LOCAL_ATTR_USERNAME: row[MAPPED_USER_KEY],
							"stage": "serializer_validation",
						}
					)
					continue
				_validated_row = serializer.validated_data

				user_dn = self.ldap_user_insert(
					data=_validated_row,
					exclude_keys=EXCLUDE_KEYS,
					return_exception=False,
					key_mapping=HEADER_MAPPING,
				)
				if not user_dn:
					failed_users.append(
						{
							LOCAL_ATTR_USERNAME: row[MAPPED_USER_KEY],
							"stage": "permission",
						}
					)
					continue

				set_pwd = False
				if user_placeholder_password:
					row[mapped_pwd_key] = user_placeholder_password
					set_pwd = True
				elif (
					mapped_pwd_key in data["headers"]
					and len(row[mapped_pwd_key]) > 0
				):
					set_pwd = True

				if set_pwd:
					try:
						self.ldap_set_password(
							user_dn=user_dn,
							user_pwd_new=row[mapped_pwd_key],
							set_by_admin=True,
						)
					except:
						failed_users.append(
							{
								LOCAL_ATTR_USERNAME: row[MAPPED_USER_KEY],
								"stage": LOCAL_ATTR_PASSWORD,
							}
						)

				imported_users.append(row[MAPPED_USER_KEY])
				DBLogMixin.log(
					user=request.user.id,
					operation_type=LOG_ACTION_CREATE,
					log_target_class=LOG_CLASS_USER,
					log_target=row[MAPPED_USER_KEY],
				)

		return Response(
			status=200,
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
		if any(v not in data for v in ["users", "permissions", "values"]):
			raise exc_base.BadRequest

		values = data.get("values", {})
		permission_list = data.get("permissions", [])

		EXCLUDE_KEYS = self.filter_attr_builder(RuntimeSettings)\
			.get_update_exclude_keys()
		EXCLUDE_KEYS.append(RuntimeSettings.LDAP_AUTH_USER_FIELDS["email"])
		for k in EXCLUDE_KEYS:
			values.pop(k, None)

		if not values and not permission_list:
			raise exc_base.BadRequest

		# Validate data
		serializer = self.serializer_cls(data=data["values"])
		if not serializer.is_valid():
			raise BadRequest(data={"errors": serializer.errors})
		validated_values = serializer.validated_data

		# Open LDAP Connection
		with LDAPConnector(user) as ldc:
			for user_to_update in data["users"]:
				self.ldap_connection = ldc.connection

				# Check that user exists and fetch it
				if not self.ldap_user_exists(
					username=user_to_update, return_exception=False
				):
					raise exc_user.UserDoesNotExist

				# Check if email overlaps with another user's
				user_email = data.get("email", None)
				if user_email:
					self.ldap_user_exists(email=user_email)

				self.get_user_object(
					user_to_update, attributes=ldap3.ALL_ATTRIBUTES
				)

				self.ldap_user_update(
					username=user_to_update,
					user_data=validated_values,
					permission_list=permission_list,
				)

		return Response(data={"code": code, "code_msg": code_msg, "data": data})

	@action(detail=False, methods=["post"])
	@auth_required
	@admin_required
	@ldap_backend_intercept
	def bulk_change_status(self, request):
		user: User = request.user
		code = 0
		code_msg = "ok"
		request_data = request.data
		disable_users = request_data["disable"]
		data = request_data["users"]

		if not isinstance(disable_users, bool) or not isinstance(data, list):
			raise BadRequest

		######################## Set LDAP Attributes ###########################
		self.ldap_filter_object = LDAPFilter.eq(
			LDAP_ATTR_OBJECT_CLASS, RuntimeSettings.LDAP_AUTH_OBJECT_CLASS
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
				if disable_users and user_data["is_enabled"]:
					self.ldap_user_change_status(
						username=user_data[LOCAL_ATTR_USERNAME], enabled=False
					)
					success.append(user_data[LOCAL_ATTR_USERNAME])
				elif not disable_users and not user_data["is_enabled"]:
					self.ldap_user_change_status(
						username=user_data[LOCAL_ATTR_USERNAME], enabled=True
					)
					success.append(user_data[LOCAL_ATTR_USERNAME])
				else:
					continue

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
		data = request.data

		if not isinstance(data, list):
			raise exc_base.CoreException

		self.ldap_settings = {
			"authUsernameIdentifier": 
				RuntimeSettings.LDAP_AUTH_USER_FIELDS[LOCAL_ATTR_USERNAME]
		}

		# Open LDAP Connection
		with LDAPConnector(user) as ldc:
			self.ldap_connection = ldc.connection
			for user in data:
				self.ldap_user_delete(username=user)

		return Response(data={"code": code, "code_msg": code_msg, "data": data})

	@action(detail=False, methods=["post"])
	@auth_required
	@admin_required
	@ldap_backend_intercept
	def bulk_unlock(self, request: Request, pk=None):
		user: User = request.user
		code = 0
		code_msg = "ok"
		data = request.data

		if not isinstance(data, list):
			raise exc_base.BadRequest

		# Open LDAP Connection
		with LDAPConnector(user) as ldc:
			self.ldap_connection = ldc.connection
			success = []
			for user_object in data:
				self.ldap_user_unlock(username=user_object)
				success.append(user_object[LOCAL_ATTR_USERNAME])

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
			RuntimeSettings.LDAP_AUTH_USER_FIELDS[LOCAL_ATTR_USERNAME],
			LDAP_ATTR_DN,
		)
		for k in ALERT_KEYS:
			if k in data:
				logger.warning(
					"User %s requested password with malformed data.",
					user.username
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
					RuntimeSettings.LDAP_AUTH_USER_FIELDS[LOCAL_ATTR_USERNAME],
					LDAP_ATTR_DN,
					LDAP_ATTR_UAC,
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
			RuntimeSettings.LDAP_AUTH_USER_FIELDS[LOCAL_ATTR_USERNAME],
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
			for key in RuntimeSettings.LDAP_AUTH_USER_FIELDS:
				mapped_key = RuntimeSettings.LDAP_AUTH_USER_FIELDS[key]
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
					LDAP_ATTR_OBJECT_CLASS,
					RuntimeSettings.LDAP_AUTH_OBJECT_CLASS
				)

				# Add filter for username
				self.ldap_filter_object = LDAPFilter.and_(
					self.ldap_filter_object,
					LDAPFilter.eq(
						RuntimeSettings.LDAP_AUTH_USER_FIELDS[LOCAL_ATTR_USERNAME],
						user_search
					)
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
						== RuntimeSettings.LDAP_AUTH_USER_FIELDS[LOCAL_ATTR_USERNAME]
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
