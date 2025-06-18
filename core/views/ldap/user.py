################################################################################
#################### INTERLOCK IS LICENSED UNDER GNU AGPLv3 ####################
################## ORIGINAL PROJECT CREATED BY DYLAN BLANQUÉ ###################
########################## AND BR CONSULTING S.R.L. ############################
################################################################################
# Module: core.views.ldap.user
# Contains the ViewSet for User related operations

# ---------------------------------- IMPORTS --------------------------------- #
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
from core.models.ldap_user import LDAPUser, DEFAULT_LOCAL_ATTRS
from core.views.mixins.logs import LogMixin
from core.models.choices.log import (
	LOG_ACTION_UPDATE,
	LOG_ACTION_READ,
	LOG_CLASS_USER,
	LOG_EXTRA_USER_CHANGE_PASSWORD,
	LOG_EXTRA_USER_END_USER_UPDATE,
	LOG_EXTRA_EXPORT,
	LOG_TARGET_ALL,
)

### Mixins
from core.views.mixins.user.main import AllUserMixins

### Serializers / Validators
from core.serializers.user import LDAPUserSerializer

### ViewSets
from core.views.base import BaseViewSet

### REST Framework
from rest_framework import status
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.decorators import action

### Auth
from core.decorators.login import auth_required, admin_required
from core.ldap import adsi as ldap_adsi
from core.constants.attrs import *
from core.ldap.connector import LDAPConnector

### Django
from django.utils import timezone as tz
from django.http import StreamingHttpResponse

### Others
from core.utils.main import getlocalkeyforldapattr
from core.utils.csv import csv_iterator
from datetime import datetime
from core.constants.attrs.local import DATE_FORMAT_ISO_8601_ALT
from core.ldap.filter import LDAPFilter
from core.decorators.intercept import ldap_backend_intercept
from core.constants.user import LOCAL_PUBLIC_FIELDS
from core.config.runtime import RuntimeSettings
from typing import Any
import logging
################################################################################

DBLogMixin = LogMixin()
logger = logging.getLogger(__name__)


class LDAPUserViewSet(BaseViewSet, AllUserMixins):
	queryset = User.objects.all()
	serializer_class = LDAPUserSerializer

	@auth_required
	@admin_required
	@ldap_backend_intercept
	def list(self, request):
		user: User = request.user
		data = {}
		code = 0
		code_msg = "ok"

		self.search_filter = LDAPFilter.eq(
			RuntimeSettings.LDAP_FIELD_MAP[LOCAL_ATTR_OBJECT_CLASS],
			RuntimeSettings.LDAP_AUTH_OBJECT_CLASS,
		)
		self.search_attrs = self.filter_attr_builder(
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

	@auth_required
	@admin_required
	@ldap_backend_intercept
	@action(
		detail=False,
		methods=["post"],
		url_name="retrieve",
		url_path="retrieve",
	)
	def retrieve_by_username(self, request: Request):
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

	@auth_required
	@admin_required
	@ldap_backend_intercept
	def create(self, request):
		user: User = request.user
		code = 0
		code_msg = "ok"
		data: dict = request.data

		username = data.get(LOCAL_ATTR_USERNAME, None)
		if not username:
			raise exc_base.MissingDataKey(data={"key": LOCAL_ATTR_USERNAME})

		# Validate user data
		serializer = self.serializer_class(data=data)
		if not serializer.is_valid():
			raise BadRequest(data={"errors": serializer.errors})
		data = serializer.validated_data

		# Open LDAP Connection
		with LDAPConnector(user) as ldc:
			self.ldap_connection = ldc.connection

			# User Exists check
			self.ldap_user_exists(
				username=username,
				email=data.get(
					RuntimeSettings.LDAP_FIELD_MAP[LOCAL_ATTR_EMAIL],
					None,
				),
			)
			self.ldap_user_insert(data=data)

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
		self.search_attrs = self.filter_attr_builder(
			RuntimeSettings
		).get_update_attrs()
		########################################################################
		user_to_update = data.get(LOCAL_ATTR_USERNAME, None)
		EXCLUDE_KEYS = (
			LOCAL_ATTR_LAST_LOGIN_WIN32,
			LOCAL_ATTR_PWD_SET_AT,
		)
		for k in EXCLUDE_KEYS:
			if k in data:
				del data[k]

		# Validate user data
		serializer = self.serializer_class(data=data)
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

	@auth_required
	@admin_required
	@ldap_backend_intercept
	@action(detail=False, methods=["post"], url_path="change-status")
	def change_status(self, request: Request):
		user: User = request.user
		data: dict = request.data
		code = 0
		code_msg = "ok"

		for required_key in (
			LOCAL_ATTR_USERNAME,
			LOCAL_ATTR_ENABLED,
		):
			if required_key not in data or data.get(required_key, None) is None:
				raise BadRequest(
					data={
						"detail": f"{required_key} key must be in dictionary."
					}
				)
		username = data.pop(LOCAL_ATTR_USERNAME)
		enabled = data.pop(LOCAL_ATTR_ENABLED)

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

	@auth_required
	@admin_required
	@ldap_backend_intercept
	def destroy(self, request: Request, pk=None):
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

	@auth_required
	@admin_required
	@ldap_backend_intercept
	@action(detail=False, methods=["post"], url_path="change-password")
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
		# TODO implement LDAPUser usage.
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

	@auth_required
	@admin_required
	@ldap_backend_intercept
	@action(detail=False, methods=["post"], url_path="bulk/create")
	def bulk_create(self, request: Request):
		request_user: User = request.user
		code = 0
		code_msg = "ok"
		data = request.data
		created_users = None
		failed_users = None
		skipped_users = None
		DATA_KEYS = (
			# CSV Keys
			"headers",
			"users",
			LOCAL_ATTR_PATH,
			"mapping",
			"placeholder_password",
			# Dict Keys
			"dict_users",
		)
		# Purge unknown keys
		for k in data.keys():
			if not k in DATA_KEYS:
				del data[k]

		create_path: str = data.get(LOCAL_ATTR_PATH, None)
		user_rows: list[list[Any]] = data.pop("users", None)
		user_dicts: list[dict[Any]] = data.pop("dict_users", None)

		if (not user_rows and not user_dicts) or (user_rows and user_dicts):
			raise BadRequest(
				data={
					"detail": "To bulk insert users you must provide either the"
					" users or dict_users fields."
				}
			)

		if user_rows:  # Insert from CSV
			headers = data.pop("headers", None)

			# Add Password attr to valid attrs if necessary
			check_attrs = list(DEFAULT_LOCAL_ATTRS)
			if LOCAL_ATTR_PASSWORD in headers:
				check_attrs.append(LOCAL_ATTR_PASSWORD)

			# Validate and Map indices for local attrs
			index_map = self.validate_and_map_csv_headers(
				headers=headers,
				csv_map=data.pop("mapping", None),
				check_attrs=tuple(check_attrs),
			)

			# Check that no username or email overlaps
			username_col = None
			email_col = None
			for idx, local_alias in index_map.items():
				if local_alias == LOCAL_ATTR_USERNAME:
					username_col = idx
				elif local_alias == LOCAL_ATTR_EMAIL:
					email_col = idx

			usernames_and_emails = [
				(u[username_col], u[email_col])
				if email_col
				else (u[username_col], None)
				for u in user_rows
			]
			skipped_users = self.bulk_check_users(
				usernames_and_emails,
				ignore_local=True,  # Todo - make this change based on a setting
				raise_exception=False,
			)

			# Perform creation operations
			with LDAPConnector(request_user) as ldc:
				self.ldap_connection = ldc.connection
				created_users, failed_users = self.ldap_bulk_create_from_csv(
					request_user=request_user,
					user_rows=user_rows,
					index_map=index_map,
					path=create_path,
					placeholder_password=data.pop("placeholder_password", None),
				)
		elif user_dicts:  # Insert from list of dicts
			skipped_users = self.bulk_check_users(
				[
					(
						u.get(LOCAL_ATTR_USERNAME),
						u.get(LOCAL_ATTR_EMAIL, None),
					)
					for u in user_dicts
				],
				ignore_local=True,  # Todo - make this change based on a setting
				raise_exception=False,
			)
			with LDAPConnector(request_user) as ldc:
				self.ldap_connection = ldc.connection
				created_users, failed_users = self.ldap_bulk_create_from_dicts(
					request_user=request_user,
					user_dicts=user_dicts,
					path=create_path,
					placeholder_password=data.pop("placeholder_password", None),
				)

		return Response(
			status=status.HTTP_200_OK,
			data={
				"code": code,
				"code_msg": code_msg,
				"created_users": created_users,
				"skipped_users": skipped_users,
				"failed_users": failed_users,
			},
		)

	@auth_required
	@admin_required
	@ldap_backend_intercept
	@action(detail=False, methods=["post"], url_path="bulk/update")
	def bulk_update(self, request: Request, pk=None):
		user: User = request.user
		code = 0
		code_msg = "ok"
		data = request.data

		# Validate data keys
		if any(
			v not in data
			for v in (
				"users",
				LOCAL_ATTR_PERMISSIONS,
				"values",
			)
		):
			raise exc_base.BadRequest

		values = data.get("values", {})
		permissions = data.get(LOCAL_ATTR_PERMISSIONS, [])

		EXCLUDE_KEYS = [LOCAL_ATTR_EMAIL]
		for k in EXCLUDE_KEYS:
			if k in values:
				del values[k]

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
				serializer = self.serializer_class(data=user_data)
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
				except Exception as e:
					logger.exception(e)
					failed_users.append(
						{
							LOCAL_ATTR_USERNAME: user_to_update,
							"stage": "update",
						}
					)

		return Response(
			data={
				"code": code,
				"code_msg": code_msg,
				"updated_users": updated_users,
				"failed_users": failed_users,
			}
		)

	@auth_required
	@admin_required
	@ldap_backend_intercept
	@action(detail=False, methods=["post"], url_path="bulk/change-status")
	def bulk_change_status(self, request: Request):
		user: User = request.user
		code = 0
		code_msg = "ok"
		request_data = request.data
		enable_users = request_data.get(LOCAL_ATTR_ENABLED, None)
		data: list[dict] | list[str] = request_data["users"]

		if enable_users is None:
			raise BadRequest
		if not isinstance(data, list) or not data:
			raise BadRequest
		if not all(isinstance(x, (dict, str)) for x in data):
			raise BadRequest

		######################## Set LDAP Attributes ###########################
		self.search_filter = LDAPFilter.eq(
			RuntimeSettings.LDAP_FIELD_MAP[LOCAL_ATTR_OBJECT_CLASS],
			RuntimeSettings.LDAP_AUTH_OBJECT_CLASS,
		).to_string()
		self.search_attrs = self.filter_attr_builder(
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
						username=username, enabled=enable_users
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

	@auth_required
	@admin_required
	@ldap_backend_intercept
	@action(detail=False, methods=["post"], url_path="bulk/destroy")
	def bulk_destroy(self, request: Request, pk=None):
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

	@auth_required
	@admin_required
	@ldap_backend_intercept
	@action(detail=False, methods=["post"], url_path="bulk/unlock")
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

	@auth_required
	@ldap_backend_intercept
	@action(detail=False, methods=["post"], url_path="self/change-password")
	def self_change_password(self, request: Request, pk=None):
		user = request.user
		user: User  # For type-hints
		code = 0
		code_msg = "ok"
		data = request.data
		if user.user_type != USER_TYPE_LDAP:
			raise exc_user.UserNotLDAPType

		ALERT_KEYS = (
			LOCAL_ATTR_USERNAME,
			LOCAL_ATTR_DN,
			RuntimeSettings.LDAP_FIELD_MAP[LOCAL_ATTR_USERNAME],
			RuntimeSettings.LDAP_FIELD_MAP[LOCAL_ATTR_DN],
		)
		for k in ALERT_KEYS:
			if k in data:
				logger.warning(
					"User %s requested self password update with malformed data.",
					user.username,
				)
				raise exc_base.BadRequest

		serializer = self.serializer_class(data=data)
		serializer.is_valid(raise_exception=True)
		data = serializer.validated_data

		# Open LDAP Connection
		# User doesn't have rights to change any data in LDAP Server
		# so admin must be forced, auth_required decorator is very important.
		with LDAPConnector(force_admin=True) as ldc:
			self.ldap_connection = ldc.connection
			ldap_user = LDAPUser(
				connection=self.ldap_connection,
				username=user.username,
				search_attrs=[
					RuntimeSettings.LDAP_FIELD_MAP[LOCAL_ATTR_USERNAME],
					RuntimeSettings.LDAP_FIELD_MAP[LOCAL_ATTR_DN],
					RuntimeSettings.LDAP_FIELD_MAP[LOCAL_ATTR_UAC],
				],
			)
			if not ldap_user.exists:
				raise exc_user.UserDoesNotExist
			if not ldap_user.can_change_password:
				raise PermissionDenied

			self.ldap_set_password(
				user_dn=ldap_user.distinguished_name,
				user_pwd_new=data[LOCAL_ATTR_PASSWORD],
				user_pwd_old=aes_decrypt(*user.encrypted_password),
			)

		django_user: User = None
		try:
			django_user = User.objects.get(username=user.username)
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
			log_target=user.username,
			message=LOG_EXTRA_USER_CHANGE_PASSWORD,
		)

		return Response(data={"code": code, "code_msg": code_msg, "data": data})

	@auth_required
	@ldap_backend_intercept
	@action(detail=False, methods=["put", "post"], url_path="self/update")
	def self_update(self, request: Request, pk=None):
		user = request.user
		user: User  # For type-hints
		code = 0
		code_msg = "ok"
		data = request.data
		if user.user_type != USER_TYPE_LDAP:
			raise exc_user.UserNotLDAPType

		ALERT_KEYS = (
			LOCAL_ATTR_USERNAME,
			LOCAL_ATTR_DN,
			RuntimeSettings.LDAP_FIELD_MAP[LOCAL_ATTR_USERNAME],
			RuntimeSettings.LDAP_FIELD_MAP[LOCAL_ATTR_DN],
		)
		for k in ALERT_KEYS:
			if k in data:
				logger.warning(
					"User %s requested self-update with malformed data.",
					user.username,
				)
				raise exc_base.BadRequest

		# Set attrs and filter
		self.search_attrs = self.filter_attr_builder(
			RuntimeSettings
		).get_update_attrs()
		EXCLUDE_KEYS = self.filter_attr_builder(
			RuntimeSettings
		).get_update_self_exclude_keys()

		for key in EXCLUDE_KEYS:
			if key in data:
				del data[key]

		serializer = self.serializer_class(data=data)
		serializer.is_valid(raise_exception=True)
		data = serializer.validated_data

		# Open LDAP Connection
		# User doesn't have rights to change any data in LDAP Server
		# so admin must be forced, auth_required decorator with
		# require_admin flag is very important
		with LDAPConnector(force_admin=True) as ldc:
			self.ldap_connection = ldc.connection
			ldap_user_search = user.username
			self.ldap_user_update(
				data=data | {LOCAL_ATTR_USERNAME: user.username}
			)

		logger.debug(self.ldap_connection.result)

		django_user: User = None
		try:
			django_user = User.objects.get(username=ldap_user_search)
		except ObjectDoesNotExist:
			pass

		if django_user:
			for key in RuntimeSettings.LDAP_FIELD_MAP:
				mapped_key = RuntimeSettings.LDAP_FIELD_MAP[key]
				if mapped_key in data and hasattr(django_user, mapped_key):
					setattr(django_user, key, data[mapped_key])
			django_user.save()

		DBLogMixin.log(
			user=user.id,
			operation_type=LOG_ACTION_UPDATE,
			log_target_class=LOG_CLASS_USER,
			log_target=ldap_user_search,
			message=LOG_EXTRA_USER_END_USER_UPDATE,
		)
		return Response(data={"code": code, "code_msg": code_msg, "data": data})

	@auth_required
	@action(detail=False, methods=["get"], url_path="self/info")
	def self_info(self, request: Request):
		"""Method used by all user types (Local, LDAP, etc.)"""
		user: User = request.user
		data = {}
		code = 0
		data[LOCAL_ATTR_USERNAME] = user.username or ""
		data[LOCAL_ATTR_FIRST_NAME] = user.first_name or ""
		data[LOCAL_ATTR_LAST_NAME] = user.last_name or ""
		data[LOCAL_ATTR_EMAIL] = user.email or ""
		data[LOCAL_ATTR_USERTYPE] = user.user_type or ""
		# This only informs the front-end it is admin capable
		# Validation is done on the back-end
		if user.is_superuser:
			data["admin_allowed"] = True
		return Response(data={"code": code, "code_msg": "ok", "user": data})

	@auth_required
	@ldap_backend_intercept
	@action(detail=False, methods=["get"], url_path="self/fetch")
	def self_fetch(self, request: Request):
		user: User = request.user
		code = 0
		code_msg = "ok"
		user_search = user.username
		if user.user_type == USER_TYPE_LOCAL:
			user_data = {}
			for field in LOCAL_PUBLIC_FIELDS:
				user_data[field] = getattr(user, field)
			for k, v in user_data.items():
				if isinstance(v, datetime):
					user_data[k] = v.strftime(DATE_FORMAT_ISO_8601_ALT)
		elif user.user_type == USER_TYPE_LDAP:
			# Open LDAP Connection
			with LDAPConnector(user) as ldc:
				self.ldap_connection = ldc.connection
				user_data = self.ldap_user_fetch(user_search=user_search)
				_keys = self.filter_attr_builder(
					RuntimeSettings
				).get_fetch_me_attrs()
				user_data = {key: user_data.get(key, "") for key in _keys}

		if LOCAL_ATTR_ID in user_data:
			del user_data[LOCAL_ATTR_ID]
		return Response(
			data={"code": code, "code_msg": code_msg, "data": user_data}
		)

	@auth_required
	@admin_required
	@ldap_backend_intercept
	@action(
		detail=False,
		methods=["get"],
		url_name="bulk-export",
		url_path="bulk/export",
	)
	def export_csv(self, request: Request):
		request_user: User = request.user
		date = tz.make_aware(datetime.now())
		filename = "interlock_ldap_users_export_%s.csv" % (
			date.strftime(DATE_FORMAT_CSV)
		)
		self.search_filter = LDAPFilter.eq(
			RuntimeSettings.LDAP_FIELD_MAP[LOCAL_ATTR_OBJECT_CLASS],
			RuntimeSettings.LDAP_AUTH_OBJECT_CLASS,
		)
		self.search_attrs = self.filter_attr_builder(
			RuntimeSettings
		).get_fetch_attrs()
		self.search_attrs.remove(LDAP_ATTR_USER_GROUPS)

		keys = [getlocalkeyforldapattr(v) for v in self.search_attrs if v]

		# Open LDAP Connection
		with LDAPConnector(force_admin=True) as ldc:
			self.ldap_connection = ldc.connection
			data = self.ldap_user_list()

		serialized_users = []
		for user in data["users"]:
			serialized_user = LDAPUserSerializer(data=user)
			if serialized_user.is_valid():
				serialized_users.append(serialized_user.validated_data)
			else:
				logger.error(
					"Could not serialize user (Errors: %s)",
					str(serialized_user.errors),
				)

		DBLogMixin.log(
			user=request_user.id,
			operation_type=LOG_ACTION_READ,
			log_target_class=LOG_CLASS_USER,
			log_target=LOG_TARGET_ALL,
			message=LOG_EXTRA_EXPORT,
		)

		return StreamingHttpResponse(
			csv_iterator(data["users"], keys),
			content_type="text/csv",
			headers={
				"Content-Disposition": f'attachment; filename="{filename}"'
			},
		)
