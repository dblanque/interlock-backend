################################################################################
#################### INTERLOCK IS LICENSED UNDER GNU AGPLv3 ####################
################## ORIGINAL PROJECT CREATED BY DYLAN BLANQUÉ ###################
########################## AND BR CONSULTING S.R.L. ############################
################################################################################
# Module: core.views.user
# Contains the Django User ViewSet and related methods

# ---------------------------------- IMPORTS -----------------------------------#
# Views
from core.views.base import BaseViewSet

# Models
from core.models.user import User, USER_TYPE_LOCAL
from core.models.choices.log import (
	LOG_ACTION_CREATE,
	LOG_ACTION_READ,
	LOG_ACTION_UPDATE,
	LOG_ACTION_DELETE,
	LOG_CLASS_USER,
	LOG_EXTRA_USER_END_USER_UPDATE,
	LOG_EXTRA_ENABLE,
	LOG_EXTRA_DISABLE,
	LOG_EXTRA_USER_CHANGE_PASSWORD,
)

# Exceptions
from django.core.exceptions import ObjectDoesNotExist
from core.exceptions import users as exc_user
from core.exceptions.base import BadRequest

# REST Framework
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.decorators import action

# Mixins
from core.views.mixins.user import AllUserMixins
from core.views.mixins.logs import LogMixin

# Others
from core.constants.attrs import (
	LOCAL_ATTR_ID,
	LOCAL_ATTR_USERTYPE,
	LOCAL_ATTR_MODIFIED,
	LOCAL_ATTR_CREATED,
	LOCAL_ATTR_PASSWORD,
	LOCAL_ATTR_PASSWORD_CONFIRM,
	LOCAL_ATTR_USERNAME,
	LOCAL_ATTR_DN,
	LOCAL_ATTR_LAST_LOGIN_WIN32,
	LOCAL_ATTR_FIRST_NAME,
	LOCAL_ATTR_LAST_NAME,
	LOCAL_ATTR_EMAIL,
	LOCAL_ATTR_ENABLED,
)
from django.db import transaction
from core.decorators.login import auth_required, admin_required
from core.constants.user import LOCAL_PUBLIC_FIELDS, LOCAL_PUBLIC_FIELDS_BASIC
from django.db.models import F
import logging
from typing import Any
################################################################################

DBLogMixin = LogMixin()
logger = logging.getLogger(__name__)


class UserViewSet(BaseViewSet, AllUserMixins):

	@auth_required
	@admin_required
	def list(self, request: Request, pk=None):
		code = 0
		code_msg = "ok"
		VALUE_ONLY = (
			LOCAL_ATTR_ID,
			LOCAL_ATTR_DN,
		)
		user_queryset = User.objects.annotate(
			distinguished_name=F(f"_{LOCAL_ATTR_DN}"),
		).all()
		DBLogMixin.log(
			user=request.user.id,
			operation_type=LOG_ACTION_READ,
			log_target_class=LOG_CLASS_USER,
		)

		result = list(user_queryset.values(*LOCAL_PUBLIC_FIELDS_BASIC))
		headers = [
			field
			for field in LOCAL_PUBLIC_FIELDS_BASIC
			if not field in VALUE_ONLY
		]

		return Response(
			data={
				"code": code,
				"code_msg": code_msg,
				"users": result,
				"headers": headers,
			}
		)

	@action(detail=False, methods=["post"])
	@auth_required
	@admin_required
	def insert(self, request: Request, pk=None):
		code = 0
		code_msg = "ok"
		data: dict = request.data
		serializer = self.serializer_class(data=data)

		if not serializer.is_valid():
			raise BadRequest(data={"errors": serializer.errors})

		validated_data = serializer.validated_data
		if LOCAL_ATTR_USERTYPE in validated_data:
			del validated_data[LOCAL_ATTR_USERTYPE]

		self.check_user_exists(username=validated_data.get(LOCAL_ATTR_USERNAME))
		with transaction.atomic():
			user_instance: User = User(**validated_data)
			password = serializer.validated_data.get(LOCAL_ATTR_PASSWORD, None)
			if password is None:
				user_instance.set_unusable_password()
			else:
				user_instance.set_password(password)
			user_instance.save()

		DBLogMixin.log(
			user=request.user.id,
			operation_type=LOG_ACTION_CREATE,
			log_target_class=LOG_CLASS_USER,
			log_target=user_instance.username,
		)

		return Response(
			data={
				"code": code,
				"code_msg": code_msg,
			}
		)

	@action(detail=True, methods=["get"])
	@auth_required
	@admin_required
	def fetch(self, request: Request, pk):
		code = 0
		code_msg = "ok"
		pk = int(pk)
		try:
			user_instance: User = User.objects.get(id=pk)
		except ObjectDoesNotExist:
			raise exc_user.UserDoesNotExist
		data = {}

		DBLogMixin.log(
			user=request.user.id,
			operation_type=LOG_ACTION_READ,
			log_target_class=LOG_CLASS_USER,
			log_target=user_instance.username,
		)
		for field in LOCAL_PUBLIC_FIELDS:
			data[field] = getattr(user_instance, field)
		return Response(data={"code": code, "code_msg": code_msg, "data": data})

	@auth_required
	@admin_required
	def update(self, request: Request, pk):
		code = 0
		code_msg = "ok"
		data: dict = request.data
		pk = int(pk)
		EXCLUDE_FIELDS = (
			LOCAL_ATTR_ID,
			LOCAL_ATTR_MODIFIED,
			LOCAL_ATTR_CREATED,
			LOCAL_ATTR_USERTYPE,
			LOCAL_ATTR_LAST_LOGIN_WIN32,
			LOCAL_ATTR_DN,
			LOCAL_ATTR_USERNAME,
		)
		for key in EXCLUDE_FIELDS:
			if key in data:
				del data[key]
		serializer = self.serializer_class(data=data, partial=True)

		# Validate Data
		if not serializer.is_valid():
			raise BadRequest(data={"errors": serializer.errors})

		try:
			user_instance: User = User.objects.get(id=pk)
		except ObjectDoesNotExist:
			raise exc_user.UserDoesNotExist

		if user_instance.user_type != USER_TYPE_LOCAL:
			raise exc_user.UserNotLocalType

		# Set data
		for key in serializer.validated_data:
			setattr(user_instance, key, serializer.validated_data[key])

		password = serializer.validated_data.get(LOCAL_ATTR_PASSWORD, None)
		if password:
			user_instance.set_password(password)
		user_instance.save()

		DBLogMixin.log(
			user=request.user.id,
			operation_type=LOG_ACTION_UPDATE,
			log_target_class=LOG_CLASS_USER,
			log_target=user_instance.username,
		)
		return Response(
			data={
				"code": code,
				"code_msg": code_msg,
			}
		)

	@action(detail=True, methods=["delete", "post"])
	@auth_required
	@admin_required
	def delete(self, request: Request, pk):
		req_user: User = request.user
		code = 0
		code_msg = "ok"
		pk = int(pk)
		if req_user.id == pk:
			raise exc_user.UserAntiLockout

		with transaction.atomic():
			try:
				user_instance: User = User.objects.get(id=pk)
			except ObjectDoesNotExist:
				raise exc_user.UserDoesNotExist

			# Deletion of local instances of remote users should
			# also be allowed in the event of needing a manual cleanup.
			user_instance.delete_permanently()

		DBLogMixin.log(
			user=request.user.id,
			operation_type=LOG_ACTION_DELETE,
			log_target_class=LOG_CLASS_USER,
			log_target=user_instance.username,
		)
		return Response(
			data={
				"code": code,
				"code_msg": code_msg,
			}
		)

	@action(detail=True, methods=["post"])
	@auth_required
	@admin_required
	def change_status(self, request: Request, pk):
		req_user: User = request.user
		code = 0
		code_msg = "ok"
		data: dict = request.data
		pk = int(pk)

		if (
			not LOCAL_ATTR_ENABLED in data or
			not isinstance(data[LOCAL_ATTR_ENABLED], bool)
		):
			raise BadRequest(
				data={"detail": "Must contain field 'enabled' of type bool."}
			)

		if req_user.id == pk:
			raise exc_user.UserAntiLockout

		user_instance = self.user_change_status(
			user_pk=pk,
			target_status=data.pop(LOCAL_ATTR_ENABLED),
		)

		DBLogMixin.log(
			user=request.user.id,
			operation_type=LOG_ACTION_UPDATE,
			log_target_class=LOG_CLASS_USER,
			log_target=user_instance.username,
			message=LOG_EXTRA_ENABLE
			if user_instance.is_enabled
			else LOG_EXTRA_DISABLE,
		)
		return Response(
			data={
				"code": code,
				"code_msg": code_msg,
			}
		)

	@action(detail=True, methods=["post"])
	@auth_required
	@admin_required
	def change_password(self, request: Request, pk):
		user: User = request.user
		code = 0
		code_msg = "ok"
		data: dict = request.data
		pk = int(pk)
		for field in (LOCAL_ATTR_PASSWORD, LOCAL_ATTR_PASSWORD_CONFIRM):
			if not field in data:
				raise BadRequest(
					data={"errors": f"Must contain field {field}."}
				)

		try:
			user_instance: User = User.objects.get(id=pk)
		except ObjectDoesNotExist:
			raise exc_user.UserDoesNotExist

		if user_instance.user_type != USER_TYPE_LOCAL:
			raise exc_user.UserNotLocalType

		# Validate Data
		serializer = self.serializer_class(data=data, partial=True)
		if not serializer.is_valid():
			raise BadRequest(data={"errors": serializer.errors})

		user_instance.set_password(
			serializer.validated_data[LOCAL_ATTR_PASSWORD]
		)
		user_instance.save()

		DBLogMixin.log(
			user=user.id,
			operation_type=LOG_ACTION_UPDATE,
			log_target_class=LOG_CLASS_USER,
			log_target=user_instance.username,
			message=LOG_EXTRA_USER_CHANGE_PASSWORD,
		)

		return Response(
			data={
				"code": code,
				"code_msg": code_msg,
				"data": {LOCAL_ATTR_USERNAME: user_instance.username},
			}
		)

	@action(detail=False, methods=["post", "put"])
	@auth_required
	def self_change_password(self, request: Request):
		user: User = request.user
		code = 0
		code_msg = "ok"
		data: dict = request.data

		if user.user_type != USER_TYPE_LOCAL:
			raise exc_user.UserNotLocalType

		for field in (
			LOCAL_ATTR_USERNAME,
			LOCAL_ATTR_ID,
		):
			if field in data:
				raise BadRequest(data={
					"detail":f"Field is not allowed ({field})."
				})

		for field in (LOCAL_ATTR_PASSWORD, LOCAL_ATTR_PASSWORD_CONFIRM):
			if not field in data:
				raise BadRequest(
					data={"errors": f"Must contain field {field}."}
				)

		# Validate Data
		serializer = self.serializer_class(data=data, partial=True)
		if not serializer.is_valid():
			raise BadRequest(data={"errors": serializer.errors})

		user.set_password(serializer.validated_data[LOCAL_ATTR_PASSWORD])
		user.save()

		DBLogMixin.log(
			user=user.id,
			operation_type=LOG_ACTION_UPDATE,
			log_target_class=LOG_CLASS_USER,
			log_target=user.username,
			message=LOG_EXTRA_USER_CHANGE_PASSWORD,
		)

		return Response(
			data={
				"code": code,
				"code_msg": code_msg,
				"data": {LOCAL_ATTR_USERNAME: user.username},
			}
		)

	@action(detail=False, methods=["post", "put"])
	@auth_required
	def self_update(self, request: Request, pk=None):
		user: User = request.user
		code = 0
		code_msg = "ok"
		data: dict = request.data

		if user.user_type != USER_TYPE_LOCAL:
			raise exc_user.UserNotLocalType

		ALLOWED_FIELDS = (
			LOCAL_ATTR_FIRST_NAME,
			LOCAL_ATTR_LAST_NAME,
			LOCAL_ATTR_EMAIL,
		)
		for key in data:
			if not key in ALLOWED_FIELDS:
				del data[key]
		serializer = self.serializer_class(data=data, partial=True)

		if not serializer.is_valid():
			raise BadRequest(data={"errors": serializer.errors})

		for key in data:
			setattr(user, key, data[key])
		user.save()

		DBLogMixin.log(
			user=user.id,
			operation_type=LOG_ACTION_UPDATE,
			log_target_class=LOG_CLASS_USER,
			log_target=user.username,
			message=LOG_EXTRA_USER_END_USER_UPDATE,
		)

		return Response(
			data={
				"code": code,
				"code_msg": code_msg,
			}
		)

	@admin_required
	@auth_required
	@action(detail=False, methods=["post"], url_path="bulk/insert")
	def bulk_insert(self, request: Request):
		request_user: User = request.user
		code = 0
		code_msg = "ok"
		data = request.data
		created_users = 0
		error_users = 0

		# Do not pop this as it is later used/popped in each bulk method
		user_rows: list[list[Any]] = data.pop("users", None)
		user_dicts: list[dict[Any]] = data.pop("dict_users", None)

		if (not user_rows and not user_dicts) or (user_rows and user_dicts):
			raise BadRequest(data={
				"detail":	"To bulk insert users you must provide either the "\
							"users or dict_users fields."
			})
		
		if user_rows: # Insert from CSV
			# Map indices for local attrs
			index_map = self.map_bulk_create_attrs(
				headers=data.pop("headers", None),
				csv_map=data.pop("mapping", None)
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
				for u in user_rows
			]
			self.bulk_check_users(usernames_and_emails)

			# Perform creation operations
			created_users, error_users = self.bulk_create_from_csv(
				request_user=request_user,
				user_rows=user_rows,
				index_map=index_map,
			)
		elif user_dicts: # Insert from list of dicts
			self.bulk_check_users([
				(
					u.get(LOCAL_ATTR_USERNAME),
					u.get(LOCAL_ATTR_EMAIL, None),
				) for u in user_dicts
			])
			created_users, error_users = self.bulk_create_from_dicts(
				request_user=request_user,
				user_dicts=user_dicts,
			)

		return Response(
			data={
				"code": code,
				"code_msg": code_msg,
				"count": created_users,
				"count_error": error_users,
			}
		)

	@admin_required
	@auth_required
	@action(detail=False, methods=["put", "post"], url_path="bulk/update")
	def bulk_update(self, request: Request):
		request_user: User = request.user
		code = 0
		code_msg = "ok"
		data = request.data
		updated_users = 0
		
		# Validate data keys
		if any(
			v not in data
			for v in ("users", "values",)
		):
			raise BadRequest

		users = self.validated_user_pk_list(data=data)
		values = data.pop("values")

		with transaction.atomic():
			for pk in users:
				# Retrieve User
				try:
					user_instance: User = User.objects.get(id=pk)
				except ObjectDoesNotExist:
					raise exc_user.UserDoesNotExist
				
				if user_instance.user_type != USER_TYPE_LOCAL:
					raise exc_user.UserNotLocalType(data={
						"detail": f"User {user_instance.username} is not of Local Type."
					})

				# Validate Data
				serializer = self.serializer_class(data=values, partial=True)
				serializer.is_valid(raise_exception=True)

				# Set new data
				validated_data = serializer.validated_data
				for k, v in validated_data.items():
					setattr(user_instance, k, v)

				# Save
				user_instance.save()
				updated_users += 1

				# Log operation
				DBLogMixin.log(
					user=request_user.id,
					operation_type=LOG_ACTION_UPDATE,
					log_target_class=LOG_CLASS_USER,
					log_target=user_instance.username,
				)

		return Response(
			data={
				"code": code,
				"code_msg": code_msg,
				"count": updated_users,
			}
		)

	@admin_required
	@auth_required
	@action(detail=False, methods=["delete", "post"], url_path="bulk/delete")
	def bulk_delete(self, request: Request, pk=None):
		req_user: User = request.user
		code = 0
		code_msg = "ok"
		data: dict = request.data
		users: list[int] = self.validated_user_pk_list(data=data)
		deleted_users = 0
		error_users = 0

		if req_user.id in users:
			raise exc_user.UserAntiLockout(data={
				"detail": "Responsible user cannot be within selection."
			})

		with transaction.atomic():
			for pk in users:
				try:
					# Deletion of local instances of remote users should
					# also be allowed in the event of needing a manual cleanup.
					user_instance: User = User.objects.get(id=pk)
					user_instance.delete_permanently()
					deleted_users += 1

					# Log operation
					DBLogMixin.log(
						user=req_user.id,
						operation_type=LOG_ACTION_DELETE,
						log_target_class=LOG_CLASS_USER,
						log_target=user_instance.username,
					)
				except ObjectDoesNotExist:
					logger.warning("Could not delete non-existent user (Primary Key: %s)" % (pk))
					error_users += 1

		return Response(
			data={
				"code": code,
				"code_msg": code_msg,
				"count": deleted_users,
				"count_error": error_users,
			}
		)

	@admin_required
	@auth_required
	@action(
		detail=False,
		methods=["put", "patch", "post"],
		url_path="bulk/change-status",
	)
	def bulk_change_status(self, request: Request, pk=None):
		req_user: User = request.user
		code = 0
		code_msg = "ok"
		data: dict = request.data
		updated_users = 0
		error_users = 0
		users: list[int] = self.validated_user_pk_list(data=data)
		target_status = data.pop(LOCAL_ATTR_ENABLED, None)

		if not isinstance(target_status, bool):
			raise BadRequest(
				data={"detail": "Request data 'enabled' must be of type bool."}
			)

		if req_user.id in users:
			raise exc_user.UserAntiLockout(data={
				"detail": "Responsible user cannot be within selection."
			})

		with transaction.atomic():
			for pk in users:
				user_instance = self.user_change_status(
					user_pk=pk,
					target_status=target_status,
				)

				if user_instance:
					updated_users += 1

					# Log Operation
					DBLogMixin.log(
						user=request.user.id,
						operation_type=LOG_ACTION_UPDATE,
						log_target_class=LOG_CLASS_USER,
						log_target=user_instance.username,
						message=LOG_EXTRA_ENABLE
						if target_status
						else LOG_EXTRA_DISABLE,
					)

		return Response(
			data={
				"code": code,
				"code_msg": code_msg,
				"count": updated_users,
			}
		)
