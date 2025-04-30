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
from core.models.user import User
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

# Serializers
from core.serializers.user import UserSerializer

# Exceptions
from core.exceptions import users as exc_user
from core.exceptions.base import BadRequest

# REST Framework
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.decorators import action

# Mixins
from core.views.mixins.logs import LogMixin

# Others
from django.db import transaction
from core.decorators.login import auth_required, admin_required
from core.config.runtime import RuntimeSettings
from core.constants.user import PUBLIC_FIELDS, PUBLIC_FIELDS_SHORT
import logging
################################################################################

DBLogMixin = LogMixin()
logger = logging.getLogger(__name__)


class UserViewSet(BaseViewSet):
	serializer_class = UserSerializer

	@auth_required
	@admin_required
	def list(self, request: Request, pk=None):
		code = 0
		code_msg = "ok"
		VALUE_ONLY = (
			"id",
			"dn",
		)
		user_queryset = User.objects.all()
		DBLogMixin.log(
			user=request.user.id,
			operation_type=LOG_ACTION_READ,
			log_target_class=LOG_CLASS_USER,
		)
		return Response(
			data={
				"code": code,
				"code_msg": code_msg,
				"users": user_queryset.values(*PUBLIC_FIELDS_SHORT),
				"headers": [
					field
					for field in PUBLIC_FIELDS_SHORT
					if not field in VALUE_ONLY
				],
			}
		)

	@action(detail=False, methods=["post"])
	@auth_required
	@admin_required
	def insert(self, request, pk=None):
		code = 0
		code_msg = "ok"
		data: dict = request.data
		serializer = self.serializer_class(data=data)
		password = None
		FIELDS_EXCLUDE = ("permission_list",)
		for field in FIELDS_EXCLUDE:
			if field in data:
				del data[field]

		if not serializer.is_valid():
			raise BadRequest(data={"errors": serializer.errors})
		else:
			serialized_data = serializer.data
			password = serialized_data.pop("password")
			serialized_data.pop("passwordConfirm")
			with transaction.atomic():
				user_instance = User.objects.create(**serialized_data)
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
	def fetch(self, request, pk):
		code = 0
		code_msg = "ok"
		pk = int(pk)
		user_instance = User.objects.get(id=pk)
		data = {}
		DBLogMixin.log(
			user=request.user.id,
			operation_type=LOG_ACTION_READ,
			log_target_class=LOG_CLASS_USER,
			log_target=user_instance.username,
		)
		for field in PUBLIC_FIELDS:
			data[field] = getattr(user_instance, field)
		return Response(data={"code": code, "code_msg": code_msg, "data": data})

	@auth_required
	@admin_required
	def update(self, request, pk):
		code = 0
		code_msg = "ok"
		data: dict = request.data
		pk = int(pk)
		EXCLUDE_FIELDS = (
			"id",
			"modified_at",
			"created_at",
			"user_type",
			"last_login",
			"dn",
			"username",
		)
		for key in EXCLUDE_FIELDS:
			if key in data:
				data.pop(key)
		serializer = self.serializer_class(data=data, partial=True)

		if not serializer.is_valid():
			raise BadRequest(data={"errors": serializer.errors})

		user_instance = User.objects.get(id=pk)
		for key in data:
			setattr(user_instance, key, data[key])
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
	def delete(self, request, pk):
		req_user: User = request.user
		code = 0
		code_msg = "ok"
		pk = int(pk)
		with transaction.atomic():
			user_instance = User.objects.get(id=pk)
			if req_user.id == pk:
				raise exc_user.UserAntiLockout
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
	def change_status(self, request, pk):
		code = 0
		code_msg = "ok"
		data: dict = request.data
		pk = int(pk)
		if not "enabled" in data or not isinstance(data["enabled"], bool):
			raise BadRequest(
				data={"errors": "Must contain field enabled (bool)"}
			)
		user_instance = User.objects.get(id=pk)
		user_instance.is_enabled = data.pop("enabled")
		user_instance.save()

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
	def change_password(self, request, pk):
		user: User = request.user
		code = 0
		code_msg = "ok"
		data: dict = request.data
		pk = int(pk)
		for field in ("password", "passwordConfirm"):
			if not field in data:
				raise BadRequest(
					data={"errors": f"Must contain field {field}."}
				)
		user_instance = User.objects.get(id=pk)
		serializer = self.serializer_class(data=data, partial=True)
		serializer.is_valid()
		user_instance.set_password(data["password"])
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
				"data": {"username": user_instance.username},
			}
		)

	@action(detail=False, methods=["post", "put"])
	@auth_required
	def self_change_password(self, request):
		user: User = request.user
		code = 0
		code_msg = "ok"
		data: dict = request.data
		for field in ("password", "passwordConfirm"):
			if not field in data:
				raise BadRequest(
					data={"errors": f"Must contain field {field}."}
				)

		serializer = self.serializer_class(data=data, partial=True)
		serializer.is_valid()
		user.set_password(data["password"])
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
				"data": {"username": user.username},
			}
		)

	@action(detail=False, methods=["post", "put"])
	@auth_required
	def self_update(self, request, pk=None):
		user: User = request.user
		code = 0
		code_msg = "ok"
		data: dict = request.data
		FIELDS = (
			"first_name",
			"last_name",
			"email",
		)
		for key in data:
			if not key in FIELDS:
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
