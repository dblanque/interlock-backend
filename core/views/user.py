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
from core.views.mixins.ldap.user import LDAPUserMixin

# Models
from core.models.user import User
from core.models.interlock_settings import (
	InterlockSetting,
	INTERLOCK_SETTING_ENABLE_LDAP,
)
from core.ldap.connector import LDAPConnector
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
from django.core.exceptions import ObjectDoesNotExist
from core.exceptions import users as exc_user
from core.exceptions.base import BadRequest

# REST Framework
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.decorators import action

# Mixins
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
)
from django.db import transaction
from core.decorators.login import auth_required, admin_required
from core.constants.user import LOCAL_PUBLIC_FIELDS, LOCAL_PUBLIC_FIELDS_BASIC
import logging
################################################################################

DBLogMixin = LogMixin()
logger = logging.getLogger(__name__)


class UserViewSet(BaseViewSet, LDAPUserMixin):
	serializer_class = UserSerializer

	@auth_required
	@admin_required
	def list(self, request: Request, pk=None):
		code = 0
		code_msg = "ok"
		VALUE_ONLY = (
			LOCAL_ATTR_ID,
			LOCAL_ATTR_DN,
		)
		user_queryset = User.objects.all()
		DBLogMixin.log(
			user=request.user.id,
			operation_type=LOG_ACTION_READ,
			log_target_class=LOG_CLASS_USER,
		)
		result = list(user_queryset.values(*LOCAL_PUBLIC_FIELDS_BASIC))
		key_to_fix = f"_{LOCAL_ATTR_DN}"
		for user in result:
			_v = user.pop(key_to_fix, None)
			if _v:
				user[LOCAL_ATTR_DN] = _v

		headers = list(LOCAL_PUBLIC_FIELDS_BASIC)
		for i, v in enumerate(headers):
			if v == key_to_fix:
				headers[i] = LOCAL_ATTR_DN

		return Response(
			data={
				"code": code,
				"code_msg": code_msg,
				"users": result,
				"headers": [
					field for field in headers if not field in VALUE_ONLY
				],
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
		password = None
		ldap_backend_enabled = InterlockSetting.objects.get(
			name=INTERLOCK_SETTING_ENABLE_LDAP
		)

		if not serializer.is_valid():
			raise BadRequest(data={"errors": serializer.errors})
		else:
			serialized_data = serializer.data
			password = serialized_data.get(LOCAL_ATTR_PASSWORD)
			if ldap_backend_enabled:
				# Open LDAP Connection
				with LDAPConnector(force_admin=True) as ldc:
					self.ldap_connection = ldc.connection
					self.ldap_user_exists(
						username=serialized_data.get(LOCAL_ATTR_USERNAME)
					)
			with transaction.atomic():
				user_instance: User = User(**serialized_data)
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
		user_instance: User = User.objects.get(id=pk)
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
				data.pop(key)
		serializer = self.serializer_class(data=data, partial=True)

		if not serializer.is_valid():
			raise BadRequest(data={"errors": serializer.errors})

		try:
			user_instance: User = User.objects.get(id=pk)
		except ObjectDoesNotExist:
			raise exc_user.UserDoesNotExist

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
	def delete(self, request: Request, pk):
		req_user: User = request.user
		code = 0
		code_msg = "ok"
		pk = int(pk)
		with transaction.atomic():
			try:
				user_instance = User.objects.get(id=pk)
			except ObjectDoesNotExist:
				raise exc_user.UserDoesNotExist

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
	def change_status(self, request: Request, pk):
		code = 0
		code_msg = "ok"
		data: dict = request.data
		pk = int(pk)
		if not "enabled" in data or not isinstance(data["enabled"], bool):
			raise BadRequest(
				data={"errors": "Must contain field enabled (bool)"}
			)

		try:
			user_instance: User = User.objects.get(id=pk)
		except ObjectDoesNotExist:
			raise exc_user.UserDoesNotExist
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
		FIELDS = (
			LOCAL_ATTR_FIRST_NAME,
			LOCAL_ATTR_LAST_NAME,
			LOCAL_ATTR_EMAIL,
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
