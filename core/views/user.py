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
from core.decorators.login import auth_required
from core.models.ldap_settings_runtime import RunningSettings
from core.constants.user import PUBLIC_FIELDS, PUBLIC_FIELDS_SHORT
import logging
################################################################################

DBLogMixin = LogMixin()
logger = logging.getLogger(__name__)

class UserViewSet(BaseViewSet):
	serializer_class = UserSerializer

	@auth_required()
	def list(self, request: Request, pk=None):
		code = 0
		code_msg = "ok"
		VALUE_ONLY = (
			"id",
			"dn",
		)
		user_queryset = User.objects.all()
		if RunningSettings.LDAP_LOG_READ == True:
			# Log this action to DB
			DBLogMixin.log(
				user_id=request.user.id,
				actionType="READ",
				objectClass="USER"
			)
		return Response(
			data={
				"code": code,
				"code_msg": code_msg,
				"users": user_queryset.values(*PUBLIC_FIELDS_SHORT),
				"headers": [field for field in PUBLIC_FIELDS_SHORT if not field in VALUE_ONLY]
			}
		)

	@action(detail=False, methods=['post'])
	@auth_required()
	def insert(self, request, pk=None):
		code = 0
		code_msg = "ok"
		data: dict = request.data
		serializer = self.serializer_class(data=data)
		password = None
		FIELDS_EXCLUDE = (
			"permission_list",
		)
		for field in FIELDS_EXCLUDE:
			if field in data:
				del data[field]

		if not serializer.is_valid():
			raise BadRequest(data={
				"errors": serializer.errors
			})
		elif not serializer.validate_password_confirm():
			raise exc_user.UserPasswordsDontMatch
		else:
			serialized_data = serializer.data
			password = serialized_data.pop("password")
			serialized_data.pop("passwordConfirm")
			with transaction.atomic():
				user_instance = User.objects.create(**serialized_data)
				user_instance.set_password(password)
				user_instance.save()

		if RunningSettings.LDAP_LOG_CREATE == True:
			# Log this action to DB
			DBLogMixin.log(
				user_id=request.user.id,
				actionType="CREATE",
				objectClass="USER",
				affectedObject=user_instance.username
			)

		return Response(
			data={
				"code": code,
				"code_msg": code_msg,
			}
		)

	@action(detail=True, methods=['get'])
	@auth_required()
	def fetch(self, request, pk):
		code = 0
		code_msg = "ok"
		pk = int(pk)
		user_instance = User.objects.get(id=pk)
		data = {}
		if RunningSettings.LDAP_LOG_READ == True:
			# Log this action to DB
			DBLogMixin.log(
				user_id=request.user.id,
				actionType="READ",
				objectClass="USER",
				affectedObject=user_instance.username
			)
		for field in PUBLIC_FIELDS:
			data[field] = getattr(user_instance, field)
		return Response(
			data={
				"code": code,
				"code_msg": code_msg,
				"data": data
			}
		)

	@auth_required()
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
			raise BadRequest(data={
				"errors": serializer.errors
			})

		user_instance = User.objects.get(id=pk)
		for key in data:
			setattr(user_instance, key, data[key])
		user_instance.save()
		if RunningSettings.LDAP_LOG_UPDATE == True:
			# Log this action to DB
			DBLogMixin.log(
				user_id=request.user.id,
				actionType="UPDATE",
				objectClass="USER",
				affectedObject=user_instance.username
			)
		return Response(
			data={
				"code": code,
				"code_msg": code_msg,
			}
		)

	@action(detail=True,methods=['delete', 'post'])
	@auth_required()
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
		if RunningSettings.LDAP_LOG_DELETE == True:
			# Log this action to DB
			DBLogMixin.log(
				user_id=request.user.id,
				actionType="DELETE",
				objectClass="USER",
				affectedObject=user_instance.username
			)
		return Response(
			data={
				"code": code,
				"code_msg": code_msg,
			}
		)

	@action(detail=True,methods=['post'])
	@auth_required()
	def change_status(self, request, pk):
		code = 0
		code_msg = "ok"
		data: dict = request.data
		pk = int(pk)
		if not "enabled" in data or not isinstance(data["enabled"], bool):
			raise BadRequest(data={
				"errors": "Must contain field enabled (bool)"
			})
		user_instance = User.objects.get(id=pk)
		user_instance.is_enabled = data.pop("enabled")
		user_instance.save()

		if RunningSettings.LDAP_LOG_UPDATE == True:
			# Log this action to DB
			DBLogMixin.log(
				user_id=request.user.id,
				actionType="UPDATE",
				objectClass="USER",
				affectedObject=user_instance.username,
				extraMessage="ENABLE" if user_instance.is_enabled is True else "DISABLE"
			)
		return Response(
			data={
				"code": code,
				"code_msg": code_msg,
			}
		)

	@action(detail=True,methods=['post'])
	@auth_required()
	def change_password(self, request, pk):
		user: User = request.user
		code = 0
		code_msg = "ok"
		data: dict = request.data
		pk = int(pk)
		for field in ("password", "passwordConfirm"):
			if not field in data:
				raise BadRequest(data={
					"errors": f"Must contain field {field}."
				})
		if not self.serializer_class().validate_password_confirm(data):
			raise exc_user.UserPasswordsDontMatch
		user_instance = User.objects.get(id=pk)
		user_instance.set_password(data["password"])
		user_instance.save()

		if RunningSettings.LDAP_LOG_UPDATE == True:
			# Log this action to DB
			DBLogMixin.log(
				user_id=user.id,
				actionType="UPDATE",
				objectClass="USER",
				affectedObject=user_instance.username,
				extraMessage="CHANGED_PASSWORD"
			)

		return Response(
			data={
				"code": code,
				"code_msg": code_msg,
				"data": { "username": user_instance.username }
			}
		)

	@action(detail=False,methods=['post', 'put'])
	@auth_required(require_admin=False)
	def self_change_password(self, request):
		user: User = request.user
		code = 0
		code_msg = "ok"
		data: dict = request.data
		for field in ("password", "passwordConfirm"):
			if not field in data:
				raise BadRequest(data={
					"errors": f"Must contain field {field}."
				})
		if not self.serializer_class().validate_password_confirm(data):
			raise exc_user.UserPasswordsDontMatch
		user.set_password(data["password"])
		user.save()

		if RunningSettings.LDAP_LOG_UPDATE == True:
			# Log this action to DB
			DBLogMixin.log(
				user_id=user.id,
				actionType="UPDATE",
				objectClass="USER",
				affectedObject=user.username,
				extraMessage="CHANGED_PASSWORD"
			)

		return Response(
			data={
				"code": code,
				"code_msg": code_msg,
				"data": { "username": user.username }
			}
		)

	@action(detail=False,methods=['post', 'put'])
	@auth_required(require_admin=False)
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
			raise BadRequest(data={
				"errors": serializer.errors
			})

		for key in data:
			setattr(user, key, data[key])
		user.save()

		if RunningSettings.LDAP_LOG_UPDATE == True:
			# Log this action to DB
			DBLogMixin.log(
				user_id=user.id,
				actionType="UPDATE",
				objectClass="USER",
				affectedObject=user.username,
				extraMessage="END_USER_UPDATED"
			)

		return Response(
			data={
				"code": code,
				"code_msg": code_msg,
			}
		)
