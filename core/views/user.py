################################################################################
#################### INTERLOCK IS LICENSED UNDER GNU AGPLv3 ####################
################## ORIGINAL PROJECT CREATED BY DYLAN BLANQUÉ ###################
########################## AND BR CONSULTING S.R.L. ############################
################################################################################
# Module: core.views.user
# Contains the Django User ViewSet and related methods

# ---------------------------------- IMPORTS -----------------------------------#
from core.views.base import BaseViewSet
from core.models.user import User
from core.serializers.user import UserSerializer
from core.exceptions.base import BadRequest

# REST Framework
from rest_framework.response import Response
from rest_framework.decorators import action

# Others
from core.decorators.login import auth_required
################################################################################


class UserViewSet(BaseViewSet):
	serializer_class = UserSerializer

	@auth_required()
	def list(self, request, pk=None):
		code = 0
		code_msg = "ok"
		FIELDS = (
			"id",
			"username",
			"email",
			"dn",
			"user_type",
			"is_enabled",
		)
		VALUE_ONLY = (
			"id",
			"dn",
		)
		users = User.objects.all()
		return Response(
			data={
				"code": code,
				"code_msg": code_msg,
				"users": users.values(*FIELDS),
				"headers": [field for field in FIELDS if not field in VALUE_ONLY]
			}
		)

	@auth_required()
	def create(self, request, pk=None):
		code = 0
		code_msg = "ok"
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
		user = User.objects.get(id=pk)
		FIELDS = (
			"id",
			"username",
			"first_name",
			"last_name",
			"last_login",
			"created_at",
			"modified_at",
			"email",
			"dn",
			"user_type",
			"is_enabled",
		)
		data = {}
		for field in FIELDS:
			data[field] = getattr(user, field)
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
		EXCLUDE_FIELDS = (
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

		user = User.objects.get(id=data.pop("id"))
		for key in data:
			setattr(user, key, data[key])
		user.save()
		return Response(
			data={
				"code": code,
				"code_msg": code_msg,
			}
		)

	@auth_required()
	def delete(self, request, pk=None):
		code = 0
		code_msg = "ok"
		return Response(
			data={
				"code": code,
				"code_msg": code_msg,
			}
		)

	@action(detail=True,methods=['post'])
	def change_status(self, request, pk):
		code = 0
		code_msg = "ok"
		data: dict = request.data
		pk = int(pk)
		if not "enabled" in data:
			raise BadRequest(data={
				"errors": "Must contain field enabled (bool)"
			})
		user = User.objects.get(id=pk)
		user.is_enabled = data.pop("enabled")
		user.save()
		return Response(
			data={
				"code": code,
				"code_msg": code_msg,
			}
		)