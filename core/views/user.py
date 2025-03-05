################################################################################
#################### INTERLOCK IS LICENSED UNDER GNU AGPLv3 ####################
################## ORIGINAL PROJECT CREATED BY DYLAN BLANQUÉ ###################
########################## AND BR CONSULTING S.R.L. ############################
################################################################################
# Module: core.views.base
# Contains a Basic Parent Class ViewSet and methods shared to all ViewSets

# ---------------------------------- IMPORTS -----------------------------------#
from core.views.base import BaseViewSet
from core.models.user import User
# REST Framework
from rest_framework.response import Response
from rest_framework.decorators import action

### Others
from core.decorators.login import auth_required
################################################################################

class UserViewSet(BaseViewSet):

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

	@auth_required()
	def fetch(self, request, pk=None):
		code = 0
		code_msg = "ok"
		return Response(
			 data={
				"code": code,
				"code_msg": code_msg,
			 }
		)

	@auth_required()
	def update(self, request, pk=None):
		code = 0
		code_msg = "ok"
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
