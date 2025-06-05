################################################################################
#################### INTERLOCK IS LICENSED UNDER GNU AGPLv3 ####################
################## ORIGINAL PROJECT CREATED BY DYLAN BLANQUÉ ###################
########################## AND BR CONSULTING S.R.L. ############################
################################################################################
# Module: core.views.totp
# Contains the ViewSet for TOTP Authentication related operations

# ---------------------------------- IMPORTS -----------------------------------#
### Rest Framework
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.decorators import action

### Core
from core.constants.attrs.local import LOCAL_ATTR_USERNAME
from core.models.choices.log import (
	LOG_ACTION_DELETE,
	LOG_CLASS_USER,
	LOG_EXTRA_TOTP_DELETE,
)
from core.serializers.token import OTPTokenSerializer
from core.views.mixins.totp import (
	create_device_totp_for_user,
	validate_user_otp,
	get_user_totp_device,
	delete_device_totp_for_user,
	set_interlock_otp_label,
)
from core.exceptions import users as exc_user, otp as exc_otp, base as exc_base
from core.decorators.login import auth_required, admin_required

### ViewSets
from .base import BaseViewSet

### Models
from core.models import User
from core.views.mixins.logs import LogMixin
################################################################################

DBLogMixin = LogMixin()


class TOTPViewSet(BaseViewSet):
	@auth_required
	def list(self, request: Request):
		user: User = request.user
		code = 0
		code_msg = "ok"
		data = {"code": code, "code_msg": code_msg}

		totp_device = get_user_totp_device(user)
		if totp_device:
			data["totp_uri"] = set_interlock_otp_label(
				url=totp_device.config_url,
				user=user,
			)
			data["totp_confirmed"] = (totp_device.confirmed,)
			data["recovery_codes"] = user.recovery_codes
		else:
			data["totp_uri"] = None
			data["totp_confirmed"] = (False,)
			data["recovery_codes"] = []

		return Response(data=data)

	@action(detail=False, methods=["get"])
	@auth_required
	def create_device(self, request: Request):
		user: User = request.user
		code = 0
		code_msg = "ok"

		totp_uri = create_device_totp_for_user(user)
		return Response(
			data={
				"code": code,
				"code_msg": code_msg,
				"totp_uri": totp_uri,
				"recovery_codes": user.recovery_codes,
			}
		)

	@action(detail=False, methods=["put", "post"])
	@auth_required
	def validate_device(self, request: Request):
		user: User = request.user
		data = request.data
		code = 0
		code_msg = "ok"

		if not OTPTokenSerializer(data=data):
			raise exc_otp.OTPInvalidData

		try:
			validate_user_otp(user, data)
		except:
			raise

		return Response(data={"code": code, "code_msg": code_msg})

	@action(detail=False, methods=["post", "delete"])
	@auth_required
	def delete_device(self, request: Request):
		user: User = request.user
		code = 0
		code_msg = "ok"

		delete_device_totp_for_user(user)
		return Response(data={"code": code, "code_msg": code_msg})

	@action(detail=False, methods=["post", "delete"])
	@auth_required
	@admin_required
	def delete_for_user(self, request: Request):
		user: User = request.user
		code = 0
		code_msg = "ok"
		data = request.data
		target_username = data.get(LOCAL_ATTR_USERNAME, None)
		if not target_username:
			raise exc_base.MissingDataKey(data={"key": LOCAL_ATTR_USERNAME})

		target_user = None
		try:
			target_user: User = User.objects.get(username=target_username)
		except:
			raise exc_user.UserDoesNotExist()

		device_was_deleted = delete_device_totp_for_user(target_user)

		if device_was_deleted:
			# Log this action to DB
			DBLogMixin.log(
				user=user.id,
				operation_type=LOG_ACTION_DELETE,
				log_target_class=LOG_CLASS_USER,
				log_target=target_user.username,
				message=LOG_EXTRA_TOTP_DELETE,
			)

		return Response(
			data={"code": code, "code_msg": code_msg, "data": target_username}
		)
