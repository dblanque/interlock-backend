################################################################################
#################### INTERLOCK IS LICENSED UNDER GNU AGPLv3 ####################
################## ORIGINAL PROJECT CREATED BY DYLAN BLANQUÉ ###################
########################## AND BR CONSULTING S.R.L. ############################
################################################################################
# Module: core.views.totp
# Contains the ViewSet for TOTP Authentication related operations

#---------------------------------- IMPORTS -----------------------------------#
### Rest Framework
from rest_framework.response import Response
from rest_framework.decorators import action

### Core
from core.serializers.token import (
	OTPTokenSerializer
)
from core.views.mixins.totp import (
	create_device_totp_for_user,
	validate_user_otp,
	get_user_totp_device,
	delete_device_totp_for_user,
	parse_config_url
)
from core.exceptions import (
	users as exc_user,
	otp as exc_otp,
	base as exc_base
)
from core.decorators.login import auth_required

### ViewSets
from .base import BaseViewSet

### Models
from core.models import User
from core.models.log import logToDB

### Interlock
from interlock_backend.ldap.constants_cache import *
################################################################################

class TOTPViewSet(BaseViewSet):
	@auth_required()
	def list(self, request):
		user = request.user
		code = 0
		code_msg = 'ok'

		try:
			totp_device = get_user_totp_device(user)
		except:
			raise

		data={
			'code': code,
			'code_msg': code_msg
		}

		if totp_device:
			data['totp_uri'] = parse_config_url(totp_device.config_url)
			data['totp_confirmed'] = totp_device.confirmed,
			data['recovery_codes'] = user.recovery_codes

		return Response(
				data=data
		)

	@action(detail=False,methods=['get'])
	@auth_required()
	def create_device(self, request):
		user = request.user
		data = request.data
		code = 0
		code_msg = 'ok'

		if not OTPTokenSerializer(data=data):
			raise exc_otp.OTPInvalidData

		try:
			totp_uri = create_device_totp_for_user(user)
		except: raise

		return Response(
				data={
				'code': code,
				'code_msg': code_msg,
				'totp_uri': totp_uri,
				'recovery_codes': user.recovery_codes
				}
		)

	@action(detail=False,methods=['put', 'post'])
	@auth_required()
	def validate_device(self, request):
		user = request.user
		data = request.data
		code = 0
		code_msg = 'ok'

		if not OTPTokenSerializer(data=data):
			raise exc_otp.OTPInvalidData

		try:
			validate_user_otp(user, data)
		except: raise

		return Response(
				data={
				'code': code,
				'code_msg': code_msg
				}
		)

	@action(detail=False,methods=['post', 'delete'])
	@auth_required()
	def delete_device(self, request):
		user = request.user
		code = 0
		code_msg = 'ok'

		try:
			delete_device_totp_for_user(user)
		except: raise

		return Response(
				data={
				'code': code,
				'code_msg': code_msg
				}
		)

	@action(detail=False,methods=['post', 'delete'])
	@auth_required()
	def delete_for_user(self, request):
		user = request.user
		code = 0
		code_msg = 'ok'
		data = request.data
		try:
			target_username = data["username"]
		except:
			e = exc_base.MissingDataKey()
			e.set_detail({ "key": "username" })
			raise e
		target_user = None
		try:
			target_user = User.objects.get(username=target_username)
		except:
			raise exc_user.UserNotSynced()

		try:
			delete_device_totp_for_user(target_user)
			if LDAP_LOG_UPDATE == True:
					# Log this action to DB
					logToDB(
						user_id=request.user.id,
						actionType="DELETE",
						objectClass="USER",
						affectedObject=target_user.username,
						extraMessage="TOTP_DELETE"
					)
		except:
			raise

		return Response(
				data={
				'code': code,
				'code_msg': code_msg,
				'data': target_username
				}
		)