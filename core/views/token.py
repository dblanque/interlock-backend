################################################################################
#################### INTERLOCK IS LICENSED UNDER GNU AGPLv3 ####################
################## ORIGINAL PROJECT CREATED BY DYLAN BLANQUÉ ###################
########################## AND BR CONSULTING S.R.L. ############################
################################################################################
# Module: core.views.token
# Contains the ViewSet for Token Authentication related operations

#---------------------------------- IMPORTS -----------------------------------#
from rest_framework_simplejwt import views as jwt_views
from rest_framework.response import Response
from rest_framework.decorators import action
from core.serializers.token import (
	TokenObtainPairSerializer,
	TokenRefreshSerializer,
	OTPTokenSerializer
)
from core.views.mixins.token import (
	create_device_totp_for_user,
	validate_user_otp,
	get_user_totp_device,
	delete_device_totp_for_user,
	parse_config_url
)
from core.models.user import User
from core.exceptions import otp as exc_otp
from core.decorators.login import auth_required
### ViewSets
from .base import BaseViewSet
################################################################################

class TokenObtainPairView(jwt_views.TokenViewBase):
	"""
	Takes a set of user credentials and returns an access and refresh JSON web
	token pair to prove the authentication of those credentials.
	"""
	serializer_class = TokenObtainPairSerializer

token_obtain_pair = TokenObtainPairView.as_view()

class TokenRefreshView(jwt_views.TokenViewBase):
	"""
	Takes a refresh type JSON web token and returns an access type JSON web
	token if the refresh token is valid.
	"""
	serializer_class = TokenRefreshSerializer

token_refresh = TokenRefreshView.as_view()

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