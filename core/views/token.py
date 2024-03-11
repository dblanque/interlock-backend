################################################################################
#################### INTERLOCK IS LICENSED UNDER GNU AGPLv3 ####################
################## ORIGINAL PROJECT CREATED BY DYLAN BLANQUÉ ###################
########################## AND BR CONSULTING S.R.L. ############################
################################################################################
# Module: core.views.token
# Contributors: Martín Vilche
# Contains the ViewSet for Token Authentication related operations

#---------------------------------- IMPORTS -----------------------------------#
### Interlock
from interlock_backend.settings import SIMPLE_JWT as JWT_SETTINGS

### Rest Framework
from rest_framework_simplejwt import views as jwt_views
from rest_framework.response import Response
from rest_framework import status
from rest_framework.decorators import action
from rest_framework.exceptions import AuthenticationFailed
from rest_framework_simplejwt.exceptions import TokenError

### Core
from core.serializers.token import (
	TokenObtainPairSerializer,
	OTPTokenSerializer
)
from core.views.mixins.token import (
	create_device_totp_for_user,
	validate_user_otp,
	get_user_totp_device,
	delete_device_totp_for_user,
	parse_config_url
)
from core.exceptions import otp as exc_otp
from core.decorators.login import auth_required
from core.views.mixins.auth import RemoveTokenResponse, DATE_FMT_COOKIE

### ViewSets
from .base import BaseViewSet

### Others
from datetime import datetime
################################################################################

class TokenObtainPairView(jwt_views.TokenViewBase):
	"""
	Takes a set of user credentials and returns an access and refresh JSON web
	token pair to prove the authentication of those credentials.
	"""
	serializer_class = TokenObtainPairSerializer
	token_exc = [
		TokenError,
		AuthenticationFailed
	]

	def post(self, request, *args, **kwargs):
		try:
			serializer: TokenObtainPairSerializer = self.get_serializer(data=request.data)
			serializer.is_valid(raise_exception=True)
		except Exception as e:
			print(type(e) in self.token_exc)
			if type(e) in self.token_exc == False: raise
			return RemoveTokenResponse()

		access_expire: datetime = datetime.now().utcnow() + JWT_SETTINGS['ACCESS_TOKEN_LIFETIME']
		refresh_expire: datetime = datetime.now().utcnow() + JWT_SETTINGS['REFRESH_TOKEN_LIFETIME']
		validated_data = serializer.validated_data
		tokens = dict()
		for k in ['access', 'refresh']:
			tokens[k] = validated_data.pop(k)
		response = Response(serializer.validated_data, status=status.HTTP_200_OK)
		response.set_cookie(
			key=JWT_SETTINGS['AUTH_COOKIE_NAME'],
			value=tokens['access'],
			httponly=True,
			samesite=JWT_SETTINGS['AUTH_COOKIE_SAME_SITE'],
			secure=JWT_SETTINGS['AUTH_COOKIE_SECURE'],
			expires=access_expire.strftime(DATE_FMT_COOKIE),
			domain=JWT_SETTINGS['AUTH_COOKIE_DOMAIN']
		)
		response.set_cookie(
			key=JWT_SETTINGS['REFRESH_COOKIE_NAME'],
			value=tokens['refresh'],
			httponly=True,
			samesite=JWT_SETTINGS['AUTH_COOKIE_SAME_SITE'],
			secure=JWT_SETTINGS['AUTH_COOKIE_SECURE'],
			expires=refresh_expire.strftime(DATE_FMT_COOKIE),
			domain=JWT_SETTINGS['AUTH_COOKIE_DOMAIN']
		)
		return response

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