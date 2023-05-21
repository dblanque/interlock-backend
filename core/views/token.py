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
	fetch_device_totp_for_user,
	delete_device_totp_for_user
)
from core.exceptions import otp as exc_otp
from interlock_backend.ldap.encrypt import validateUser
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
	def list(self, request):
		user = request.user
		validateUser(request=request)
		code = 0
		code_msg = 'ok'

		try:
			totp_uri = fetch_device_totp_for_user(user)
		except: raise

		return Response(
				data={
				'code': code,
				'code_msg': code_msg,
				'totp_uri': totp_uri
				}
		)

	@action(detail=False,methods=['get'])
	def create_device(self, request):
		user = request.user
		data = request.data
		validateUser(request=request)
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
				'totp_uri': totp_uri
				}
		)

	@action(detail=False,methods=['put', 'post'])
	def validate_device(self, request):
		user = request.user
		data = request.data
		validateUser(request=request)
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
	def delete_device(self, request):
		user = request.user
		validateUser(request=request)
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