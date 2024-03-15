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
from rest_framework.exceptions import AuthenticationFailed
from rest_framework_simplejwt.exceptions import TokenError

### Core
from core.serializers.token import TokenObtainPairSerializer
from core.views.mixins.auth import RemoveTokenResponse, DATE_FMT_COOKIE

### Others
from datetime import datetime, timezone
import logging
################################################################################

logger = logging.getLogger(__name__)
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
			if any(type(e) == type(te) for te in self.token_exc):
				return RemoveTokenResponse()
			raise e

		access_expire: datetime = datetime.now().astimezone(timezone.utc) + JWT_SETTINGS['ACCESS_TOKEN_LIFETIME']
		refresh_expire: datetime = datetime.now().astimezone(timezone.utc) + JWT_SETTINGS['REFRESH_TOKEN_LIFETIME']
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
