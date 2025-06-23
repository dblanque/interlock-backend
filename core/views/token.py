################################################################################
#################### INTERLOCK IS LICENSED UNDER GNU AGPLv3 ####################
################## ORIGINAL PROJECT CREATED BY DYLAN BLANQUÉ ###################
########################## AND BR CONSULTING S.R.L. ############################
################################################################################
# Module: core.views.token
# Contributors: Martín Vilche
# Contains the ViewSet for Token Authentication related operations

# ---------------------------------- IMPORTS --------------------------------- #
### Interlock
from interlock_backend.settings import (
	SIMPLE_JWT as JWT_SETTINGS,
	BAD_LOGIN_COOKIE_NAME,
)

### Rest Framework
from rest_framework_simplejwt import views as jwt_views
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework import status
from rest_framework.exceptions import AuthenticationFailed
from rest_framework_simplejwt.exceptions import TokenError
from django.utils.timezone import now as tz_aware_now

### Core
from core.constants.attrs.local import (
	LOCAL_ATTR_USERNAME,
	LOCAL_ATTR_LAST_LOGIN,
)
from core.models.user import User, USER_TYPE_LDAP
from core.serializers.token import TokenObtainPairSerializer
from core.views.mixins.auth import RemoveTokenResponse, DATE_FMT_COOKIE
from core.decorators.intercept import is_ldap_backend_enabled

### Others
import logging
################################################################################

logger = logging.getLogger(__name__)


class TokenObtainPairView(jwt_views.TokenViewBase):
	"""
	Takes a set of user credentials and returns an access and refresh JSON web
	token pair to prove the authentication of those credentials.
	"""

	serializer_class = TokenObtainPairSerializer
	token_exc = [TokenError, AuthenticationFailed]

	def get_serializer(self, *args, **kwargs) -> TokenObtainPairSerializer:
		return super().get_serializer(*args, **kwargs)

	def post(self, request: Request, *args, **kwargs):
		try:
			serializer = self.get_serializer(data=request.data)
			serializer.is_valid(raise_exception=True)
		except Exception as e:
			if any(type(e) == te for te in self.token_exc):
				return RemoveTokenResponse(request, bad_login_count=True)
			raise e

		validated_data = serializer.validated_data
		tokens = {}
		for k in ["access", "refresh"]:
			tokens[k] = validated_data.pop(k)

		# Get User Instance
		user: User = User.objects.get(
			username=request.data.get(LOCAL_ATTR_USERNAME)
		)
		if user.user_type == USER_TYPE_LDAP and not is_ldap_backend_enabled():
			return RemoveTokenResponse(request, remove_refresh=True)
		user.last_login = tz_aware_now()
		user.save(update_fields=[LOCAL_ATTR_LAST_LOGIN])

		# Send expiry date to backend on data as well.
		refresh = serializer.refresh
		access = refresh.access_token
		access_expire_time = access.current_time + access.lifetime
		refresh_expire_time = refresh.current_time + refresh.lifetime

		response = Response(validated_data, status=status.HTTP_200_OK)
		response.set_cookie(
			key=JWT_SETTINGS["AUTH_COOKIE_NAME"],
			value=tokens["access"],
			httponly=True,
			samesite=JWT_SETTINGS["AUTH_COOKIE_SAME_SITE"],
			secure=JWT_SETTINGS["AUTH_COOKIE_SECURE"],
			expires=access_expire_time.strftime(DATE_FMT_COOKIE),
			domain=JWT_SETTINGS["AUTH_COOKIE_DOMAIN"],
		)
		response.set_cookie(
			key=JWT_SETTINGS["REFRESH_COOKIE_NAME"],
			value=tokens["refresh"],
			httponly=True,
			samesite=JWT_SETTINGS["AUTH_COOKIE_SAME_SITE"],
			secure=JWT_SETTINGS["AUTH_COOKIE_SECURE"],
			expires=refresh_expire_time.strftime(DATE_FMT_COOKIE),
			domain=JWT_SETTINGS["AUTH_COOKIE_DOMAIN"],
		)
		response.set_cookie(
			key=BAD_LOGIN_COOKIE_NAME,
			value=0,
			httponly=True,
			samesite=JWT_SETTINGS["AUTH_COOKIE_SAME_SITE"],
			secure=JWT_SETTINGS["AUTH_COOKIE_SECURE"],
			domain=JWT_SETTINGS["AUTH_COOKIE_DOMAIN"],
		)
		return response
