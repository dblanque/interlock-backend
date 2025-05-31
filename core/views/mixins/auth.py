################################################################################
#################### INTERLOCK IS LICENSED UNDER GNU AGPLv3 ####################
################## ORIGINAL PROJECT CREATED BY DYLAN BLANQUÉ ###################
########################## AND BR CONSULTING S.R.L. ############################
################################################################################
# Module: core.views.mixins.auth
# Contributors: Martín Vilche
# Contains the ViewSet for Token Authentication related operations

# ---------------------------------- IMPORTS -----------------------------------#
### Django
from django.utils.translation import gettext_lazy as _
from django.contrib.auth.models import AnonymousUser

### Interlock
from interlock_backend.settings import (
	SIMPLE_JWT as JWT_SETTINGS,
	BAD_LOGIN_COOKIE_NAME,
)

### Core
from core.models.user import User
from core.exceptions.base import AccessTokenInvalid, RefreshTokenExpired

### Rest Framework
from rest_framework.response import Response
from rest_framework import status
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework_simplejwt.exceptions import TokenError
from rest_framework_simplejwt.tokens import AccessToken, RefreshToken

### Others
import logging
################################################################################

logger = logging.getLogger(__name__)

EMPTY_TOKEN = ""
DATE_FMT_COOKIE = "%a, %d %b %Y %H:%M:%S GMT"
BAD_LOGIN_LIMIT = 5


def RemoveTokenResponse(
	request, remove_refresh=False, bad_login_count=False
) -> Response:
	response = Response(status=status.HTTP_401_UNAUTHORIZED)
	response.set_cookie(
		key=JWT_SETTINGS["AUTH_COOKIE_NAME"],
		value="expired",
		httponly=True,
		samesite=JWT_SETTINGS["AUTH_COOKIE_SAME_SITE"],
		domain=JWT_SETTINGS["AUTH_COOKIE_DOMAIN"],
	)
	if remove_refresh:
		response.set_cookie(
			key=JWT_SETTINGS["REFRESH_COOKIE_NAME"],
			value="expired",
			httponly=True,
			samesite=JWT_SETTINGS["AUTH_COOKIE_SAME_SITE"],
			domain=JWT_SETTINGS["AUTH_COOKIE_DOMAIN"],
		)

	if bad_login_count:
		try:
			bad_login_count = int(request.COOKIES.get(BAD_LOGIN_COOKIE_NAME))
		except:
			bad_login_count = 0
			pass
		if bad_login_count < BAD_LOGIN_LIMIT:
			bad_login_count = int(bad_login_count) + 1
		else:
			bad_login_count = 0
		try:
			response.set_cookie(
				key=BAD_LOGIN_COOKIE_NAME,
				value=bad_login_count,
				httponly=False,
				samesite=JWT_SETTINGS["AUTH_COOKIE_SAME_SITE"],
				domain=JWT_SETTINGS["AUTH_COOKIE_DOMAIN"],
			)
		except:
			pass
	response.data = {"remaining_login_count": BAD_LOGIN_LIMIT - bad_login_count}
	return response


class CookieJWTAuthentication(JWTAuthentication):
	def authenticate(self, request) -> tuple[User, AccessToken]:
		"""Authenticates request user.

		Args:
			request (HttpRequest): The HTTP Request

		Raises:
			AccessTokenInvalid
			generic_e

		Returns:
			tuple[User, AccessToken]: Returns a tuple with the corresponding User
			and Access Token object.
		"""
		try:
			AUTH_TOKEN = request.COOKIES.get(JWT_SETTINGS["AUTH_COOKIE_NAME"])
			if (
				not AUTH_TOKEN
				or AUTH_TOKEN == "expired"
				or len(AUTH_TOKEN) == 0
			):
				return AnonymousUser(), EMPTY_TOKEN
			validated_token = AccessToken(AUTH_TOKEN)
		except TokenError as e:
			raise AccessTokenInvalid()
		except Exception as generic_e:
			logger.exception(generic_e)
			raise generic_e
		return self.get_user(validated_token), validated_token

	def refresh(self, request) -> tuple[AccessToken, RefreshToken]:
		"""Validates user tokens and returns new access and refresh based on
		validation outcome.

		Returns:
			tuple[AccessToken, str]: A tuple with the AccessToken as an object
				and stringified Refresh Token.
		"""
		REFRESH_TOKEN = request.COOKIES.get(JWT_SETTINGS["REFRESH_COOKIE_NAME"])
		if (
			not REFRESH_TOKEN
			or REFRESH_TOKEN == "expired"
			or len(REFRESH_TOKEN) == 0
		):
			raise RefreshTokenExpired()

		try:
			refreshed_tokens = RefreshToken(REFRESH_TOKEN)
		except TokenError as e:
			raise RefreshTokenExpired()
		except Exception as generic_e:
			logger.exception(generic_e)
			raise generic_e
		refreshed_tokens.set_jti()
		refreshed_tokens.set_exp()
		refreshed_tokens.set_iat()

		return refreshed_tokens.access_token, refreshed_tokens
