################################################################################
#################### INTERLOCK IS LICENSED UNDER GNU AGPLv3 ####################
################## ORIGINAL PROJECT CREATED BY DYLAN BLANQUÉ ###################
########################## AND BR CONSULTING S.R.L. ############################
################################################################################
# Module: core.views.mixins.auth
# Contributors:
# 	- Martín Vilche
# 	- Dylan Blanqué
# Contains the ViewSet for Token Authentication related operations

# ---------------------------------- IMPORTS --------------------------------- #
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
from rest_framework.renderers import BrowsableAPIRenderer

### Others
from django.http.request import HttpRequest
import logging
################################################################################

logger = logging.getLogger(__name__)

EMPTY_TOKEN = ""
DATE_FMT_COOKIE = "%a, %d %b %Y %H:%M:%S GMT"
BAD_LOGIN_LIMIT = 5


def is_axios_request(request: HttpRequest):
	"""Determine if the request comes from Front-end"""
	headers = request.headers
	# Check for Axios-specific headers
	is_xml = (
		headers.get("X-Requested-With", "").lower() == "xmlhttprequest"
		or headers.get("X-XHR-Requested-With", "").lower() == "xmlhttprequest"
	)
	# Check for content type (Axios mostly sends JSON)
	is_json = request.content_type == "application/json"
	# Check if it's an API view (DRF adds this attribute)
	renderer = getattr(request, "accepted_renderer", None)
	renderer_is_accepted = renderer is not None
	return (is_xml or is_json or renderer_is_accepted) and not isinstance(
		renderer, BrowsableAPIRenderer
	)


class RemoveTokenResponse:
	def __new__(
		cls,
		request: HttpRequest,
		remove_refresh: bool = False,
		bad_login_count: bool = False,
	) -> Response:
		"""Response used to Remove a client's JWT.

		Args:
			request (HttpRequest): The HTTP Request
			remove_refresh (bool, optional): Whether to remove the client's
				Refresh Token or just the Access Token. Defaults to False.
			bad_login_count (bool, optional): Whether to set the bad login
				count cookie on the client. Defaults to False.

		Returns:
			Response: Standard rest_framework Response type.
		"""
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

		# If not a front-end request return without bad login count logic
		if is_axios_request(request=request) and bad_login_count:
			try:
				_count = int(request.COOKIES.get(BAD_LOGIN_COOKIE_NAME))
			except:
				_count = 0
				pass
			if _count < BAD_LOGIN_LIMIT:
				_count = int(_count) + 1
			else:
				_count = 0
			response.set_cookie(
				key=BAD_LOGIN_COOKIE_NAME,
				value=_count,
				httponly=False,
				samesite=JWT_SETTINGS["AUTH_COOKIE_SAME_SITE"],
				domain=JWT_SETTINGS["AUTH_COOKIE_DOMAIN"],
			)

			response.data = {"remaining_login_count": BAD_LOGIN_LIMIT - _count}
		return response


class CookieJWTAuthentication(JWTAuthentication):
	def authenticate(self, request: HttpRequest) -> tuple[User, AccessToken]:
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

	def refresh(self, request: HttpRequest) -> tuple[AccessToken, RefreshToken]:
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
