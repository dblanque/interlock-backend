################################################################################
#################### INTERLOCK IS LICENSED UNDER GNU AGPLv3 ####################
################## ORIGINAL PROJECT CREATED BY DYLAN BLANQUÉ ###################
########################## AND BR CONSULTING S.R.L. ############################
################################################################################
# Module: core.views.auth
# Contains the ViewSet for Authentication related operations

# ---------------------------------- IMPORTS -----------------------------------#
### Core
from core.views.mixins.auth import CookieJWTAuthentication
from core.views.mixins.logs import LogMixin
from core.models.choices.log import LOG_ACTION_LOGOUT, LOG_CLASS_USER

### ViewSets
from .base import BaseViewSet

### REST Framework
from rest_framework.response import Response
from rest_framework.request import Request
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.exceptions import TokenError

### Django
from django.http.request import HttpRequest

### Interlock
from interlock_backend.settings import (
	SIMPLE_JWT as JWT_SETTINGS,
	BAD_LOGIN_COOKIE_NAME,
)

### Others
from core.exceptions.base import BadRequest, InternalServerError
from typing import Union
import logging
from core.views.mixins.auth import DATE_FMT_COOKIE
from core.decorators.login import auth_required
################################################################################

DBLogMixin = LogMixin()
logger = logging.getLogger(__name__)


def set_expired_jwt_cookies(response: Response):
	# Expire Access/Refresh Cookie
	response.set_cookie(
		key=JWT_SETTINGS["AUTH_COOKIE_NAME"],
		value="expired",
		httponly=True,
		samesite=JWT_SETTINGS["AUTH_COOKIE_SAME_SITE"],
		domain=JWT_SETTINGS["AUTH_COOKIE_DOMAIN"],
	)
	response.set_cookie(
		key=JWT_SETTINGS["REFRESH_COOKIE_NAME"],
		value="expired",
		httponly=True,
		samesite=JWT_SETTINGS["AUTH_COOKIE_SAME_SITE"],
		domain=JWT_SETTINGS["AUTH_COOKIE_DOMAIN"],
	)
	response.set_cookie(
		key=BAD_LOGIN_COOKIE_NAME,
		value=0,
		httponly=True,
		samesite=JWT_SETTINGS["AUTH_COOKIE_SAME_SITE"],
		domain=JWT_SETTINGS["AUTH_COOKIE_DOMAIN"],
	)
	return response


class AuthViewSet(BaseViewSet):
	def refresh(self, request: Request):
		cookieauth = CookieJWTAuthentication()
		access, refresh = cookieauth.refresh(request)

		# Send expiry date to backend on data as well.
		access_expire_time = access.current_time + access.lifetime
		refresh_expire_time = refresh.current_time + refresh.lifetime

		response = Response(
			status=200,
			data={
				"access_expire": int(access_expire_time.timestamp() * 1000),
				"refresh_expire": int(refresh_expire_time.timestamp() * 1000),
			},
		)
		response.set_cookie(
			key=JWT_SETTINGS["AUTH_COOKIE_NAME"],
			value=access.__str__(),
			expires=access_expire_time.strftime(DATE_FMT_COOKIE),
			secure=JWT_SETTINGS["AUTH_COOKIE_SECURE"],
			httponly=JWT_SETTINGS["AUTH_COOKIE_HTTP_ONLY"],
			samesite=JWT_SETTINGS["AUTH_COOKIE_SAME_SITE"],
		)
		response.set_cookie(
			key=JWT_SETTINGS["REFRESH_COOKIE_NAME"],
			value=refresh.__str__(),
			expires=refresh_expire_time.strftime(DATE_FMT_COOKIE),
			secure=JWT_SETTINGS["AUTH_COOKIE_SECURE"],
			httponly=JWT_SETTINGS["AUTH_COOKIE_HTTP_ONLY"],
			samesite=JWT_SETTINGS["AUTH_COOKIE_SAME_SITE"],
		)
		return response

	@auth_required
	def logout(self, request: Union[HttpRequest, Request]):
		code = 0
		code_msg = "ok"

		try:
			# Blacklist refresh token
			refresh_token = request.COOKIES.get(
				JWT_SETTINGS["REFRESH_COOKIE_NAME"]
			)
			if refresh_token:
				token = RefreshToken(refresh_token)
				token.blacklist()

			# Log logout if necessary
			DBLogMixin.log(
				user=request.user.id,
				operation_type=LOG_ACTION_LOGOUT,
				log_target_class=LOG_CLASS_USER,
			)

			# Response with access/refresh removal
			response = Response(
				data={
					"code": code,
					"code_msg": code_msg,
				}
			)
			response = set_expired_jwt_cookies(response=response)
			return response
		except TokenError as e:
			raise BadRequest(
				data={
					"detail": str(e),
				}
			)
		except Exception as e:
			logger.exception(e)
			raise InternalServerError
