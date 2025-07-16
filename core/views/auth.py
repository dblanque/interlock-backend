################################################################################
#################### INTERLOCK IS LICENSED UNDER GNU AGPLv3 ####################
################## ORIGINAL PROJECT CREATED BY DYLAN BLANQUÉ ###################
########################## AND BR CONSULTING S.R.L. ############################
################################################################################
# Module: core.views.auth
# Contains the ViewSet for Authentication related operations

# ---------------------------------- IMPORTS --------------------------------- #
### Core
from core.decorators.login import auth_required
from core.views.mixins.auth import CookieJWTAuthentication, DATE_FMT_COOKIE
from core.views.mixins.logs import LogMixin
from core.models.choices.log import LOG_ACTION_LOGOUT, LOG_CLASS_USER
from core.models.user import User, USER_TYPE_LOCAL
from core.constants.attrs.local import LOCAL_ATTR_USERNAME, LOCAL_ATTR_PASSWORD
from core.ldap.connector import LDAPConnector
from core.views.mixins.totp import validate_user_otp
from interlock_backend.encrypt import fernet_decrypt
from core.decorators.intercept import is_ldap_backend_enabled

### Exceptions
from core.exceptions.base import (
	BadRequest,
	InternalServerError,
	Unauthorized,
	PermissionDenied,
)
from core.exceptions.otp import OTPRequired

### ViewSets
from .base import BaseViewSet

### REST Framework
from rest_framework.views import APIView
from rest_framework.throttling import AnonRateThrottle, UserRateThrottle
from rest_framework.response import Response
from rest_framework.request import Request
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.exceptions import TokenError
from rest_framework import status

### Django
from django.core.exceptions import ObjectDoesNotExist
from django.http.request import HttpRequest
from django.http.response import JsonResponse

### Interlock
from interlock_backend.settings import (
	SIMPLE_JWT as JWT_SETTINGS,
	BAD_LOGIN_COOKIE_NAME,
)

### Others
from django_otp import user_has_device
from django.conf import settings
from typing import Union
import logging
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


class LinuxPamAnonRateThrottle(AnonRateThrottle):
	rate = getattr(settings, "LINUX_PAM_AUTH_THROTTLE", None) or "15/min"


class LinuxPamUserRateThrottle(UserRateThrottle):
	rate = getattr(settings, "LINUX_PAM_AUTH_THROTTLE", None) or "15/min"


class LinuxPamView(APIView):
	throttle_classes = [LinuxPamAnonRateThrottle, LinuxPamUserRateThrottle]

	def validate(self, data) -> dict:
		errors = {}
		if not isinstance(data, dict):
			raise BadRequest(
				data={"detail": "A json data dictionary is required."}
			)

		# Cross Check Key Verification
		unsafe_mode = data.get("unsafe", False)
		cross_check_key = None
		if not unsafe_mode:
			auth_key = data.get("cross_check_key", None)
			if not auth_key:
				errors["cross_check_key"] = "Client cross-check key required."
			else:
				try:
					cross_check_key = fernet_decrypt(auth_key)
				except Exception as e:
					logger.error("Could not decrypt PAM Auth cross-check key.")
					logger.exception(e)
					errors["cross_check_key"] = (
						"Client cross-check key could not be decrypted."
					)

			# If we have errors at this stage ignore all other validation.
			if errors:
				raise BadRequest(data={"errors": errors})
		data["cross_check_key"] = cross_check_key

		# String Values Validation
		str_err = "is required and must be of type str."
		## Username data type validation
		username = data.get(LOCAL_ATTR_USERNAME, None)
		if not isinstance(username, str) or not username:
			errors[LOCAL_ATTR_USERNAME] = f"Username {str_err}"
		## Password data type validation
		password = data.get(LOCAL_ATTR_PASSWORD, None)
		if not isinstance(password, str) or not password:
			errors[LOCAL_ATTR_PASSWORD] = f"Password {str_err}"

		# TOTP Code data type validation
		totp_exc_msg = "TOTP Code must be a numeric str or int."
		totp_code = data.get("totp_code", None)
		if isinstance(totp_code, str):
			totp_code = totp_code.strip()
		if totp_code:
			if not (
				isinstance(totp_code, int)
				or (
					isinstance(totp_code, str)
					and totp_code.isnumeric()
				)
			):
				errors["totp_code"] = totp_exc_msg
		data["totp_code"] = totp_code

		if errors:
			raise BadRequest(data={"errors": errors})

		if "unsafe" in data:
			del data["unsafe"]
		return data

	def get(self, request: Request, format=None):
		"""Endpoint to verify authentication for Linux PAM."""
		# Some of this can probably be put into a mixin if more non token
		# providing auth endpoints are required.

		# Validation
		validated_data = self.validate(data=request.data)
		username = validated_data[LOCAL_ATTR_USERNAME]
		password = validated_data[LOCAL_ATTR_PASSWORD]
		totp_code = validated_data.get("totp_code", None)
		cross_check_key = validated_data.get("cross_check_key", None)

		# Check User Auth.
		user = None
		authenticated = False

		# Try getting Local User and checking if password is OK
		try:
			user = User.objects.get(
				username=username,
				user_type=USER_TYPE_LOCAL,
			)
			if isinstance(user, User):
				authenticated = user.check_password(password)
		except (ObjectDoesNotExist, User.DoesNotExist):
			pass

		# Try with LDAP User if no Local User was found
		if not isinstance(user, User) and is_ldap_backend_enabled():
			with LDAPConnector(force_admin=True, is_authenticating=True) as ldc:
				# Syncs the user to local db then checks it
				user = ldc.get_user(username=username)
				if isinstance(user, User):
					if ldc.rebind(
						user_dn=user.distinguished_name, password=password
					):
						authenticated = True

		if not user or not authenticated:
			raise Unauthorized

		if (
			getattr(settings, "LINUX_PAM_AUTH_ENDPOINT_ADMIN_ONLY", True) and
			not (user.is_superuser and user.is_staff)
		):
			raise PermissionDenied

		if user_has_device(user=user):
			if not totp_code:
				raise OTPRequired
			else:
				validate_user_otp(user=user, data=validated_data)
		return Response(
			data={
				"code": 0,
				"code_msg": "ok",
				"is_superuser": user.is_superuser,
				"cross_check_key": cross_check_key
			},
			status=status.HTTP_200_OK
		)
	
	def post(self, request: Request, format=None):
		return self.get(request=request, format=format)

class AuthViewSet(BaseViewSet):
	@auth_required
	def check_session(self, request: Request):
		return JsonResponse(
			data={
				"code": 200,
				"code_msg": "ok",
			}
		)

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
