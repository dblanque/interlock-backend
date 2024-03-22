################################################################################
#################### INTERLOCK IS LICENSED UNDER GNU AGPLv3 ####################
################## ORIGINAL PROJECT CREATED BY DYLAN BLANQUÉ ###################
########################## AND BR CONSULTING S.R.L. ############################
################################################################################
# Module: core.views.auth
# Contains the ViewSet for Authentication related operations

#---------------------------------- IMPORTS -----------------------------------#
### Core
from core.views.mixins.auth import CookieJWTAuthentication
from core.models.log import logToDB

### ViewSets
from .base import BaseViewSet

### REST Framework
from rest_framework.response import Response

### Interlock
from interlock_backend.ldap.constants_cache import *
from interlock_backend.settings import SIMPLE_JWT as JWT_SETTINGS, BAD_LOGIN_COOKIE_NAME

### Others
from datetime import datetime
import logging, jwt
from core.views.mixins.auth import DATE_FMT_COOKIE
################################################################################

logger = logging.getLogger(__name__)

class AuthViewSet(BaseViewSet):
	def refresh(self, request):
		cookieauth = CookieJWTAuthentication()
		access, refresh = cookieauth.refresh(request)

		# Send expiry date to backend on data as well.
		decoded_refresh = jwt.decode(
			refresh,
			key=JWT_SETTINGS["SIGNING_KEY"],
			algorithms=JWT_SETTINGS['ALGORITHM'],
			leeway=JWT_SETTINGS["LEEWAY"]
		)
		access_expire_epoch_seconds = access["exp"]
		refresh_expire_epoch_seconds = decoded_refresh["exp"]

		response =  Response(
			status=200,
			data={
				"access_expire":	access_expire_epoch_seconds * 1000,
				"refresh_expire":	refresh_expire_epoch_seconds * 1000
			}
		)
		response.set_cookie(
			key = JWT_SETTINGS['AUTH_COOKIE_NAME'],
			value = access,
			expires = datetime.fromtimestamp(access_expire_epoch_seconds).strftime(DATE_FMT_COOKIE),
			secure = JWT_SETTINGS['AUTH_COOKIE_SECURE'],
			httponly = JWT_SETTINGS['AUTH_COOKIE_HTTP_ONLY'],
			samesite = JWT_SETTINGS['AUTH_COOKIE_SAME_SITE']
		)
		response.set_cookie(
			key = JWT_SETTINGS['REFRESH_COOKIE_NAME'], 
			value = refresh,
			expires = datetime.fromtimestamp(refresh_expire_epoch_seconds).strftime(DATE_FMT_COOKIE),
			secure = JWT_SETTINGS['AUTH_COOKIE_SECURE'],
			httponly = JWT_SETTINGS['AUTH_COOKIE_HTTP_ONLY'],
			samesite = JWT_SETTINGS['AUTH_COOKIE_SAME_SITE']
		)
		return response

	def logout(self, request):
		user = request.user
		code = 0
		code_msg = 'ok'

		if LDAP_LOG_LOGOUT == True:
			# Log this action to DB
			logToDB(
				user_id=request.user.id,
				actionType="LOGOUT",
				objectClass="USER",
			)

		response = Response(
			 data={
				'code': code,
				'code_msg': code_msg,
			 }
		)

		# Expire Access/Refresh Cookie
		response.set_cookie(
			key=JWT_SETTINGS['AUTH_COOKIE_NAME'],
			value='expired',
			httponly=True,
			samesite=JWT_SETTINGS['AUTH_COOKIE_SAME_SITE'],
			domain=JWT_SETTINGS['AUTH_COOKIE_DOMAIN']
		)
		response.set_cookie(
			key=JWT_SETTINGS['REFRESH_COOKIE_NAME'],
			value='expired',
			httponly=True,
			samesite=JWT_SETTINGS['AUTH_COOKIE_SAME_SITE'],
			domain=JWT_SETTINGS['AUTH_COOKIE_DOMAIN']
		)
		response.delete_cookie(
			key=BAD_LOGIN_COOKIE_NAME,
			domain=JWT_SETTINGS['AUTH_COOKIE_DOMAIN']
		)

		return response