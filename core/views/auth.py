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
from core.decorators.login import auth_required
from core.models.log import logToDB

### ViewSets
from .base import BaseViewSet

### REST Framework
from rest_framework.response import Response

### Interlock
from interlock_backend.ldap.constants_cache import *
from interlock_backend.settings import SIMPLE_JWT as JWT_SETTINGS

### Others
from datetime import datetime
import logging
################################################################################

logger = logging.getLogger(__name__)

class AuthViewSet(BaseViewSet):
	def refresh(self, request):
		cookieauth = CookieJWTAuthentication()
		access, refresh = cookieauth.refresh(request)
		access_expire: datetime = datetime.now().utcnow() + JWT_SETTINGS['ACCESS_TOKEN_LIFETIME']
		refresh_expire: datetime = datetime.now().utcnow() + JWT_SETTINGS['REFRESH_TOKEN_LIFETIME']

		response =  Response(
			status=200,
		)
		response.set_cookie(
			key = JWT_SETTINGS['AUTH_COOKIE_NAME'],
			value = access,
			expires = access_expire,
			secure = JWT_SETTINGS['AUTH_COOKIE_SECURE'],
			httponly = JWT_SETTINGS['AUTH_COOKIE_HTTP_ONLY'],
			samesite = JWT_SETTINGS['AUTH_COOKIE_SAME_SITE']
		)
		response.set_cookie(
			key = JWT_SETTINGS['REFRESH_COOKIE_NAME'], 
			value = refresh,
			expires = refresh_expire,
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

		return response