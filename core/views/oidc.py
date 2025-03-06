################################################################################
#################### INTERLOCK IS LICENSED UNDER GNU AGPLv3 ####################
################## ORIGINAL PROJECT CREATED BY DYLAN BLANQUÉ ###################
########################## AND BR CONSULTING S.R.L. ############################
################################################################################
# Module: core.views.application
# Contains the ViewSet for SSO Application related operations

#---------------------------------- IMPORTS -----------------------------------#

### Mixins
from core.views.mixins.auth import CookieJWTAuthentication

### ViewSets
from oidc_provider.views import TokenView, AuthorizeView
from oidc_provider.lib.endpoints.authorize import AuthorizeEndpoint

### Models
from core.models.user import User

### Django
from django.http import HttpRequest, HttpResponse
from django.shortcuts import redirect
from urllib.parse import quote

### Others
from urllib.parse import urlparse, parse_qs
from interlock_backend.settings import (
	OIDC_INTERLOCK_LOGIN_COOKIE,
	SIMPLE_JWT as JWT_SETTINGS
)
from interlock_backend.settings import LOGIN_URL
import logging
################################################################################
logger = logging.getLogger(__name__)

class OidcAuthorizeEndpoint(AuthorizeEndpoint):
	def _extract_params(self) -> None:
		super()._extract_params()
		logger.debug(self.params)
		return

Q_OIDC_FAILED = "oidc_failed"
Q_OIDC_ERROR = "oidc_error"
Q_NEXT = "next"
# OIDC Middleware
class OidcAuthorizeView(AuthorizeView):
	authorize_endpoint_class = OidcAuthorizeEndpoint

	def get(self, request: HttpRequest, *args, **kwargs):
		cookieauth = CookieJWTAuthentication()
		request.user, token = cookieauth.authenticate(request)
		user: User = request.user
		login_url = None

		# TODO - Check if user is in application's groups (LDAP, Local, etc.)
		if not user.is_authenticated or not user.is_enabled:
			OIDC_FAILED = request.COOKIES.get(OIDC_INTERLOCK_LOGIN_COOKIE, "false").lower() == "true"
			if OIDC_FAILED:
				login_url = f"{LOGIN_URL}/?{Q_OIDC_FAILED}=true"
			else:
				original_url = request.get_full_path()
				# Encode the URL for safe inclusion in another URL
				encoded_url = quote(original_url)
				login_url = f"{LOGIN_URL}/?{Q_NEXT}={encoded_url}"

			redirect_response = redirect(login_url)
			if OIDC_FAILED:
				redirect_response.delete_cookie(OIDC_INTERLOCK_LOGIN_COOKIE)
			else:
				redirect_response.set_cookie(
					key=OIDC_INTERLOCK_LOGIN_COOKIE,
					value="true",
					httponly=False,
					samesite=JWT_SETTINGS['AUTH_COOKIE_SAME_SITE'],
					secure=JWT_SETTINGS['AUTH_COOKIE_SECURE'],
					domain=JWT_SETTINGS['AUTH_COOKIE_DOMAIN']
				)
		else:
			redirect_response: HttpResponse = super().get(request, *args, **kwargs)
			redirect_response.delete_cookie(OIDC_INTERLOCK_LOGIN_COOKIE)

			if hasattr(redirect_response, "headers"):
				for location_key in ("Location", "location"):
					if location_key in redirect_response.headers:
						_redirect_url = redirect_response.headers[location_key]
						_parsed_url = urlparse(_redirect_url)
						_parsed_query = parse_qs(_parsed_url.query)

				if "error" in _parsed_query:
					_error = _parsed_query["error"][0]
					login_url = f"{LOGIN_URL}/?{Q_OIDC_FAILED}=true&{Q_OIDC_ERROR}={_error}"
					redirect_response = redirect(login_url)
					redirect_response.delete_cookie(OIDC_INTERLOCK_LOGIN_COOKIE)
					return redirect_response
		return redirect_response

	def post(self, request, *args, **kwargs):
		user: User = request.user
		response = super().post(request, *args, **kwargs)
		logger.warning(f"{user.username} used OIDC.")
		return response

# class CustomTokenView(TokenView):
# 	def post(self, request, *args, **kwargs):
# 		# Add custom token issuance logic (e.g., track token grants)
# 		response = super().post(request, *args, **kwargs)
# 		if 'access_token' in response.data:
# 			track_access_token(request.user, response.data['access_token'])
# 		return response