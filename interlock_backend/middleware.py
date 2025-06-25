################################################################################
#################### INTERLOCK IS LICENSED UNDER GNU AGPLv3 ####################
################## ORIGINAL PROJECT CREATED BY DYLAN BLANQUÉ ###################
########################## AND BR CONSULTING S.R.L. ############################
################################################################################
# Module: interlock_backend.middleware
# Contains Middleware classes

# ---------------------------------- IMPORTS --------------------------------- #
from core.models.user import User
from core.exceptions.base import PermissionDenied
from corsheaders.middleware import (
	CorsMiddleware,
	ACCESS_CONTROL_ALLOW_ORIGIN,
	ACCESS_CONTROL_ALLOW_METHODS,
)
from django.http.request import HttpRequest
from django.http.response import HttpResponseBase, HttpResponse
import re
################################################################################


def AccountStatusMiddleware(get_response):
	def middleware(request: HttpRequest):
		response: HttpResponse = get_response(request)
		if hasattr(request, "user"):
			user: User = request.user
			if hasattr(user, "is_enabled"):
				if not user.is_enabled:
					return PermissionDenied()
		return response

	return middleware


OPENID_WELLKNOWN_PATTERN = re.compile(r"^(/openid/)?\.well-known/openid-configuration/?$")
class OpenIDCorsMiddleware(CorsMiddleware):
	def add_response_headers(
		self, request: HttpRequest, response: HttpResponseBase
	) -> HttpResponseBase:
		# Bypass CORS restrictions for the OpenID configuration endpoint
		if request.path and OPENID_WELLKNOWN_PATTERN.match(request.path):
			response[ACCESS_CONTROL_ALLOW_ORIGIN] = "*"
			response[ACCESS_CONTROL_ALLOW_METHODS] = "GET, OPTIONS"
			return response

		# Apply default CORS rules for all other endpoints
		return super().add_response_headers(request, response)