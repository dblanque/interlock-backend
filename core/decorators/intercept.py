################################################################################
#################### INTERLOCK IS LICENSED UNDER GNU AGPLv3 ####################
################## ORIGINAL PROJECT CREATED BY DYLAN BLANQUÉ ###################
########################## AND BR CONSULTING S.R.L. ############################
################################################################################
# Module: core.decorators.intercept
# Contains Request interception decorators for DEVELOPMENT

# ---------------------------------- IMPORTS --------------------------------- #
from core.models.interlock_settings import (
	InterlockSetting,
	INTERLOCK_SETTING_ENABLE_LDAP,
)
from django.core.exceptions import ObjectDoesNotExist
from rest_framework.request import Request
from core.exceptions.base import LDAPBackendDisabled
from functools import wraps
from logging import getLogger
from core.views.mixins.auth import CookieJWTAuthentication
from core.exceptions.base import AccessTokenInvalid

################################################################################
logger = getLogger()


def request_intercept(func=None):
	def decorator(view_func):
		@wraps(view_func)
		def _wrapped(self, request: Request, *args, **kwargs):
			try:
				cookie_auth = CookieJWTAuthentication()
				request.user, token = cookie_auth.authenticate(request)
			except AccessTokenInvalid:
				pass
			logger.info(request)
			logger.info(request.user)
			if hasattr(request, "query_params"):
				logger.info(request.query_params)
			else:
				logger.info("No query params.")
			if hasattr(request, "data"):
				logger.info(request.data)
			else:
				logger.info("No data.")
			return view_func(self, request, *args, **kwargs)

		return _wrapped

	if func is None:
		return decorator
	return decorator(func)


def is_ldap_backend_enabled() -> bool:
	"""Gets the LDAP Back-end enabled state."""
	try:
		ldap_setting = InterlockSetting.objects.get(
			name=INTERLOCK_SETTING_ENABLE_LDAP
		)
		return ldap_setting.value
	except ObjectDoesNotExist:
		# Handle missing setting (not properly initialized)
		pass
	return False


def ldap_backend_intercept(func=None):
	def decorator(view_func):
		@wraps(view_func)
		def _wrapped(self, request: Request, *args, **kwargs):
			if not is_ldap_backend_enabled():
				raise LDAPBackendDisabled()
			return view_func(self, request, *args, **kwargs)

		return _wrapped

	# Handle both @decorator and @decorator() usage
	if func is None:
		return decorator
	return decorator(func)


def intercept():
	def decorator(func):
		@wraps(func)
		def _wrapped(*args, **kwargs):
			logger.info(args)
			logger.info(kwargs)
			return func(*args, **kwargs)

		return _wrapped

	return decorator
