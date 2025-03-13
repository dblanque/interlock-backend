################################################################################
#################### INTERLOCK IS LICENSED UNDER GNU AGPLv3 ####################
################## ORIGINAL PROJECT CREATED BY DYLAN BLANQUÉ ###################
########################## AND BR CONSULTING S.R.L. ############################
################################################################################
# Module: core.decorators.intercept
# Contains Interception related decorators
# ONLY FOR BUILDING TESTS FROM REAL DATA
from core.models.user import User
from core.models.interlock_settings import InterlockSetting, INTERLOCK_SETTING_ENABLE_LDAP
from django.core.exceptions import ObjectDoesNotExist
from rest_framework.request import Request
from core.exceptions.base import LDAPBackendDisabled
from rest_framework import status
from functools import wraps
from logging import getLogger
logger = getLogger()

def request_intercept(func=None):
	def decorator(view_func):
		@wraps(view_func)
		def _wrapped(request, *args, **kwargs):
			actual_request: Request = request.request
			user: User = actual_request.user
			logger.info(actual_request)
			logger.info(user)
			logger.info(actual_request.query_params)
			logger.info(actual_request.data)
			return view_func(request, *args, **kwargs)
		return _wrapped
	if func is None:
		return decorator
	return decorator(func)

def ldap_backend_intercept(func=None):
	def decorator(view_func):
		@wraps(view_func)
		def _wrapped(request, *args, **kwargs):            
			try:
				ldap_setting = InterlockSetting.objects.get(
					name=INTERLOCK_SETTING_ENABLE_LDAP
				)
				ldap_enabled = ldap_setting.value
			except ObjectDoesNotExist:
				# Handle missing setting (now properly initialized)
				ldap_enabled = False

			if not ldap_enabled:
				raise LDAPBackendDisabled()
			return view_func(request, *args, **kwargs)
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
