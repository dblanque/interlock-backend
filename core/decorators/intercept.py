################################################################################
#################### INTERLOCK IS LICENSED UNDER GNU AGPLv3 ####################
################## ORIGINAL PROJECT CREATED BY DYLAN BLANQUÉ ###################
########################## AND BR CONSULTING S.R.L. ############################
################################################################################
# Module: core.decorators.intercept
# Contains Interception related decorators
# ONLY FOR BUILDING TESTS FROM REAL DATA
from core.models.user import User
from rest_framework.request import Request
from functools import wraps
from logging import getLogger
logger = getLogger()

def request_intercept():
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
	return decorator

def intercept():
	def decorator(view_func):
		@wraps(view_func)
		def _wrapped(*args, **kwargs):
			logger.info(args)
			logger.info(kwargs)
			return view_func(*args, **kwargs)
		return _wrapped
	return decorator
