################################################################################
#################### INTERLOCK IS LICENSED UNDER GNU AGPLv3 ####################
################## ORIGINAL PROJECT CREATED BY DYLAN BLANQUÉ ###################
########################## AND BR CONSULTING S.R.L. ############################
################################################################################
# Module: core.decorators.login
# Contains Login and Authentication related decorators
from core.models.user import User
from rest_framework.request import Request
from core.exceptions.base import PermissionDenied
from core.views.mixins.auth import RemoveTokenResponse
from functools import wraps


def auth_required(func=None):
	def decorator(view_func):
		@wraps(view_func)
		def _wrapped(self, request: Request, *args, **kwargs):
			user: User = request.user

			# Check auth
			if not user.is_authenticated or user.is_anonymous:
				return RemoveTokenResponse(request=request)

			# Check account status
			if getattr(user, "deleted", False):
				raise PermissionDenied()

			return view_func(self, request, *args, **kwargs)

		return _wrapped

	# Handle decorator with/without arguments
	if func is None:
		return decorator
	return decorator(func)


def admin_required(func=None):
	def decorator(view_func):
		@wraps(view_func)
		def _wrapped(self, request: Request, *args, **kwargs):
			user: User = request.user
			if not getattr(user, "is_superuser", False):
				raise PermissionDenied()
			return view_func(self, request, *args, **kwargs)

		return _wrapped

	# Handle decorator with/without arguments
	if func is None:
		return decorator
	return decorator(func)
