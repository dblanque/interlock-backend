################################################################################
#################### INTERLOCK IS LICENSED UNDER GNU AGPLv3 ####################
################## ORIGINAL PROJECT CREATED BY DYLAN BLANQUÉ ###################
########################## AND BR CONSULTING S.R.L. ############################
################################################################################
# Module: core.decorators.login
# Contains Login and Authentication related decorators
from core.models.user import User
from core.exceptions.base import PermissionDenied
from core.views.mixins.auth import RemoveTokenResponse
from functools import wraps

def auth_required(require_admin: bool = True):
	def decorator(view_func):
		@wraps(view_func)
		def _wrapped(request, *args, **kwargs):
			actual_request = request.request
			user: User = actual_request.user
			# Check if user logically deleted or disabled
			if not user.is_authenticated or user.is_anonymous:
				return RemoveTokenResponse(request=request)
			if user.deleted:
				raise PermissionDenied()

			if require_admin is True or require_admin is None:
				if user.is_superuser is False or not user:
					raise PermissionDenied()
			return view_func(request, *args, **kwargs)
		return _wrapped
	return decorator
