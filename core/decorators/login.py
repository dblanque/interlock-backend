################################################################################
#################### INTERLOCK IS LICENSED UNDER GNU AGPLv3 ####################
################## ORIGINAL PROJECT CREATED BY DYLAN BLANQUÉ ###################
########################## AND BR CONSULTING S.R.L. ############################
################################################################################
# Module: core.decorators.login
# Contains Login and Authentication related decorators

from django.core.exceptions import PermissionDenied
from functools import wraps

def auth_required(require_admin: bool = True):
	def decorator(view_func):
		@wraps(view_func)
		def _wrapped(request, *args, **kwargs):
			actual_request = request.request
			user = actual_request.user
			# Check if user logically deleted or disabled
			if user.deleted == True: raise PermissionDenied

			# Check user is_staff for any user that is not local default admin
			if require_admin == True or require_admin is None:
				if user.username != 'admin' and (user.is_superuser == False or not user):
					raise PermissionDenied()
			elif user.is_staff != True:
				raise PermissionDenied()
			return view_func(request, *args, **kwargs)
		return _wrapped
	return decorator
