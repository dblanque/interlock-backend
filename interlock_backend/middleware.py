from core.models.user import User
from core.exceptions.base import PermissionDenied


def AccountStatusMiddleware(get_response):
	def middleware(request):
		response = get_response(request)
		if hasattr(request, "user"):
			user: User = request.user
			if hasattr(user, "is_enabled"):
				if not user.is_enabled:
					return PermissionDenied()
		return response

	return middleware
