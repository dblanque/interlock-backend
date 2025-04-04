from django.contrib.auth import get_user_model


class EmailAuthBackend(object):
	"""
	Authenticate Local DB user using an e-mail address.
	"""

	def authenticate(self, request, username=None, password=None):
		User = get_user_model()
		try:
			user = User.objects.get(email=username)
			if user.check_password(password):
				return user
			return None
		except User.DoesNotExist:
			return None

	def get_user(self, user_id):
		User = get_user_model()
		try:
			return User.objects.get(pk=user_id)
		except User.DoesNotExist:
			return None
