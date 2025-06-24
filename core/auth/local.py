################################################################################
#################### INTERLOCK IS LICENSED UNDER GNU AGPLv3 ####################
################## ORIGINAL PROJECT CREATED BY DYLAN BLANQUÉ ###################
########################## AND BR CONSULTING S.R.L. ############################
################################################################################
# Module: core.auth.local
# Contains E-Mail authentication related operations

# ---------------------------------- IMPORTS --------------------------------- #
from django.contrib.auth.backends import ModelBackend
from django.contrib.auth import get_user_model
################################################################################


class EmailAuthBackend(ModelBackend):
	"""
	Authenticate Local DB user using an e-mail address.
	"""

	supports_inactive_user = False

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
