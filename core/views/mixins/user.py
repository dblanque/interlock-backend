################################################################################
#################### INTERLOCK IS LICENSED UNDER GNU AGPLv3 ####################
################## ORIGINAL PROJECT CREATED BY DYLAN BLANQUÉ ###################
########################## AND BR CONSULTING S.R.L. ############################
################################################################################
# Module: core.views.mixins.user
# Contains the ViewSet for User related operations

# ---------------------------------- IMPORTS --------------------------------- #
### ViewSets
from rest_framework import viewsets

### Models
from core.models.user import User, USER_TYPE_LOCAL

### Exceptions
from django.core.exceptions import ObjectDoesNotExist
from core.exceptions import (
	users as exc_user,
	base as exc_base,
)

### Other
import logging
from core.views.mixins.logs import LogMixin
################################################################################

DBLogMixin = LogMixin()
logger = logging.getLogger(__name__)

class UserMixin(viewsets.ViewSetMixin):

	def validated_user_pk_list(self, data: dict) -> list[int]:
		"""
		Validates that request data 'users' Primary Key List is composed of
		integers.
		"""
		users: list[int] = data.pop("users", [])
		if not users or not isinstance(users, list):
			raise exc_base.BadRequest(
				data={"detail": "Request data 'users' must be of type list."}
			)
		for pk in users:
			try:
				int(pk)
			except:
				raise exc_base.BadRequest(data={
					"detail": "Request data 'users' must contain integer PKs."
				})
		return users

	def user_change_status(
		self,
		user_pk: int,
		target_status: bool,
		raise_exception: bool = True,
	) -> User | None:
		"""Changes a Local User's Status (Enabled/Disabled).
		Performs User Type check before applying changes.

		Args:
			user_pk (int): Users' Primary Key.
			target_status (bool): The status to set.
			raise_exception (bool): To raise or not to raise,
				that is the question.

		Raises:
			UserDoesNotExist: When raise_exception is True.		
			UserNotLocalType: When user type is not local.

		Returns:
			User: The target user's username
		"""
		try:
			user_instance: User = User.objects.get(id=user_pk)
		except ObjectDoesNotExist:
			if raise_exception:
				raise exc_user.UserDoesNotExist
			else:
				return None

		if raise_exception:
			if user_instance.user_type != USER_TYPE_LOCAL:
				raise exc_user.UserNotLocalType
		user_instance.is_enabled = target_status
		user_instance.save()

		return user_instance
