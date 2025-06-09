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

# Serializers
from core.serializers.user import UserSerializer

### Constants
from core.constants.attrs.local import LOCAL_ATTR_USERNAME
from core.models.choices.log import (
	LOG_ACTION_UPDATE,
	LOG_CLASS_USER,
)

### Other

import logging
from django.db import transaction
from core.views.mixins.logs import LogMixin
################################################################################

DBLogMixin = LogMixin()
logger = logging.getLogger(__name__)

class UserMixin(viewsets.ViewSetMixin):
	serializer_class = UserSerializer

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

	def bulk_create_from_csv(self, request_user: User, data: dict) -> int:
		"""Create Users from CSV Rows
		
		Returns:
			tuple: created_users (int), error_users (int)
		"""
		created_users = 0
		error_users = 0

		headers = data.pop("headers", None)
		user_rows = data.pop("users", None)
		csv_map = data.pop("mapping", None)
		index_map = {}

		for required_key in (headers, csv_map,):
			if not required_key:
				raise exc_base.BadRequest(data={
					"detail": f"Key {required_key} is required in request data."
				})

		# Map Header Column Indexes
		if csv_map:
			for local_alias, csv_alias in csv_map:
				index_map[headers.index(csv_alias)] = local_alias
		else:
			index_map = {
				idx: local_alias
				for idx, local_alias in enumerate(headers)
			}

		with transaction.atomic():
			for row in user_rows:
				# Exists Check
				exists = User.objects\
					.filter(username=index_map[LOCAL_ATTR_USERNAME])\
					.exists()
				if exists:
					error_users += 1
					continue

				# Validate Data
				user_attrs = {}
				for idx, value in enumerate(row):
					user_attrs[index_map[idx]] = value
				serializer = self.serializer_class(data=user_attrs)
				try:
					serializer.is_valid(raise_exception=True)
				except:
					error_users += 1
					continue
				validated_data = serializer.validated_data

				# Create User Instance
				try:
					user_instance = User(**validated_data)
					user_instance.save()
				except:
					error_users += 1
					continue

				created_users += 1

				# Log operation
				DBLogMixin.log(
					user=request_user.id,
					operation_type=LOG_ACTION_UPDATE,
					log_target_class=LOG_CLASS_USER,
					log_target=user_instance.username,
				)
		return created_users, error_users
	
	def bulk_create_from_dicts(self, request_user: User, data: dict):
		"""Create Users from Dictionaries
		
		Returns:
			tuple: created_users (int), error_users (int)
		"""
		created_users = 0
		error_users = 0

		user_dicts = data.pop("dict_users", None)
		with transaction.atomic():
			for user in user_dicts:
				# Validate Data
				try:
					serializer = self.serializer_class(data=user)
					serializer.is_valid(raise_exception=True)
				except:
					error_users += 1
					continue
				validated_data = serializer.validated_data

				# Create User
				try:
					user_instance = User(**validated_data)
					user_instance.save()
				except:
					error_users += 1
					continue

				created_users += 1

				# Log operation
				DBLogMixin.log(
					user=request_user.id,
					operation_type=LOG_ACTION_UPDATE,
					log_target_class=LOG_CLASS_USER,
					log_target=user_instance.username,
				)

		return created_users, error_users
