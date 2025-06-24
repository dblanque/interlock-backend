################################################################################
#################### INTERLOCK IS LICENSED UNDER GNU AGPLv3 ####################
################## ORIGINAL PROJECT CREATED BY DYLAN BLANQUÉ ###################
########################## AND BR CONSULTING S.R.L. ############################
################################################################################
# Module: core.views.mixins.user.main
# Contains the ViewSet for User related operations

# ---------------------------------- IMPORTS --------------------------------- #
### ViewSets
from rest_framework import viewsets

### Models
from core.models.user import User, USER_TYPE_LOCAL

### Mixins
from core.views.mixins.ldap.user import LDAPUserMixin
from core.views.mixins.user.utils import UserUtilsMixin

### Exceptions
from django.core.exceptions import ObjectDoesNotExist
from core.exceptions import (
	users as exc_user,
	base as exc_base,
	ldap as exc_ldap,
)

### Serializers
from core.serializers.user import UserSerializer

### Constants
from core.constants.attrs.local import (
	LOCAL_ATTR_USERNAME,
	LOCAL_ATTR_EMAIL,
	LOCAL_ATTR_PASSWORD,
)
from core.models.choices.log import (
	LOG_ACTION_UPDATE,
	LOG_CLASS_USER,
)

### Other
import logging
from core.ldap.connector import LDAPConnector
from django.db import transaction
from core.views.mixins.logs import LogMixin
from typing import Any
################################################################################

DBLogMixin = LogMixin()
logger = logging.getLogger(__name__)


class UserMixin(viewsets.ViewSetMixin, UserUtilsMixin):
	serializer_class = UserSerializer

	def local_user_exists(
		self,
		username: str = None,
		email: str = None,
		raise_exception: bool = True,
	) -> bool | exc_user.UserExists:
		args = {}
		if not username and not email:
			raise Exception("username or email required")
		if username:
			args[LOCAL_ATTR_USERNAME] = username
		if email:
			args[LOCAL_ATTR_EMAIL] = email
		user_exists = User.objects.filter(**args).exists()
		if user_exists and raise_exception:
			raise exc_user.UserExists
		return user_exists

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
				raise exc_base.BadRequest(
					data={
						"detail": "Request data 'users' must contain integer PKs."
					}
				)
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

	def bulk_create_from_csv(
		self,
		request_user: User,
		user_rows: list[list[Any]],
		index_map: dict[str],
		placeholder_password: str = None,
	) -> tuple[list[str], list[dict]]:
		"""Create Users from CSV Rows

		Returns:
			tuple: created_users (list[str]), failed_users (list[dict])
		"""
		created_users = []
		failed_users = []
		user_pwd = None
		self.validate_csv_row_length(
			rows=user_rows,
			headers=list(index_map.values()),
		)
		password_in_csv = (
			True if LOCAL_ATTR_PASSWORD in index_map.values() else False
		)

		with transaction.atomic():
			for row_idx, row in enumerate(user_rows):
				# Translate Data
				user_attrs = {}
				for col_idx, value in enumerate(row):
					user_attrs[index_map[col_idx]] = value

				# Pop Credentials
				if placeholder_password:
					user_pwd = placeholder_password
				elif password_in_csv:
					user_pwd = user_attrs.pop(LOCAL_ATTR_PASSWORD)

				# Validate Data
				serializer = self.serializer_class(data=user_attrs)
				if not serializer.is_valid():
					logger.error(serializer.errors)
					failed_users.append(
						{
							LOCAL_ATTR_USERNAME: row_idx
							if LOCAL_ATTR_USERNAME in serializer.errors
							else user_attrs[LOCAL_ATTR_USERNAME],
							"stage": "serializer",
						}
					)
					continue

				# Cleanup Data
				cleaned_data = self.cleanup_empty_str_values(
					serializer.validated_data
				)

				# Create User Instance
				try:
					user_instance = User(**cleaned_data)
					# Set Password if necessary
					if user_pwd:
						user_instance.set_password(user_pwd)
					else:
						user_instance.set_unusable_password()
					user_instance.save()
				except Exception as e:
					logger.exception(e)
					failed_users.append(
						{
							LOCAL_ATTR_USERNAME: user_attrs[
								LOCAL_ATTR_USERNAME
							],
							"stage": "save",
						}
					)
					continue

				created_users.append(user_attrs[LOCAL_ATTR_USERNAME])

				# Log operation
				DBLogMixin.log(
					user=request_user.id,
					operation_type=LOG_ACTION_UPDATE,
					log_target_class=LOG_CLASS_USER,
					log_target=user_instance.username,
				)
		return created_users, failed_users

	def bulk_create_from_dicts(
		self,
		request_user: User,
		user_dicts: list[dict],
		placeholder_password: str = None,
	) -> tuple[list[str], list[dict]]:
		"""Create Users from Dictionaries

		Returns:
			tuple: created_users (list[str]), failed_users (list[dict])
		"""
		created_users = []
		failed_users = []
		user_pwd = None
		user_nr = 0

		with transaction.atomic():
			for user in user_dicts:
				# This is for front-end exception handling if a row
				# has no username
				user_nr += 1

				# Pop Credentials
				if placeholder_password:
					user_pwd = placeholder_password
				else:
					user_pwd = user.pop(LOCAL_ATTR_PASSWORD, None)

				# Validate Data
				serializer: UserSerializer = self.serializer_class(data=user)
				if not serializer.is_valid():
					logger.error(serializer.errors)
					failed_users.append(
						{
							LOCAL_ATTR_USERNAME: user_nr
							if LOCAL_ATTR_USERNAME in serializer.errors
							else user[LOCAL_ATTR_USERNAME],
							"stage": "serializer",
						}
					)
					continue
				cleaned_data = self.cleanup_empty_str_values(
					serializer.validated_data
				)

				# Create User
				try:
					user_instance = User(**cleaned_data)
					# Set Password if necessary
					if user_pwd:
						user_instance.set_password(user_pwd)
					else:
						user_instance.set_unusable_password()
					user_instance.save()
				except Exception as e:
					logger.exception(e)
					failed_users.append(
						{
							LOCAL_ATTR_USERNAME: user[LOCAL_ATTR_USERNAME],
							"stage": "save",
						}
					)
					continue

				created_users.append(user[LOCAL_ATTR_USERNAME])

				# Log operation
				DBLogMixin.log(
					user=request_user.id,
					operation_type=LOG_ACTION_UPDATE,
					log_target_class=LOG_CLASS_USER,
					log_target=user_instance.username,
				)

		return created_users, failed_users


class AllUserMixins(LDAPUserMixin, UserMixin):
	def check_user_exists(
		self,
		username: str = None,
		email: str = None,
		ignore_ldap: bool = False,
		ignore_local: bool = False,
		raise_exception: bool = True,
	):
		"""Checks if a user exists Locally and in LDAP if enabled."""
		exists = False
		self.get_ldap_backend_enabled()

		if self.ldap_backend_enabled and not ignore_ldap:
			# Open LDAP Connection
			with LDAPConnector(force_admin=True) as ldc:
				self.ldap_connection = ldc.connection
				try:
					exists = self.ldap_user_exists(
						username=username,
						email=email,
						return_exception=raise_exception,
					)
				except exc_ldap.LDAPObjectExists:
					raise exc_user.UserExists
		if not ignore_local:
			exists = self.local_user_exists(
				username=username,
				email=email,
				raise_exception=raise_exception,
			)
		return exists

	def bulk_check_users(
		self,
		l: list[tuple[str, str]],
		ignore_ldap: bool = False,
		ignore_local: bool = False,
		raise_exception: bool = True,
	) -> list[str] | exc_user.UserExists:
		"""Checks in bulk if users exist or not.

		Raises:
			exc_user.UserExists: When a user exists and raise_exception is True.
		Returns:
			list[str]: List containing existing usernames.
		"""
		result = []
		for username, email in l:
			if self.check_user_exists(
				username=username,
				email=email,
				ignore_ldap=ignore_ldap,
				ignore_local=ignore_local,
				raise_exception=raise_exception,
			):
				result.append(username)
		return result
