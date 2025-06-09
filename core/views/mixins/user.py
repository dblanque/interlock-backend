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
from core.models.interlock_settings import (
	InterlockSetting,
	INTERLOCK_SETTING_ENABLE_LDAP,
)

### Mixins
from core.views.mixins.ldap.user import LDAPUserMixin

### Exceptions
from django.core.exceptions import ObjectDoesNotExist
from core.exceptions import (
	users as exc_user,
	base as exc_base,
)

### Serializers
from core.serializers.user import UserSerializer

### Constants
from core.constants.attrs.local import LOCAL_ATTR_USERNAME, LOCAL_ATTR_EMAIL
from core.constants.attrs import local as local_attrs
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

class UserMixin(viewsets.ViewSetMixin):
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

	def map_bulk_create_attrs(
		self,
		headers: list[str],
		csv_map: dict[str] = None,
	):
		"""Map headers to local attributes
		
		Returns:
			dict: Mapped attribute keys { index: local_attr }
		"""
		index_map = {}

		if not headers:
			raise exc_base.BadRequest(data={
				"detail": f"Key 'headers' is required in request data."
			})
		if csv_map and not isinstance(csv_map, dict):
			raise exc_base.BadRequest(data={
				"detail": f"Key 'csv_map' must be of type dict"
			})

		# Map Header Column Indexes
		if csv_map:
			for local_alias, csv_alias in csv_map.items():
				index_map[headers.index(csv_alias)] = local_alias
		else:
			index_map = {
				idx: local_alias
				for idx, local_alias in enumerate(headers)
			}

		_local_attrs = {
			k: getattr(local_attrs, k)
			for k in dir(local_attrs)
			if k.startswith("LOCAL_")
		}
		# Validate Headers / Mappings
		for unvalidated_local_alias in index_map.values():
			if (not isinstance(unvalidated_local_alias, str) or
	   			not unvalidated_local_alias in _local_attrs.values()
			):
				raise exc_base.BadRequest(data={
					"detail":	"All headers and/or header mappings must be"\
								" of type str and existing local attributes."
				})

		return index_map

	def cleanup_empty_str_values(self, d: dict) -> dict:
		_new_d = d.copy()
		delete_keys = []
		for k, v in d.items():
			if isinstance(v, str) and not v:
				delete_keys.append(k)
		for k in delete_keys:
			del _new_d[k]
		return _new_d

	def bulk_create_from_csv(
		self,
		request_user: User,
		user_rows: list[list[Any]],
		index_map: dict[str],
	) -> int:
		"""Create Users from CSV Rows
		
		Returns:
			tuple: created_users (int), error_users (int)
		"""
		created_users = 0
		error_users = 0
		for idx, row in enumerate(user_rows):
			if not len(row) == len(index_map):
				raise exc_user.UserBulkInsertLengthError(data={
					"detail": f"Row number {idx} column count error."
				})

		with transaction.atomic():
			for row in user_rows:
				# Validate Data
				user_attrs = {}
				for col_idx, value in enumerate(row):
					user_attrs[index_map[col_idx]] = value
				serializer = self.serializer_class(data=user_attrs)
				try:
					serializer.is_valid(raise_exception=True)
				except Exception as e:
					logger.exception(e)
					error_users += 1
					continue
				cleaned_data = self.cleanup_empty_str_values(
					serializer.validated_data
				)

				# Create User Instance
				try:
					user_instance = User(**cleaned_data)
					user_instance.set_unusable_password()
					user_instance.save()
				except Exception as e:
					logger.exception(e)
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
	
	def bulk_create_from_dicts(
		self,
		request_user: User,
		user_dicts: list[dict],
	):
		"""Create Users from Dictionaries
		
		Returns:
			tuple: created_users (int), error_users (int)
		"""
		created_users = 0
		error_users = 0

		with transaction.atomic():
			for user in user_dicts:
				# Validate Data
				try:
					serializer = self.serializer_class(data=user)
					serializer.is_valid(raise_exception=True)
				except Exception as e:
					logger.exception(e)
					error_users += 1
					continue
				cleaned_data = self.cleanup_empty_str_values(
					serializer.validated_data
				)

				# Create User
				try:
					user_instance = User(**cleaned_data)
					user_instance.set_unusable_password()
					user_instance.save()
				except Exception as e:
					logger.exception(e)
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

class AllUserMixins(LDAPUserMixin, UserMixin):
	ldap_backend_enabled = False

	def get_ldap_backend_enabled(self):
		"""Gets current LDAP Backend Enabled Setting"""
		try:
			self.ldap_backend_enabled = InterlockSetting.objects.get(
				name=INTERLOCK_SETTING_ENABLE_LDAP
			).value
		except ObjectDoesNotExist:
			self.ldap_backend_enabled = False

	def check_user_exists(self, username: str = None, email: str = None):
		"""Checks if a user exists Locally and in LDAP if enabled."""
		self.get_ldap_backend_enabled()

		if self.ldap_backend_enabled:
			# Open LDAP Connection
			with LDAPConnector(force_admin=True) as ldc:
				self.ldap_connection = ldc.connection
				self.ldap_user_exists(username=username, email=email)
		self.local_user_exists(username=username, email=email)

	def bulk_check_users(
		self,
		l: list[tuple[str, str]],
		raise_exception=True
	) -> bool | exc_user.UserExists:
		result = False
		for username, email in l:
			if self.check_user_exists(
				username=username,
				email=email,
				raise_exception=raise_exception
			):
				result = True
		return result