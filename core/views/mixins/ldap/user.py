################################################################################
#################### INTERLOCK IS LICENSED UNDER GNU AGPLv3 ####################
################## ORIGINAL PROJECT CREATED BY DYLAN BLANQUÉ ###################
########################## AND BR CONSULTING S.R.L. ############################
################################################################################
# Module: core.views.mixins.ldap.user
# Contains the Mixin for User related operations

# ---------------------------------- IMPORTS --------------------------------- #
### ViewSets
from rest_framework import viewsets
from rest_framework.request import Request
from django.core.exceptions import ObjectDoesNotExist

### Interlock
from core.ldap.adsi import join_ldap_filter
from core.config.runtime import RuntimeSettings
from core.serializers.user import LDAPUserSerializer
from core.ldap import adsi as ldap_adsi
from core.ldap.types.account import LDAPAccountTypes

### Models
from core.models.user import User, USER_TYPE_LDAP
from core.models.ldap_group import LDAPGroup
from core.models.ldap_user import LDAPUser
from core.models.choices.log import (
	LOG_CLASS_USER,
	LOG_ACTION_CREATE,
	LOG_ACTION_READ,
	LOG_ACTION_UPDATE,
	LOG_ACTION_DELETE,
	LOG_EXTRA_UNLOCK,
	LOG_EXTRA_ENABLE,
	LOG_EXTRA_DISABLE,
	LOG_TARGET_ALL,
)
from core.ldap.connector import LDAPConnector
from core.views.mixins.logs import LogMixin
from ldap3 import (
	Connection,
	MODIFY_REPLACE,
	Entry as LDAPEntry,
)
from ldap3.extend import (
	ExtendedOperationsRoot,
	StandardExtendedOperations,
	MicrosoftExtendedOperations,
)

### Serializers
from core.serializers.user import UserSerializer
from rest_framework.serializers import ValidationError

### Mixins
from core.views.mixins.ldap.group import GroupViewMixin
from core.views.mixins.user.utils import UserUtilsMixin

### Exception Handling
from core.exceptions import (
	base as exc_base,
	users as exc_user,
	ldap as exc_ldap,
)
import logging

### Constants
from core.constants.attrs import *
from core.constants.user import (
	BUILTIN_USERS,
	BUILTIN_ADMIN,
	LDAPUserSearchAttrBuilder,
)

### Utils
from core.utils.main import getldapattrvalue
from ldap3.utils.dn import safe_dn
from core.utils.filetime import to_datetime
from django.utils import timezone as tz

### Others
from ldap3.core.exceptions import LDAPException
from typing import Any, TypedDict
from django.db import transaction
from core.type_hints.connector import LDAPConnectionProtocol
from core.ldap.filter import LDAPFilter, LDAPFilterType
from datetime import datetime
import re
################################################################################

DBLogMixin = LogMixin()
logger = logging.getLogger(__name__)


class LdapListResult(TypedDict):
	headers: list[str]
	users: list[dict[Any]]


class LDAPUserMixin(viewsets.ViewSetMixin, UserUtilsMixin):
	"""LDAP User Mixin

	Methods in this mixin may be used in the local django users viewset, so
	beware not to have any overlap with its' mixin (if any exists).
	"""

	serializer_class = LDAPUserSerializer
	ldap_connection: LDAPConnectionProtocol = None
	# LDAP Search Filter
	search_filter = None
	# LDAP Search Attributes
	search_attrs = None
	filter_attr_builder = LDAPUserSearchAttrBuilder
	request: Request

	@staticmethod
	def is_built_in_user(
		username: str = None,
		security_id: str = None,
		ignore_admin: bool = False,
	) -> bool:
		if username or security_id:
			for well_known_username, well_known_rid in BUILTIN_USERS:
				is_admin = (
					well_known_username,
					well_known_rid,
				) == BUILTIN_ADMIN
				if ignore_admin and is_admin:
					continue
				# Check SID First, as it's more specific
				if security_id:
					_sid_re = re.compile(rf"^S-1-5-.*-{str(well_known_rid)}$")
					if _sid_re.match(security_id):
						return True
				# Check username
				if username:
					if username.lower() == well_known_username.lower():
						return True
		return False

	def get_user_object_filter(
		self,
		username: str = None,
		email: str = None,
		xor=True,
		match_both=False,
	):
		"""Gets LDAP User Object Filter

		Args:
			username (str, optional): Username. Defaults to None.
			email (str, optional): User Email. Defaults to None.
			xor (bool, optional): Use XOR, disallows searching by username and email at
				the same time. Defaults to True.
			match_both (bool, optional): Whether to match username and email in search
				filter (Uses LDAP_FILTER_AND instead of LDAP_FILTER_OR)

		Raises:
			ValueError: Raised if XOR is True and both username and email
				are Truthy or Falsy at the same time.

		Returns:
			str: LDAP Object Filter String
		"""
		if xor:
			if (not username and not email) or (username and email):
				raise ValueError(
					"xor: Username OR Email required, single value allowed."
				)
			if match_both:
				raise ValueError("match_both and xor are incompatible options.")

		if match_both:
			id_filter_op = ldap_adsi.LDAP_FILTER_AND
		else:
			id_filter_op = ldap_adsi.LDAP_FILTER_OR

		# Class Filter Setup
		_OBJECT_CLASS_FIELD = RuntimeSettings.LDAP_FIELD_MAP[
			LOCAL_ATTR_OBJECT_CLASS
		]
		class_filter = join_ldap_filter(
			None,
			f"{_OBJECT_CLASS_FIELD}={RuntimeSettings.LDAP_AUTH_OBJECT_CLASS}",
		)
		# Exclude Computer Accounts if settings allow it
		if RuntimeSettings.EXCLUDE_COMPUTER_ACCOUNTS:
			class_filter = join_ldap_filter(
				class_filter,
				f"{_OBJECT_CLASS_FIELD}=computer",
				negate_add=True,
			)

		# User ID Filter Setup
		id_filter = None
		if username:
			_USERNAME_FIELD = RuntimeSettings.LDAP_FIELD_MAP[
				LOCAL_ATTR_USERNAME
			]
			id_filter = join_ldap_filter(
				id_filter,
				f"{_USERNAME_FIELD}={username}",
				expression=id_filter_op,
			)
		if email:
			_EMAIL_FIELD = RuntimeSettings.LDAP_FIELD_MAP[LOCAL_ATTR_EMAIL]
			id_filter = join_ldap_filter(
				id_filter,
				f"{_EMAIL_FIELD}={email}",
				expression=id_filter_op,
			)
		return join_ldap_filter(class_filter, id_filter)

	def get_user_entry(
		self, username=None, email=None, raise_if_not_exists=False
	):
		"""Fetch user entry from current ldap connection entries,
		does not perform an LDAP Search.

		Args:
			username (str, optional): User username. Defaults to None.
			email (str, optional): User Email. Defaults to None.

		Raises:
			ValueError: Raised when both username and email are falsy.

		Returns:
			ldap3.Entry: User Entry
		"""
		if not username and not email:
			raise ValueError(
				"username or email must be specified in get_user_entry call."
			)
		if not self.ldap_connection.entries:
			if raise_if_not_exists:
				raise exc_user.UserEntryNotFound
			else:
				return

		_username_field = RuntimeSettings.LDAP_FIELD_MAP[LOCAL_ATTR_USERNAME]
		_email_field = RuntimeSettings.LDAP_FIELD_MAP[LOCAL_ATTR_EMAIL]
		for entry in self.ldap_connection.entries:
			entry: LDAPEntry
			if username and email:
				if (
					getldapattrvalue(entry, _username_field) == username
					and getldapattrvalue(entry, _email_field) == email
				):
					return entry
			elif username:
				if getldapattrvalue(entry, _username_field) == username:
					return entry
			elif email:
				if getldapattrvalue(entry, _email_field) == email:
					return entry

		if raise_if_not_exists:
			raise exc_user.UserEntryNotFound
		return

	def get_user_object(
		self,
		username: str = None,
		email: str = None,
		attributes: list = None,
		object_class_filter=None,
	):
		"""Default: Do an LDAP Search for the requested object using username, email,
			or both.

		Args:
			username (str, optional): Required if no email is provided. Defaults to None.
			email (str, optional): Required if no username is provided. Defaults to None.
			attributes (list, optional): LDAP Attributes. Defaults to None.
				If None, minimal attributes will be fetched (username field and distinguished name)
			object_class_filter (str, optional): LDAP Search Filter. Defaults to None.

		Raises:
			ValidationError: If username and email are Falsy.

		Returns the matching user entry.
		"""
		if not username and not email:
			raise ValidationError(
				"username or email are required for get_user_object call."
			)

		if not attributes:
			attributes = [
				RuntimeSettings.LDAP_FIELD_MAP[LOCAL_ATTR_USERNAME],
				RuntimeSettings.LDAP_FIELD_MAP[LOCAL_ATTR_DN],
			]
		if not object_class_filter:
			object_class_filter = self.get_user_object_filter(
				username=username, email=email, xor=False
			)

		self.ldap_connection.search(
			search_base=RuntimeSettings.LDAP_AUTH_SEARCH_BASE,
			search_filter=object_class_filter,
			attributes=attributes,
		)
		return self.get_user_entry(username=username, email=email)

	def _get_all_ldap_users(
		self, as_entries=False
	) -> list[dict] | list[LDAPEntry]:
		"""Function to fetch all LDAP Users.

		Returns list of dictionaries.

		Returns list of ldap3.Entry objects if as_entries is True.
		"""
		user_list = []
		if not self.search_filter:
			self.search_filter = LDAPFilter.eq(
				RuntimeSettings.LDAP_FIELD_MAP[LOCAL_ATTR_OBJECT_CLASS],
				RuntimeSettings.LDAP_AUTH_OBJECT_CLASS,
			)
		if not self.search_attrs:
			self.search_attrs = self.filter_attr_builder(
				RuntimeSettings
			).get_list_attrs()

		if isinstance(self.search_filter, str):
			self.search_filter = LDAPFilter.from_string(self.search_filter)

		# Exclude Computer Accounts if settings allow it
		if RuntimeSettings.EXCLUDE_COMPUTER_ACCOUNTS:
			self.search_filter = LDAPFilter.and_(
				self.search_filter,
				LDAPFilter.not_(
					LDAPFilter.eq(
						RuntimeSettings.LDAP_FIELD_MAP[LOCAL_ATTR_OBJECT_CLASS],
						"computer",
					)
				),
			)

		# Exclude Contacts
		filter_contacts = LDAPFilter.not_(
			LDAPFilter.eq(
				RuntimeSettings.LDAP_FIELD_MAP[LOCAL_ATTR_OBJECT_CLASS],
				"contact",
			)
		)
		if self.search_filter.type == LDAPFilterType.AND:
			self.search_filter.children.append(filter_contacts)
		else:
			self.search_filter = LDAPFilter.and_(
				self.search_filter,
				filter_contacts,
			)

		# Perform search
		self.ldap_connection.search(
			search_base=RuntimeSettings.LDAP_AUTH_SEARCH_BASE,
			search_filter=self.search_filter.to_string(),
			attributes=self.search_attrs,
		)
		user_entry_list: list[LDAPEntry] = self.ldap_connection.entries
		if as_entries:
			return user_entry_list.copy()

		# Parse user attrs into dictionaries
		for user_entry in user_entry_list:
			user_object = LDAPUser(entry=user_entry)
			user_dict = user_object.attributes.copy()
			user_dict.pop(LOCAL_ATTR_UAC, None)

			# Check if user is disabled
			try:
				user_dict[LOCAL_ATTR_IS_ENABLED] = user_object.is_enabled
			except Exception as e:
				username_or_dn = user_dict.get(
					RuntimeSettings.LDAP_FIELD_MAP[LOCAL_ATTR_DN],
					user_dict.get(
						RuntimeSettings.LDAP_FIELD_MAP[LOCAL_ATTR_USERNAME],
						"",  # Default
					),
				)
				logger.exception(e)
				logger.error(
					f"Could not get user status for user {username_or_dn}"
				)
				pass
			user_list.append(user_dict)
		return user_list

	def ldap_user_list(self) -> LdapListResult:
		"""List LDAP Users

		Returns:
			LdapListResult: Dictionary containing headers and users.
		"""
		user_list = self._get_all_ldap_users()

		DBLogMixin.log(
			user=self.request.user.id,
			operation_type=LOG_ACTION_READ,
			log_target_class=LOG_CLASS_USER,
			log_target=LOG_TARGET_ALL,
		)

		result = {}
		result["users"] = user_list
		result["headers"] = (
			LOCAL_ATTR_USERNAME,
			LOCAL_ATTR_FIRST_NAME,
			LOCAL_ATTR_LAST_NAME,
			LOCAL_ATTR_EMAIL,
			LOCAL_ATTR_IS_ENABLED,
		)
		return result

	def ldap_user_insert(
		self,
		data: dict,
		exclude_keys: list = None,
		return_exception: bool = True,
	) -> str:
		"""
		Returns User LDAP Distinguished Name on successful insert.
		"""
		if exclude_keys:
			for key in exclude_keys:
				if key in data:
					del data[key]

		# ADDS requires password and status change to be separated from creation
		set_pwd = False
		user_pwd = data.pop(LOCAL_ATTR_PASSWORD, None)
		if user_pwd:
			set_pwd = True

		# ADDS Requires permission changes to be separate from creation
		user_perms = data.pop(LOCAL_ATTR_PERMISSIONS, [])
		# Normalize and de-duplicate to set
		user_perms = set(user_perms)
		user_should_be_enabled = (
			ldap_adsi.LDAP_UF_ACCOUNT_DISABLE not in user_perms
		)
		user_perms.add(ldap_adsi.LDAP_UF_NORMAL_ACCOUNT)
		data[LOCAL_ATTR_PERMISSIONS] = {}

		username: str = data.get(LOCAL_ATTR_USERNAME).lower()
		try:
			user_path: str = data.pop(LOCAL_ATTR_PATH, None)
			if user_path:
				user_dn = f"CN={username},{user_path}"
			else:
				user_dn = f"CN={username},CN=Users,{RuntimeSettings.LDAP_AUTH_SEARCH_BASE}"
			user_dn = safe_dn(dn=user_dn)
		except:
			raise exc_user.UserDNPathException

		logger.debug(f"Creating user in DN Path: {user_dn}")
		try:
			user_obj = LDAPUser(
				connection=self.ldap_connection,
				distinguished_name=user_dn,
				attributes=data,
			)
			# Set Account to Disabled on create (ADDS Requirement). =_=
			user_perms.add(ldap_adsi.LDAP_UF_ACCOUNT_DISABLE)
			user_obj.attributes[LOCAL_ATTR_PERMISSIONS] = user_perms

			# Save User
			user_obj.save()

			# ADDS requires password and status change to be POST-CREATE.
			# Garbage, I know.
			if set_pwd:
				# Set Password
				try:
					self.ldap_set_password(
						user_dn=user_dn,
						user_pwd_new=user_pwd,
						set_by_admin=True,
					)
				except Exception as e:
					logger.error(e)
					pass
				# Change Status
				self.ldap_user_change_status(
					username=username,
					enabled=True,
				)
			# ADDS also requires permission changes to be POST-CREATE.
			# UNLIKE SAMBA LDAP, garbage, I know!
			if user_perms:
				if (
					ldap_adsi.LDAP_UF_ACCOUNT_DISABLE in user_perms
					and user_should_be_enabled
					and set_pwd
				):
					user_perms.remove(ldap_adsi.LDAP_UF_ACCOUNT_DISABLE)
				self.ldap_user_update(
					data={
						LOCAL_ATTR_USERNAME: username,
						LOCAL_ATTR_DN: user_dn,
						LOCAL_ATTR_PERMISSIONS: user_perms,
					}
				)
		except LDAPException as e:
			logger.error(e)
			logger.error(f"Could not create User: {user_dn}")
			if return_exception:
				raise exc_user.UserCreate(
					data={"ldap_response": self.ldap_connection.result}
				)
			return None
		except Exception as e:
			logger.exception(e)
			raise exc_base.InternalServerError(data={"detail": str(e)})

		DBLogMixin.log(
			user=self.request.user.id,
			operation_type=LOG_ACTION_CREATE,
			log_target_class=LOG_CLASS_USER,
			log_target=username,
		)

		return user_dn

	def ldap_user_update(self, data: dict) -> LDAPConnector:
		"""Updates LDAP User with user data.
		Does not validate (See LDAPUserSerializer).

		Returns:
			ldap3.Connection
		"""
		username = data.get(LOCAL_ATTR_USERNAME)
		user_obj = LDAPUser(connection=self.ldap_connection, username=username)
		user_obj.attributes = data
		user_obj.save()

		DBLogMixin.log(
			user=self.request.user.id,
			operation_type=LOG_ACTION_UPDATE,
			log_target_class=LOG_CLASS_USER,
			log_target=username,
		)

		try:
			django_user: User = User.objects.get(username=username)
		except ObjectDoesNotExist:
			django_user = None
			pass

		if django_user:
			for _key in data.keys():
				if _key in (LOCAL_ATTR_USER_GROUPS,):
					continue

				if _key in data:
					setattr(django_user, _key, data[_key])
			django_user.save()
		return self.ldap_connection

	def ldap_set_password(
		self,
		user_dn: str,
		user_pwd_new: str,
		user_pwd_old: str = None,
		set_by_admin=False,
	) -> LDAPConnector:
		"""Sets the LDAP User's Password with Microsoft Extended LDAP Commands
		- Microsoft ADDS does not allow password changing without LDAPS

		Args:
			user_dn (str): User's Distinguished Name, required.
			user_pwd_new (str): User's new password, required.
			user_pwd_old (str): User's old password, required if not set_by_admin.
			set_by_admin (bool): Whether the password is being set by an administrator.
				Defaults to False.

		Returns:
			ldap3.Connection
		"""
		# Type hinting defs
		extended_operations: ExtendedOperationsRoot = (
			self.ldap_connection.extend
		)
		eo_standard: StandardExtendedOperations = extended_operations.standard
		eo_microsoft: MicrosoftExtendedOperations = (
			extended_operations.microsoft
		)

		if not isinstance(user_dn, str):
			raise TypeError("user_dn must be of type str.")

		if not isinstance(user_pwd_new, str):
			raise TypeError("user_pwd_new must be of type str.")

		if not set_by_admin and not isinstance(user_pwd_old, str):
			raise TypeError("user_pwd_old must be of type str.")

		# Validation
		if not user_pwd_new:
			raise ValueError("user_pwd_new cannot be empty.")
		if not set_by_admin and not user_pwd_old:
			raise exc_user.UserOldPasswordRequired()

		# Set kwargs
		pwd_kwargs = {"new_password": user_pwd_new}
		if user_pwd_old:
			pwd_kwargs["old_password"] = user_pwd_old

		try:
			# If available use standard password extended operation
			if (
				"1.3.6.1.4.1.4203.1.11.1"
				in self.ldap_connection.server.info.supported_extensions
			):
				return eo_standard.modify_password(user=user_dn, **pwd_kwargs)
			else:
				# Otherwise attempt to change password directly with
				# Microsoft Extended Operations
				return eo_microsoft.modify_password(user=user_dn, **pwd_kwargs)
		except Exception as e:
			logger.exception(e)
			logger.error(f"Could not update password for User DN: {user_dn}")
			if hasattr(self.ldap_connection, "result"):
				try:
					_message = self.ldap_connection.result.get("message", "")
					# If unwillingToPerform Password over Plain LDAP (ADDS)
					if "0000052D" in _message:
						raise exc_user.UserPasswordOverPlainLDAP
				except:
					pass
				raise exc_user.UserUpdateError(
					data={"ldap_response": self.ldap_connection.result}
				)

	def ldap_user_exists(
		self,
		username: str = None,
		email: str = None,
		return_exception: bool = True,
	) -> bool:
		"""Checks if LDAP User Exists on Directory

		Args:
			username (str, optional): Required if no email is provided. Defaults to None.
			email (str, optional): Required if no username is provided. Defaults to None.
			return_exception (bool, optional): Whether to return exception when a user
				entry is found. Defaults to True.

		Raises:
			ValidationError: Returned if no email and username are provided.
			exc_ldap.LDAPObjectExists: Returned if return_exception is True
				and user exists.

		Returns:
			bool
		"""

		# Send LDAP Query for user being created to see if it exists
		if not username and not email:
			raise ValidationError(
				"username or email args are required for ldap_user_exists call."
			)
		ldap_attributes = [
			RuntimeSettings.LDAP_FIELD_MAP[LOCAL_ATTR_USERNAME],
			RuntimeSettings.LDAP_FIELD_MAP[LOCAL_ATTR_DN],
			RuntimeSettings.LDAP_FIELD_MAP[LOCAL_ATTR_EMAIL],
		]
		self.get_user_object(
			username=username, email=email, attributes=ldap_attributes
		)
		entry_by_username = (
			self.get_user_entry(username=username) if username else None
		)
		entry_by_email = self.get_user_entry(email=email) if email else None

		# If entries is not falsy, return Exception or True
		if self.ldap_connection.entries:
			if entry_by_email or entry_by_username:
				if return_exception:
					if entry_by_email:
						_code = "user_ldap_email_exists"
					elif entry_by_username:
						_code = "user_ldap_exists"
					raise exc_ldap.LDAPObjectExists(data={"code": _code})
				else:
					return True
		return False

	def ldap_user_fetch(
		self, user_search, return_entry=False, log_operation: bool = True
	) -> dict:
		"""Returns Serialized LDAP User attributes or Entry."""
		self.search_filter = self.get_user_object_filter(username=user_search)
		if not self.search_attrs:
			self.search_attrs = self.filter_attr_builder(
				RuntimeSettings
			).get_fetch_attrs()

		user_obj = LDAPUser(
			connection=self.ldap_connection, username=user_search
		)
		if return_entry:
			return user_obj.entry

		user_dict = user_obj.attributes

		if log_operation:
			DBLogMixin.log(
				user=self.request.user.id,
				operation_type=LOG_ACTION_READ,
				log_target_class=LOG_CLASS_USER,
				log_target=user_search,
			)

		# Expand Groups from DN to Objects
		member_of_objects: list[dict] = []
		user_dict[LOCAL_ATTR_USER_GROUPS] = []
		try:
			_USER_GROUPS_FIELD = RuntimeSettings.LDAP_FIELD_MAP[
				LOCAL_ATTR_USER_GROUPS
			]
			if _USER_GROUPS_FIELD in user_obj.entry.entry_attributes:
				user_groups = getldapattrvalue(
					user_obj.entry, _USER_GROUPS_FIELD
				)
				if user_groups:
					if isinstance(user_groups, (list, tuple, set)):
						for _group_dn in user_groups:
							member_of_objects.append(
								LDAPGroup(
									connection=self.ldap_connection,
									distinguished_name=_group_dn,
								).attributes
							)
					else:
						member_of_objects.append(
							LDAPGroup(
								connection=self.ldap_connection,
								distinguished_name=user_groups,
							).attributes
						)

			### Also add default Users Group to be available as Selectable PID
			_PRIMARY_GROUP_ID_FIELD = RuntimeSettings.LDAP_FIELD_MAP[
				LOCAL_ATTR_PRIMARY_GROUP_ID
			]
			if _PRIMARY_GROUP_ID_FIELD in self.search_attrs:
				_primary_group_id = user_dict[LOCAL_ATTR_PRIMARY_GROUP_ID]
				if not any(
					_g.get(LOCAL_ATTR_RELATIVE_ID, None) == _primary_group_id
					for _g in member_of_objects
				):
					primary_group = GroupViewMixin.get_group_by_rid(
						_primary_group_id
					)
					member_of_objects.append(primary_group)

			if member_of_objects:
				user_dict[LOCAL_ATTR_USER_GROUPS] = member_of_objects
		except Exception as e:
			logger.exception(e)
			raise exc_user.UserGroupsFetchError

		if LOCAL_ATTR_UAC in user_dict.keys():
			# Check if user is disabled
			try:
				user_dict[LOCAL_ATTR_IS_ENABLED] = user_obj.is_enabled
				user_dict[LOCAL_ATTR_CAN_CHANGE_PWD] = (
					user_obj.can_change_password
				)
			except Exception as e:
				logger.exception(e)

			# Build permissions list
			try:
				user_permissions = ldap_adsi.list_user_perms(
					user=user_obj.entry
				)
				user_dict[LOCAL_ATTR_PERMISSIONS] = user_permissions
			except Exception as e:
				logger.exception(e)

		if LOCAL_ATTR_ACCOUNT_TYPE in user_dict:
			# Replace sAMAccountType Value with String
			user_account_type = int(user_dict[LOCAL_ATTR_ACCOUNT_TYPE])
			user_dict[LOCAL_ATTR_ACCOUNT_TYPE] = LDAPAccountTypes(
				user_account_type
			).name

		# Validate data
		serializer = LDAPUserSerializer(data=user_dict)
		serializer.is_valid(raise_exception=True)

		# Parse dates to LDAP Format (Front-end requirement)
		_result = serializer.validated_data.copy()
		for fld in [
			LOCAL_ATTR_CREATED,
			LOCAL_ATTR_MODIFIED,
			LOCAL_ATTR_LOGON_TIMESTAMP,
			LOCAL_ATTR_EXPIRES_AT,
		]:
			if fld in _result:
				_result[fld] = _result[fld].strftime(DATE_FORMAT_ISO_8601_ALT)

		# Filetime Dates
		for fld in (
			LOCAL_ATTR_LAST_LOGIN_WIN32,
			LOCAL_ATTR_PWD_SET_AT,
		):
			_v = _result.pop(fld, None)
			# Try to fetch last login from LDAP Timestamp
			if _v:
				_result[fld] = to_datetime(_v)
				_result[fld] = tz.make_aware(_result[fld]).strftime(
					DATE_FORMAT_ISO_8601_ALT
				)
			else:
				# Try to get last login from local django synced user
				try:
					local_instance: User = User.objects.get(
						username=user_search
					)
					_result[fld] = local_instance.last_login.strftime(
						DATE_FORMAT_ISO_8601_ALT
					)
				except:
					# Use datetime now if all else fails
					_result[fld] = tz.make_aware(datetime.now()).strftime(
						DATE_FORMAT_ISO_8601_ALT
					)
		return _result

	def ldap_user_change_status(
		self, username: str, enabled: bool
	) -> Connection:
		if not self.search_attrs:
			self.search_attrs = self.filter_attr_builder(
				RuntimeSettings
			).get_update_attrs()
		self.search_filter = self.get_user_object_filter(username=username)
		user_entry = self.get_user_object(
			username=username, attributes=self.search_attrs
		)
		permission_list = ldap_adsi.list_user_perms(user=user_entry)

		if user_entry.entry_dn == RuntimeSettings.LDAP_AUTH_CONNECTION_USER_DN:
			raise exc_user.UserAntiLockout

		try:
			if enabled is True:
				new_permissions = ldap_adsi.calc_permissions(
					permission_list,
					perm_remove=ldap_adsi.LDAP_UF_ACCOUNT_DISABLE,
				)
			else:
				new_permissions = ldap_adsi.calc_permissions(
					permission_list, perm_add=ldap_adsi.LDAP_UF_ACCOUNT_DISABLE
				)
		except Exception as e:
			logger.exception(e)
			raise exc_user.UserPermissionError

		_UAC_FIELD = RuntimeSettings.LDAP_FIELD_MAP[LOCAL_ATTR_UAC]
		self.ldap_connection.modify(
			user_entry.entry_dn,
			{_UAC_FIELD: [(MODIFY_REPLACE, [new_permissions])]},
		)

		try:
			django_user = User.objects.get(username=username)
		except:
			django_user = None
			pass

		if django_user:
			django_user.is_enabled = enabled
			django_user.save()

		DBLogMixin.log(
			user=self.request.user.id,
			operation_type=LOG_ACTION_UPDATE,
			log_target_class=LOG_CLASS_USER,
			log_target=username,
			message=LOG_EXTRA_ENABLE if enabled else LOG_EXTRA_DISABLE,
		)
		return self.ldap_connection

	def ldap_user_unlock(self, username: str) -> Connection:
		user_entry = self.get_user_object(username=username)

		self.ldap_connection.extend.microsoft.unlock_account(
			user=user_entry.entry_dn
		)
		DBLogMixin.log(
			user=self.request.user.id,
			operation_type=LOG_ACTION_UPDATE,
			log_target_class=LOG_CLASS_USER,
			log_target=username,
			message=LOG_EXTRA_UNLOCK,
		)
		return self.ldap_connection

	def ldap_user_delete(self, username: str):
		user_entry = self.get_user_object(username=username)

		try:
			self.ldap_connection.delete(user_entry.entry_dn)
		except Exception as e:
			raise exc_base.CoreException(
				data={"ldap_response": self.ldap_connection.result}
			)

		DBLogMixin.log(
			user=self.request.user.id,
			operation_type=LOG_ACTION_DELETE,
			log_target_class=LOG_CLASS_USER,
			log_target=username,
		)

		return self.ldap_connection

	def ldap_bulk_create_from_csv(
		self,
		request_user: User,
		user_rows: list[list[Any]],
		index_map: dict[str],
		path: str = None,
		placeholder_password: str = None,
	) -> tuple[list[str], list[dict]]:
		"""Create LDAP Users from CSV Rows

		Returns:
			tuple: created_users (list[str]), error_users (list[dict])
		"""
		if not path:
			path = f"CN=Users,{RuntimeSettings.LDAP_AUTH_SEARCH_BASE}"
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

		for row_idx, row in enumerate(user_rows):
			# Translate Data
			user_attrs = {}
			for col_idx, value in enumerate(row):
				user_attrs[index_map[col_idx]] = value

			# Pop Credentials
			if placeholder_password:
				user_pwd = placeholder_password
			if password_in_csv:
				user_pwd = user_attrs.pop(LOCAL_ATTR_PASSWORD)

			# Validate Data
			serializer = LDAPUserSerializer(
				data=user_attrs | {LOCAL_ATTR_PATH: path}
			)
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
				user_dn = self.ldap_user_insert(data=cleaned_data)
			except Exception as e:
				logger.exception(e)
				failed_users.append(
					{
						LOCAL_ATTR_USERNAME: user_attrs[LOCAL_ATTR_USERNAME],
						"stage": "save",
					}
				)
				continue

			created_users.append(user_attrs[LOCAL_ATTR_USERNAME])

			# Set Password if necessary
			if user_pwd:
				try:
					self.ldap_set_password(
						user_dn=user_dn,
						user_pwd_new=user_pwd,
						set_by_admin=True,
					)
				except Exception as e:
					logger.exception(e)
					failed_users.append(
						{
							LOCAL_ATTR_USERNAME: user_attrs[
								LOCAL_ATTR_USERNAME
							],
							"stage": "password",
						}
					)

			# Log operation
			DBLogMixin.log(
				user=request_user.id,
				operation_type=LOG_ACTION_UPDATE,
				log_target_class=LOG_CLASS_USER,
				log_target=cleaned_data[LOCAL_ATTR_USERNAME],
			)
		return created_users, failed_users

	def ldap_bulk_create_from_dicts(
		self,
		request_user: User,
		user_dicts: list[dict],
		path: str = None,
		placeholder_password: str = None,
	) -> tuple[list[str], list[dict]]:
		"""Create LDAP Users from Dictionaries

		Returns:
			tuple: created_users (list[str]), failed_users (list[dict])
		"""
		if not path:
			path = f"CN=Users,{RuntimeSettings.LDAP_AUTH_SEARCH_BASE}"
		created_users = []
		failed_users = []
		user_pwd = None
		user_nr = 0

		for user_attrs in user_dicts:
			# This is for front-end exception handling if a row has no username
			user_nr += 1

			# Pop Credentials
			if placeholder_password:
				user_pwd = placeholder_password
			if LOCAL_ATTR_PASSWORD in user_attrs:
				user_pwd = user_attrs.pop(LOCAL_ATTR_PASSWORD)

			# Validate Data
			serializer = LDAPUserSerializer(
				data=user_attrs | {LOCAL_ATTR_PATH: path}
			)
			if not serializer.is_valid():
				logger.error(serializer.errors)
				failed_users.append(
					{
						LOCAL_ATTR_USERNAME: user_nr
						if LOCAL_ATTR_USERNAME in serializer.errors
						else user_attrs[LOCAL_ATTR_USERNAME],
						"stage": "serializer",
					}
				)
				continue
			cleaned_data = self.cleanup_empty_str_values(
				serializer.validated_data
			)

			# Create User
			try:
				user_dn = self.ldap_user_insert(data=cleaned_data)
			except Exception as e:
				logger.exception(e)
				failed_users.append(
					{
						LOCAL_ATTR_USERNAME: user_attrs[LOCAL_ATTR_USERNAME],
						"stage": "save",
					}
				)
				continue

			created_users.append(user_attrs[LOCAL_ATTR_USERNAME])

			# Set Password if necessary
			if user_pwd:
				try:
					self.ldap_set_password(
						user_dn=user_dn,
						user_pwd_new=user_pwd,
						set_by_admin=True,
					)
				except Exception as e:
					logger.exception(e)
					failed_users.append(
						{
							LOCAL_ATTR_USERNAME: user_attrs[
								LOCAL_ATTR_USERNAME
							],
							"stage": "password",
						}
					)

			# Log operation
			DBLogMixin.log(
				user=request_user.id,
				operation_type=LOG_ACTION_UPDATE,
				log_target_class=LOG_CLASS_USER,
				log_target=cleaned_data[LOCAL_ATTR_USERNAME],
			)

		return created_users, failed_users


class LDAPUserBaseMixin(LDAPUserMixin):
	@transaction.atomic
	def ldap_users_sync(self, responsible_user: User = None) -> int:
		synced_users = 0
		updated_users = 0
		with LDAPConnector(
			user=responsible_user,
			force_admin=True if not responsible_user else False,
		) as ldc:
			self.ldap_connection = ldc.connection

			ldap_users: list[dict] = self._get_all_ldap_users()
			for ldap_user in ldap_users:
				user: User = None
				_username = ldap_user.get(LOCAL_ATTR_USERNAME, None)
				is_non_admin_builtin = self.is_built_in_user(
					username=_username,
					security_id=ldap_user.get(LOCAL_ATTR_SECURITY_ID, None),
					ignore_admin=True,
				)
				if is_non_admin_builtin:
					logger.debug(
						"Skipping sync for built-in non-admin user (%s)",
						_username,
					)
					continue

				# Serialize Data
				user_serializer = UserSerializer(data=ldap_user)
				user_serializer.is_valid()
				validated_data = user_serializer.validated_data

				# Create the user lookup.
				user_lookup = {}
				for field_name in RuntimeSettings.LDAP_AUTH_USER_LOOKUP_FIELDS:
					_v = ldap_user.get(field_name, "")
					if _v and len(_v) >= 1:
						user_lookup[field_name] = _v

				# Update or create the user.
				user, created = User.objects.update_or_create(
					defaults=validated_data, **user_lookup
				)

				# If the user was created, set them an unusable password.
				user.user_type = USER_TYPE_LDAP
				if created:
					synced_users += 1
					user.set_unusable_password()
				else:
					updated_users += 1

				user.save()
		return synced_users, updated_users

	@transaction.atomic
	def ldap_users_prune(self, responsible_user: User = None) -> int:
		pruned_users = 0
		with LDAPConnector(
			user=responsible_user,
			force_admin=True if not responsible_user else False,
		) as ldc:
			self.ldap_connection = ldc.connection
			users: list[User] = User.objects.filter(user_type=USER_TYPE_LDAP)
			for user in users:
				if not self.ldap_user_exists(
					username=user.username,
					email=user.email,
					return_exception=False,
				):
					logger.warning(f"LDAP User {user.username} pruned.")
					user.delete_permanently()
					pruned_users += 1
		return pruned_users

	@transaction.atomic
	def ldap_users_purge(self, responsible_user: User = None) -> int:
		purged_users = 0
		users = User.objects.filter(user_type=USER_TYPE_LDAP)
		for user in users:
			user: User
			if responsible_user:
				if user.username.lower() == responsible_user.username.lower():
					continue
			user.delete_permanently()
			purged_users += 1
		return purged_users
