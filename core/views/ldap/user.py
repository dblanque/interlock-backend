################################################################################
#################### INTERLOCK IS LICENSED UNDER GNU AGPLv3 ####################
################## ORIGINAL PROJECT CREATED BY DYLAN BLANQUÉ ###################
########################## AND BR CONSULTING S.R.L. ############################
################################################################################
# Module: core.views.user
# Contains the ViewSet for User related operations

# ---------------------------------- IMPORTS -----------------------------------#
### Exceptions
from core.exceptions.base import PermissionDenied, BadRequest
from core.exceptions import base as exc_base, users as exc_user
from django.core.exceptions import ObjectDoesNotExist
from interlock_backend.encrypt import aes_encrypt, aes_decrypt

### Models
from core.models.user import (
	User,
	USER_PASSWORD_FIELDS,
	USER_TYPE_LDAP,
	USER_TYPE_LOCAL,
)
from core.views.mixins.logs import LogMixin
from core.models.choices.log import (
	LOG_ACTION_UPDATE,
	LOG_ACTION_CREATE,
	LOG_CLASS_USER,
	LOG_EXTRA_USER_CHANGE_PASSWORD,
	LOG_EXTRA_USER_END_USER_UPDATE,
)

### Mixins
from core.views.mixins.ldap.user import UserViewMixin, UserViewLDAPMixin

### Serializers / Validators
from core.serializers import user as UserValidators

### ViewSets
from core.views.base import BaseViewSet

### REST Framework
from rest_framework.response import Response
from rest_framework.decorators import action

### Auth
from core.decorators.login import auth_required, admin_required
from core.ldap import adsi as ldap_adsi
from core.constants import user as ldap_user
from core.ldap.connector import LDAPConnector
import ldap3

### Others
from core.decorators.intercept import ldap_backend_intercept
from core.constants.user import PUBLIC_FIELDS
from core.config.runtime import RuntimeSettings
import logging
################################################################################

DBLogMixin = LogMixin()
logger = logging.getLogger(__name__)


# TODO - Make decorator that checks user existence both in LDAP and Django
# TODO - Make decorator that checks user type being correct (ldap or django/local)
class LDAPUserViewSet(BaseViewSet, UserViewMixin, UserViewLDAPMixin):
	queryset = User.objects.all()

	@auth_required
	@admin_required
	@ldap_backend_intercept
	def list(self, request):
		user: User = request.user
		data = {}
		code = 0
		code_msg = "ok"

		self.ldap_filter_object = "(objectClass=" + RuntimeSettings.LDAP_AUTH_OBJECT_CLASS + ")"
		self.ldap_filter_attr = self.filter_attr_builder(RuntimeSettings).get_list_attrs()

		# Open LDAP Connection
		with LDAPConnector(user) as ldc:
			self.ldap_connection = ldc.connection
			data = self.ldap_user_list()

		return Response(
			data={
				"code": code,
				"code_msg": code_msg,
				"users": data["users"],
				"headers": data["headers"],
			}
		)

	@action(detail=False, methods=["post"])
	@auth_required
	@admin_required
	@ldap_backend_intercept
	def fetch(self, request):
		user: User = request.user
		code = 0
		code_msg = "ok"
		data: dict = request.data

		user_search = None
		for _k in [RuntimeSettings.LDAP_AUTH_USER_FIELDS["username"], "username"]:
			if not user_search:
				user_search = data.get(_k, None)

		if not user_search or not isinstance(user_search, str):
			raise exc_base.BadRequest

		# Open LDAP Connection
		with LDAPConnector(user) as ldc:
			self.ldap_connection = ldc.connection
			user_data = self.ldap_user_fetch(user_search=user_search)

		return Response(data={"code": code, "code_msg": code_msg, "data": user_data})

	@action(detail=False, methods=["post"])
	@auth_required
	@admin_required
	@ldap_backend_intercept
	def insert(self, request):
		user: User = request.user
		code = 0
		code_msg = "ok"
		data: dict = request.data

		if "username" not in data:
			raise exc_base.MissingDataKey(data={"key": "username"})

		if data["password"] != data["passwordConfirm"]:
			raise exc_user.UserPasswordsDontMatch(
				data={"code": "user_passwords_dont_match", "user": data["username"]}
			)

		# TODO - Add Deserializer Validation
		# Open LDAP Connection
		with LDAPConnector(user) as ldc:
			self.ldap_connection = ldc.connection

			# User Exists check
			self.ldap_user_exists(
				username=data.get("username"),
				email=data.get(RuntimeSettings.LDAP_AUTH_USER_FIELDS["email"], None),
			)

			user_dn = self.ldap_user_insert(user_data=data)
			user_pwd = data["password"]
			self.ldap_set_password(user_dn=user_dn, user_pwd_new=user_pwd, set_by_admin=True)

		return Response(data={"code": code, "code_msg": code_msg, "data": data["username"]})

	@auth_required
	@admin_required
	@ldap_backend_intercept
	def update(self, request, pk=None):
		user: User = request.user
		code = 0
		code_msg = "ok"
		data: dict = request.data

		######################## Set LDAP Attributes ###########################
		self.ldap_filter_attr = self.filter_attr_builder(RuntimeSettings).get_update_attrs()
		########################################################################

		EXCLUDE_KEYS = self.filter_attr_builder(RuntimeSettings).get_update_exclude_keys()

		user_to_update = data.get(RuntimeSettings.LDAP_AUTH_USER_FIELDS["username"])
		if "permission_list" in data:
			permission_list = data["permission_list"]
		else:
			permission_list = None
		for key in EXCLUDE_KEYS:
			if key in data:
				del data[key]

		# Open LDAP Connection
		with LDAPConnector(user) as ldc:
			self.ldap_connection = ldc.connection

			# Check user exists and fetch it with minimal attributes
			if not self.ldap_user_exists(username=user_to_update, return_exception=False):
				raise exc_user.UserDoesNotExist

			# Check if email overlaps with any other users
			user_email = data.get("email", None)
			if user_email:
				self.ldap_user_exists(email=user_email)

			# Update
			self.ldap_user_update(
				username=user_to_update,
				user_data=data,
				permission_list=permission_list,
			)

		return Response(data={"code": code, "code_msg": code_msg, "data": data})

	@action(detail=False, methods=["post"])
	@auth_required
	@admin_required
	@ldap_backend_intercept
	def change_status(self, request):
		user: User = request.user
		data: dict = request.data
		code = 0
		code_msg = "ok"

		for required_key in ["username", "enabled"]:
			if required_key not in data:
				raise BadRequest
		enabled = data.pop("enabled")

		######################## Set LDAP Attributes ###########################
		self.ldap_filter_object = "(objectClass=" + RuntimeSettings.LDAP_AUTH_OBJECT_CLASS + ")"
		self.ldap_filter_attr = self.filter_attr_builder(RuntimeSettings).get_update_attrs()
		########################################################################

		if data["username"] == self.request.user:
			raise exc_user.UserAntiLockout

		# Open LDAP Connection
		with LDAPConnector(user) as ldc:
			self.ldap_connection = ldc.connection
			self.ldap_user_change_status(username=data["username"], enabled=enabled)

		return Response(data={"code": code, "code_msg": code_msg})

	@action(detail=False, methods=["post"])
	@auth_required
	@admin_required
	@ldap_backend_intercept
	def delete(self, request, pk=None):
		user: User = request.user
		code = 0
		code_msg = "ok"
		data = request.data

		if not isinstance(data, dict):
			raise exc_base.CoreException

		# Open LDAP Connection
		username = data.get("username", None)
		if not username:
			username = data.get(RuntimeSettings.LDAP_AUTH_USER_FIELDS["username"], None)
		if not username:
			raise exc_base.BadRequest

		with LDAPConnector(user) as ldc:
			self.ldap_connection = ldc.connection

			if username == user.username:
				raise exc_user.UserAntiLockout

			# Check user exists and delete in LDAP Server
			if self.ldap_user_exists(username=username, return_exception=False):
				self.ldap_user_delete(username=data)

			try:
				django_user = User.objects.get(username=username, user_type=USER_TYPE_LDAP)
				django_user.delete_permanently()
			except ObjectDoesNotExist:
				pass

		return Response(data={"code": code, "code_msg": code_msg, "data": data})

	@action(detail=False, methods=["post"])
	@auth_required
	@admin_required
	@ldap_backend_intercept
	def change_password(self, request, pk=None):
		user: User = request.user
		code = 0
		code_msg = "ok"
		data = request.data
		ldap_user_search = None

		# Open LDAP Connection
		with LDAPConnector(user) as ldc:
			self.ldap_connection = ldc.connection
			if RuntimeSettings.LDAP_AUTH_USER_FIELDS["username"] in data:
				ldap_user_search = data[RuntimeSettings.LDAP_AUTH_USER_FIELDS["username"]]
			elif "username" in data:
				ldap_user_search = data["username"]

			# If data request for deletion has user DN
			if "distinguishedName" in data.keys() and data["distinguishedName"] != "":
				logger.debug("Updating with distinguishedName obtained from front-end")
				logger.debug(data["distinguishedName"])
				dn = data["distinguishedName"]
			# Else, search for username dn
			else:
				logger.debug("Updating with user dn search method")
				ldap_user_entry = self.get_user_object(ldap_user_search)

				dn = str(ldap_user_entry.distinguishedName)
				logger.debug(dn)

			if dn is None or dn == "":
				raise exc_user.UserDoesNotExist

			if data["password"] != data["passwordConfirm"]:
				raise exc_user.UserPasswordsDontMatch
			self.ldap_set_password(user_dn=dn, user_pwd_new=data["password"], set_by_admin=True)

		django_user = None
		try:
			django_user = User.objects.get(username=ldap_user_search)
		except Exception as e:
			logger.error(e)
		if django_user:
			encrypted_data = aes_encrypt(data["password"])
			for index, field in enumerate(USER_PASSWORD_FIELDS):
				setattr(django_user, field, encrypted_data[index])
			django_user.set_unusable_password()
			django_user.save()

		DBLogMixin.log(
			user=request.user.id,
			operation_type=LOG_ACTION_UPDATE,
			log_target_class=LOG_CLASS_USER,
			log_target=ldap_user_search,
			message=LOG_EXTRA_USER_CHANGE_PASSWORD,
		)

		return Response(data={"code": code, "code_msg": code_msg, "data": data})

	@action(detail=False, methods=["post"])
	@auth_required
	@admin_required
	@ldap_backend_intercept
	def unlock(self, request, pk=None):
		user: User = request.user
		code = 0
		code_msg = "ok"
		data = request.data

		# Open LDAP Connection
		with LDAPConnector(user) as ldc:
			self.ldap_connection = ldc.connection

			# Check user exists and fetch it with minimal attributes
			if not self.ldap_user_exists(username=data["username"], return_exception=False):
				raise exc_user.UserDoesNotExist

			try:
				self.ldap_user_unlock(username=data["username"])
				result = self.ldap_connection.result
				if result["description"] == "success":
					response_result = data["username"]
				else:
					raise exc_user.CouldNotUnlockUser
			except:
				raise exc_user.CouldNotUnlockUser

		return Response(data={"code": code, "code_msg": code_msg, "data": response_result})

	@action(detail=False, methods=["post"])
	@auth_required
	@admin_required
	@ldap_backend_intercept
	def bulk_insert(self, request):
		user: User = request.user
		code = 0
		code_msg = "ok"
		data = request.data
		data_keys = ["headers", "users", "path", "mapping"]
		imported_users = []
		skipped_users = []
		failed_users = []

		for k in data_keys:
			if k not in data:
				e = exc_base.MissingDataKey()
				e.set_detail({"key": k})
				raise e

		user_headers = data["headers"]
		user_list = data["users"]
		user_path = data["path"]
		user_placeholder_password = None
		header_mapping = data["mapping"]

		######################## Set LDAP Attributes ###########################
		self.ldap_filter_attr = self.filter_attr_builder(RuntimeSettings).get_bulk_insert_attrs()

		# Check if data has a requested placeholder_password
		required_fields = ["username"]
		if "placeholder_password" in data and data["placeholder_password"]:
			if len(data["placeholder_password"]) > 0:
				user_placeholder_password = data["placeholder_password"]

		# Use CSV column if placeholder not requested
		if not user_placeholder_password:
			required_fields.append("password")

		mapped_user_key = header_mapping[ldap_user.USERNAME]
		mapped_email_key = header_mapping[ldap_user.EMAIL]
		if user_placeholder_password:
			mapped_pwd_key = ldap_user.PASSWORD
		else:
			mapped_pwd_key = header_mapping[ldap_user.PASSWORD]
		EXCLUDE_KEYS = [
			mapped_user_key,  # LDAP Uses sAMAccountName
			mapped_pwd_key,
			"permission_list",  # This array was parsed and calculated, then changed to userAccountControl
			"distinguishedName",  # We don't want the front-end generated DN
		]
		########################################################################

		# Validate Front-end mapping with CSV Headers
		for k in required_fields:
			if k not in header_mapping:
				raise exc_user.UserBulkInsertMappingError(data={"key": k})

		# Validate all usernames before opening connection
		for row in user_list:
			if len(row) != len(user_headers):
				raise exc_user.UserBulkInsertLengthError(data={"user": row[mapped_user_key]})

			for f in row.keys():
				if f in UserValidators.FIELD_VALIDATORS:
					if UserValidators.FIELD_VALIDATORS[f] is not None:
						validator = UserValidators.FIELD_VALIDATORS[f] + "_validator"
						if getattr(UserValidators, validator)(row[f]) == False:
							if len(user_list) > 1:
								failed_users.append(
									{"username": row[mapped_user_key], "stage": "validation"}
								)
								user_list.remove(row)
							else:
								data = {"field": f, "value": row[f]}
								raise exc_user.UserFieldValidatorFailed(data=data)

		# Open LDAP Connection
		with LDAPConnector(user) as ldc:
			self.ldap_connection = ldc.connection
			for row in user_list:
				row: dict
				user_search = row[mapped_user_key]
				row["path"] = user_path

				if self.ldap_user_exists(
					username=user_search,
					email=row.get(mapped_email_key, None),
					return_exception=False,
				):
					skipped_users.append(row[mapped_user_key])
					continue

				user_dn = self.ldap_user_insert(
					user_data=row,
					exclude_keys=EXCLUDE_KEYS,
					return_exception=False,
					key_mapping=header_mapping,
				)
				if not user_dn:
					failed_users.append({"username": row[mapped_user_key], "stage": "permission"})
					continue

				set_pwd = False
				if user_placeholder_password:
					row[mapped_pwd_key] = user_placeholder_password
					set_pwd = True
				elif mapped_pwd_key in data["headers"] and len(row[mapped_pwd_key]) > 0:
					set_pwd = True

				if set_pwd:
					try:
						self.ldap_set_password(
							user_dn=user_dn, user_pwd_new=row[mapped_pwd_key], set_by_admin=True
						)
					except:
						failed_users.append({"username": row[mapped_user_key], "stage": "password"})

				imported_users.append(row[mapped_user_key])
				DBLogMixin.log(
					user=request.user.id,
					operation_type=LOG_ACTION_CREATE,
					log_target_class=LOG_CLASS_USER,
					log_target=row[mapped_user_key],
				)

		return Response(
			status=200,
			data={
				"code": code,
				"code_msg": code_msg,
				"imported_users": imported_users,
				"skipped_users": skipped_users,
				"failed_users": failed_users,
			},
		)

	@action(detail=False, methods=["post"])
	@auth_required
	@admin_required
	@ldap_backend_intercept
	def bulk_update(self, request, pk=None):
		user: User = request.user
		code = 0
		code_msg = "ok"
		data = request.data

		if any(v not in data for v in ["users", "permissions", "values"]):
			raise exc_base.BadRequest

		permission_list = None
		if len(data["permissions"]) > 0:
			permission_list = data["permissions"]

		EXCLUDE_KEYS = self.filter_attr_builder(RuntimeSettings).get_update_exclude_keys()
		EXCLUDE_KEYS.append(RuntimeSettings.LDAP_AUTH_USER_FIELDS["email"])
		for k in EXCLUDE_KEYS:
			if k in data["values"]:
				del data["values"][k]

		if len(data["values"]) == 0 and len(data["permissions"]) == 0:
			raise exc_base.BadRequest

		# Open LDAP Connection
		with LDAPConnector(user) as ldc:
			for user_to_update in data["users"]:
				self.ldap_connection = ldc.connection

				# Check that user exists and fetch it
				if not self.ldap_user_exists(username=user_to_update, return_exception=False):
					raise exc_user.UserDoesNotExist

				# Check if email overlaps with another user's
				user_email = data.get("email", None)
				if user_email:
					self.ldap_user_exists(email=user_email)

				self.get_user_object(user_to_update, attributes=ldap3.ALL_ATTRIBUTES)

				self.ldap_user_update(
					username=user_to_update,
					user_data=data["values"],
					permission_list=permission_list,
				)

		return Response(data={"code": code, "code_msg": code_msg, "data": data})

	@action(detail=False, methods=["post"])
	@auth_required
	@admin_required
	@ldap_backend_intercept
	def bulk_change_status(self, request):
		user: User = request.user
		code = 0
		code_msg = "ok"
		request_data = request.data
		disable_users = request_data["disable"]
		data = request_data["users"]

		if not isinstance(disable_users, bool) or not isinstance(data, list):
			raise BadRequest

		######################## Set LDAP Attributes ###########################
		self.ldap_filter_object = "(objectClass=" + RuntimeSettings.LDAP_AUTH_OBJECT_CLASS + ")"
		self.ldap_filter_attr = self.filter_attr_builder(RuntimeSettings).get_update_attrs()
		########################################################################

		# Open LDAP Connection
		with LDAPConnector(user) as ldc:
			self.ldap_connection = ldc.connection
			success = []
			for user_data in data:
				if disable_users and user_data["is_enabled"]:
					self.ldap_user_change_status(username=user_data["username"], enabled=False)
					success.append(user_data["username"])
				elif not disable_users and not user_data["is_enabled"]:
					self.ldap_user_change_status(username=user_data["username"], enabled=True)
					success.append(user_data["username"])
				else:
					continue

		return Response(data={"code": code, "code_msg": code_msg, "data": success})

	@action(detail=False, methods=["post"])
	@auth_required
	@admin_required
	@ldap_backend_intercept
	def bulk_delete(self, request, pk=None):
		user: User = request.user
		code = 0
		code_msg = "ok"
		data = request.data

		if not isinstance(data, list):
			raise exc_base.CoreException

		self.ldap_settings = {
			"authUsernameIdentifier": RuntimeSettings.LDAP_AUTH_USER_FIELDS["username"]
		}

		# Open LDAP Connection
		with LDAPConnector(user) as ldc:
			self.ldap_connection = ldc.connection
			for user in data:
				self.ldap_user_delete(username=user)

		return Response(data={"code": code, "code_msg": code_msg, "data": data})

	@action(detail=False, methods=["post"])
	@auth_required
	@admin_required
	@ldap_backend_intercept
	def bulk_unlock(self, request, pk=None):
		user: User = request.user
		code = 0
		code_msg = "ok"
		data = request.data

		if not isinstance(data, list):
			raise exc_base.BadRequest

		# Open LDAP Connection
		with LDAPConnector(user) as ldc:
			self.ldap_connection = ldc.connection
			success = []
			for user_object in data:
				self.ldap_user_unlock(username=user_object)
				success.append(user_object["username"])

			result = self.ldap_connection.result
			if result["description"] == "success":
				response_result = success
			else:
				raise exc_user.CouldNotUnlockUser

		return Response(data={"code": code, "code_msg": code_msg, "data": response_result})

	@action(detail=False, methods=["post"])
	@auth_required
	@ldap_backend_intercept
	def self_change_password(self, request, pk=None):
		user: User = request.user
		code = 0
		code_msg = "ok"
		data = request.data

		excKeys = ["username", RuntimeSettings.LDAP_AUTH_USER_FIELDS["username"]]
		for k in excKeys:
			if k in data:
				raise exc_base.BadRequest

		# Open LDAP Connection
		# User doesn't have rights to change any data in LDAP Server
		# so admin must be forced, auth_required decorator with
		# require_admin flag is very important
		with LDAPConnector(force_admin=True) as ldc:
			self.ldap_connection = ldc.connection
			ldap_user_search = user.username
			ldap_user_entry = self.get_user_object(
				ldap_user_search,
				attributes=[
					RuntimeSettings.LDAP_AUTH_USER_FIELDS["username"],
					"distinguishedName",
					"userAccountControl",
				],
			)

			if "distinguishedName" in data.keys() and data["distinguishedName"] != "":
				logger.debug("Updating with distinguishedName obtained from front-end")
				logger.debug(data["distinguishedName"])
				distinguishedName = data["distinguishedName"]
			else:
				logger.debug("Updating with user dn search method")

				distinguishedName = str(ldap_user_entry.distinguishedName)
				logger.debug(distinguishedName)

			if ldap_adsi.list_user_perms(
				user=ldap_user_entry, perm_search=ldap_adsi.LDAP_UF_PASSWD_CANT_CHANGE
			):
				raise PermissionDenied

			if not distinguishedName or distinguishedName == "":
				raise exc_user.UserDoesNotExist

			if data["password"] != data["passwordConfirm"]:
				raise exc_user.UserPasswordsDontMatch

			self.ldap_set_password(
				user_dn=distinguishedName,
				user_pwd_new=data["password"],
				user_pwd_old=aes_decrypt(*user.encryptedPassword),
			)

		django_user = None
		try:
			django_user = User.objects.get(username=ldap_user_search)
		except Exception as e:
			logger.error(e)
		if django_user:
			encrypted_data = aes_encrypt(data["password"])
			for index, field in enumerate(USER_PASSWORD_FIELDS):
				setattr(django_user, field, encrypted_data[index])
			django_user.set_unusable_password()
			django_user.save()

		DBLogMixin.log(
			user=request.user.id,
			operation_type=LOG_ACTION_UPDATE,
			log_target_class=LOG_CLASS_USER,
			log_target=ldap_user_search,
			message=LOG_EXTRA_USER_CHANGE_PASSWORD,
		)

		return Response(data={"code": code, "code_msg": code_msg, "data": data})

	@action(detail=False, methods=["put", "post"])
	@auth_required
	@ldap_backend_intercept
	def self_update(self, request, pk=None):
		user: User = request.user
		code = 0
		code_msg = "ok"
		data = request.data

		BAD_KEYS = ["username", RuntimeSettings.LDAP_AUTH_USER_FIELDS["username"]]
		for k in BAD_KEYS:
			if k in data:
				raise exc_base.BadRequest

		# Get basic attributes for this user from AD to compare query and get dn
		self.ldap_filter_attr = self.filter_attr_builder(RuntimeSettings).get_update_attrs()
		EXCLUDE_KEYS = self.filter_attr_builder(RuntimeSettings).get_update_self_exclude_keys()

		for key in EXCLUDE_KEYS:
			if key in data:
				del data[key]

		# Open LDAP Connection
		# User doesn't have rights to change any data in LDAP Server
		# so admin must be forced, auth_required decorator with
		# require_admin flag is very important
		with LDAPConnector(force_admin=True) as ldc:
			self.ldap_connection = ldc.connection
			ldap_user_search = user.username
			self.ldap_user_update(username=ldap_user_search, user_data=data)

		logger.debug(self.ldap_connection.result)

		DBLogMixin.log(
			user=request.user.id,
			operation_type=LOG_ACTION_UPDATE,
			log_target_class=LOG_CLASS_USER,
			log_target=ldap_user_search,
			message=LOG_EXTRA_USER_END_USER_UPDATE,
		)

		django_user = None
		try:
			django_user = User.objects.get(username=ldap_user_search)
		except:
			pass

		if django_user:
			for key in RuntimeSettings.LDAP_AUTH_USER_FIELDS:
				mapped_key = RuntimeSettings.LDAP_AUTH_USER_FIELDS[key]
				if mapped_key in data:
					setattr(django_user, key, data[mapped_key])
				if "mail" not in data:
					django_user.email = None
			django_user.save()

		for k in EXCLUDE_KEYS:
			if k in data:
				del data[k]
		return Response(data={"code": code, "code_msg": code_msg, "data": data})

	@action(detail=False, methods=["get"])
	@auth_required
	def self_info(self, request):
		user: User = request.user
		data = {}
		code = 0
		data["username"] = user.username or ""
		data["first_name"] = user.first_name or ""
		data["last_name"] = user.last_name or ""
		data["email"] = user.email or ""
		# This only informs the front-end it is admin capable
		# Validation is done on the back-end
		if user.is_superuser:
			data["admin_allowed"] = True
		return Response(data={"code": code, "code_msg": "ok", "user": data})

	@action(detail=False, methods=["get"])
	@auth_required
	@ldap_backend_intercept
	def self_fetch(self, request):
		user: User = request.user
		code = 0
		code_msg = "ok"
		user_search = user.username
		if user.user_type == USER_TYPE_LOCAL:
			user_data = {}
			for field in PUBLIC_FIELDS:
				user_data[field] = getattr(user, field)
		elif user.user_type == USER_TYPE_LDAP:
			# Open LDAP Connection
			with LDAPConnector(user, force_admin=True) as ldc:
				self.ldap_connection = ldc.connection
				self.ldap_filter_attr = self.filter_attr_builder(
					RuntimeSettings
				).get_fetch_me_attrs()

				self.ldap_filter_object = (
					"(objectClass=" + RuntimeSettings.LDAP_AUTH_OBJECT_CLASS + ")"
				)

				# Add filter for username
				self.ldap_filter_object = ldap_adsi.join_ldap_filter(
					self.ldap_filter_object,
					f"{RuntimeSettings.LDAP_AUTH_USER_FIELDS['username']}={user_search}",
				)
				self.ldap_connection.search(
					RuntimeSettings.LDAP_AUTH_SEARCH_BASE,
					self.ldap_filter_object,
					attributes=self.ldap_filter_attr,
				)
				user_entry = self.ldap_connection.entries

				self.ldap_filter_attr.remove("userAccountControl")

				# For each attribute in user object attributes
				user_data = {}
				for attr_key in self.ldap_filter_attr:
					if attr_key in self.ldap_filter_attr:
						str_key = str(attr_key)
						str_value = str(getattr(user_entry[0], attr_key))
						if str_value == "[]":
							user_data[str_key] = ""
						else:
							user_data[str_key] = str_value
					if attr_key == RuntimeSettings.LDAP_AUTH_USER_FIELDS["username"]:
						user_data["username"] = str_value

					# Check if user can change password based on perms
					user_data["can_change_pwd"] = not ldap_adsi.list_user_perms(
						user=user_entry[0], perm_search=ldap_adsi.LDAP_UF_PASSWD_CANT_CHANGE
					)

		return Response(data={"code": code, "code_msg": code_msg, "data": user_data})
