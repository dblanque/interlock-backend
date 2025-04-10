################################################################################
#################### INTERLOCK IS LICENSED UNDER GNU AGPLv3 ####################
################## ORIGINAL PROJECT CREATED BY DYLAN BLANQUÉ ###################
########################## AND BR CONSULTING S.R.L. ############################
################################################################################
# Module: interlock_backend.ldap.accountTypes
# Contains:
# - Bind User connector for Administrative Privilege Operations
# - Recursive directory listing functions

# ---------------------------------- IMPORTS -----------------------------------#
# Typing
from typing import TypedDict
from typing_extensions import NotRequired
from enum import Enum

# LDAP
import ldap3
from django_python3_ldap.utils import import_func
from core.ldap.adsi import search_filter_add, LDAP_FILTER_OR
from core.exceptions import ldap as exc_ldap
from ldap3.core.exceptions import LDAPException

# Models
from core.models.choices.log import (
	LOG_ACTION_OPEN,
	LOG_ACTION_CLOSE,
	LOG_CLASS_CONN,
)
from core.views.mixins.logs import LogMixin
from core.models.user import User, USER_PASSWORD_FIELDS, USER_TYPE_LDAP, USER_TYPE_LOCAL

# Settings
from interlock_backend.settings import (
	DEFAULT_SUPERUSER_USERNAME,
	DEVELOPMENT_LOG_LDAP_BIND_CREDENTIALS,
)
from core.config.runtime import RuntimeSettings

# Auth
from django.contrib.auth.models import update_last_login
from django.contrib.auth import get_user_model
from interlock_backend.encrypt import aes_encrypt, aes_decrypt

# Libs
from inspect import getfullargspec
import ssl
import logging
import sys
from typing import Iterable
from uuid import uuid4
###############################################################################

this_module = sys.modules[__name__]
DBLogMixin = LogMixin()
logger = logging.getLogger(__name__)


def recursive_member_search(user_dn: str, connection: ldap3.Connection, group_dn: str):
	# Type checks
	if not isinstance(user_dn, str):
		raise TypeError("user_dn must be str.")
	if not isinstance(group_dn, str):
		raise TypeError("group_dn must be str.")
	# Length Checks
	if len(user_dn) <= 0:
		raise ValueError("user_dn cannot be empty.")
	if len(group_dn) <= 0:
		raise ValueError("user_dn cannot be empty.")

	# Add filter for username
	ldap_filter_object = ""
	ldap_filter_object = search_filter_add(ldap_filter_object, f"distinguishedName={group_dn}")
	ldap_filter_object = search_filter_add(ldap_filter_object, f"objectClass=group")
	connection.search(
		RuntimeSettings.LDAP_AUTH_SEARCH_BASE,
		ldap_filter_object,
		attributes=["member", "objectClass", "distinguishedName"],
	)
	for e in connection.entries:
		if "group" in e.objectClass:
			# Check if member in group directly
			if user_dn in e.member:
				return True
			# Check if member in nested groups
			for dn in e.member:
				# Avoid infinite self recursion
				# (should not be possible to be a member of itself, but regardless)
				if group_dn == dn:
					continue
				# Recursive search
				r = recursive_member_search(user_dn=user_dn, connection=connection, group_dn=dn)
				if r == True:
					return r
	return False


def sync_user_relations(user: User, ldap_attributes, *, connection=None):
	if not "distinguishedName" in ldap_attributes:
		raise ValueError("distinguishedName not present in User LDAP Attributes.")

	if isinstance(ldap_attributes["distinguishedName"], str):
		user.dn = str(ldap_attributes["distinguishedName"]).lstrip("['").rstrip("']")
	elif isinstance(ldap_attributes["distinguishedName"], Iterable):
		user.dn = ldap_attributes["distinguishedName"][0].lstrip("['").rstrip("']")
	if "Administrator" in ldap_attributes[RuntimeSettings.LDAP_AUTH_USER_FIELDS["username"]]:
		user.is_staff = True
		user.is_superuser = True
		user.save()
	elif recursive_member_search(
		user_dn=user.dn, connection=connection, group_dn=RuntimeSettings.ADMIN_GROUP_TO_SEARCH
	):
		user.is_staff = True
		user.is_superuser = True
		if "mail" in ldap_attributes:
			user.email = str(ldap_attributes["mail"]).lstrip("['").rstrip("']") or ""
		user.save()
	else:
		user.is_staff = False
		user.is_superuser = False
		if "mail" in ldap_attributes:
			user.email = str(ldap_attributes["mail"]).lstrip("['").rstrip("']") or ""
		user.save()


def authenticate(*args, **kwargs):
	"""
	Authenticates with the LDAP server, and returns
	the corresponding Django user instance.

	The user identifier should be keyword arguments matching the fields
	in settings.LDAP_AUTH_USER_LOOKUP_FIELDS, plus a `password` argument.
	"""
	username = kwargs["username"]
	if username == DEFAULT_SUPERUSER_USERNAME:
		return None
	password = kwargs.pop("password", None)
	auth_user_lookup_fields = RuntimeSettings.LDAP_AUTH_USER_LOOKUP_FIELDS
	ldap_kwargs = {key: value for (key, value) in kwargs.items() if key in auth_user_lookup_fields}

	# Check that this is valid login data.
	if not password or "username" not in ldap_kwargs.keys():
		return None

	# Connect to LDAP and fetch user DN, create or update user if necessary
	with LDAPConnector(password=password, force_admin=True, is_authenticating=True) as ldc:
		if ldc.connection is None:
			return None
		user: User = ldc.get_user(**ldap_kwargs)
		ldc.connection.unbind()
		if user is None:
			return None

		# ! I went insane with this garbage ! #
		# Test user credentials against server, keep in mind LDAP Passwords have history
		# lifetime in the NTLM.
		# Letting you know so you don't spend 50 hours debugging something that's
		# actually working properly =_= -Dylan
		# sources:
		# https://learn.microsoft.com/en-US/troubleshoot/windows-server/windows-security/new-setting-modifies-ntlm-network-authentication
		# https://unix.stackexchange.com/questions/737113/samba-4-change-password-old-enable
		if not ldc.rebind(user_dn=user.dn, password=password):
			return None

	# Save user password in DB (encrypted) for LDAP Operations
	encrypted_data = aes_encrypt(password)
	for index, field in enumerate(USER_PASSWORD_FIELDS):
		setattr(user, field, encrypted_data[index])
	del password
	user.user_type = USER_TYPE_LDAP
	update_last_login(None, user)
	user.save()
	return user


class LDAPConnectionOptions(TypedDict):
	user_dn: NotRequired[str]
	password: NotRequired[str]
	user: NotRequired[User]
	force_admin: NotRequired[bool]
	plain_text_password: NotRequired[bool]
	get_ldap_info: NotRequired[str]
	is_authenticating: NotRequired[bool]


class LDAPConnector(object):
	connection: ldap3.Connection
	log_debug_prefix = "[DEBUG - LDAPConnector] | "
	_entered = False

	def __init__(
		self,
		user: User = None,
		force_admin=False,
		get_ldap_info=ldap3.DSA,
		is_authenticating=False,
		**kwargs,
	):
		is_local_superuser = hasattr(user, "username") and (
			user.username == DEFAULT_SUPERUSER_USERNAME
			or (user.is_superuser and user.user_type == USER_TYPE_LOCAL)
		)
		self.default_user_dn = RuntimeSettings.LDAP_AUTH_CONNECTION_USER_DN
		self.default_user_pwd = RuntimeSettings.LDAP_AUTH_CONNECTION_PASSWORD
		self.__new_uuid__()
		self.is_authenticating = is_authenticating

		# If it's an Initial Authentication we need to use the bind user first
		if force_admin or is_local_superuser:
			self.user_dn = self.default_user_dn
			self._temp_password = self.default_user_pwd
		# If initial auth or user is local interlock superadmin
		elif user is not None and user.user_type == USER_TYPE_LDAP:
			self.user_dn = getattr(user, "dn", None)
			self._temp_password = aes_decrypt(*user.encryptedPassword)
		else:
			raise Exception("No valid user in LDAP Connector.")

		if not isinstance(RuntimeSettings.LDAP_AUTH_TLS_VERSION, Enum):
			ldap_auth_tls_version = getattr(ssl, RuntimeSettings.LDAP_AUTH_TLS_VERSION)
		else:
			ldap_auth_tls_version = RuntimeSettings.LDAP_AUTH_TLS_VERSION

		if not self.user_dn and not force_admin:
			raise ValueError("No user_dn was provided for LDAP Connector.")

		self.__log_init__(user=user, tls_version=ldap_auth_tls_version)

		# Initialize Server Args Dictionary
		server_args = {
			"get_info": get_ldap_info,
			"connect_timeout": RuntimeSettings.LDAP_AUTH_CONNECT_TIMEOUT,
		}

		# Build server pool
		self.server_pool = ldap3.ServerPool(None, ldap3.RANDOM, active=True, exhaust=5)
		self.auth_url = RuntimeSettings.LDAP_AUTH_URL
		if not isinstance(self.auth_url, list):
			self.auth_url = [self.auth_url]

		# Include SSL, if requested.
		server_args["use_ssl"] = RuntimeSettings.LDAP_AUTH_USE_SSL
		# Include TLS, if requested.
		if RuntimeSettings.LDAP_AUTH_USE_TLS:
			self.tlsSettings = ldap3.Tls(
				ciphers="ALL",
				version=ldap_auth_tls_version,
			)
			server_args["tls"] = self.tlsSettings
		else:
			self.tlsSettings = None

		for url in self.auth_url:
			server = ldap3.Server(url, allowed_referral_hosts=[("*", True)], **server_args)
			self.server_pool.add(server)

		self.user = user
		self.auth_url = self.auth_url
		self.connection = None

	def __log_init__(self, user, tls_version):
		logger.debug("%sUser: %s", self.log_debug_prefix, user)
		logger.debug("%sUser DN: %s", self.log_debug_prefix, self.user_dn)
		logger.debug("%sURL: %s", self.log_debug_prefix, RuntimeSettings.LDAP_AUTH_URL)
		logger.debug(
			"%sConnect Timeout: %s", self.log_debug_prefix, RuntimeSettings.LDAP_AUTH_CONNECT_TIMEOUT
		)
		logger.debug(
			"%sReceive Timeout: %s", self.log_debug_prefix, RuntimeSettings.LDAP_AUTH_RECEIVE_TIMEOUT
		)
		logger.debug("%sUse SSL: %s", self.log_debug_prefix, RuntimeSettings.LDAP_AUTH_USE_SSL)
		logger.debug("%sUse TLS: %s", self.log_debug_prefix, RuntimeSettings.LDAP_AUTH_USE_TLS)
		logger.debug("%sTLS Version: %s", self.log_debug_prefix, tls_version)

	def __enter__(self) -> "LDAPConnector":
		self._entered = True
		self.bind()
		logger.info(f"Connection {self.uuid} opened.")
		# LOG Open Connection Events
		if not self.is_authenticating and self.user:
			DBLogMixin.log(
				user=self.user.id,
				operation_type=LOG_ACTION_OPEN,
				log_target_class=LOG_CLASS_CONN,
				log_target=f"{self.uuid}",
			)
		return self

	def __exit__(self, exc_type, exc_value, traceback) -> None:
		self.__validate_entered__()
		if self.connection:
			self.connection.unbind()
		# LOG Open Connection Events
		if not self.is_authenticating and self.user:
			DBLogMixin.log(
				user=self.user.id,
				operation_type=LOG_ACTION_CLOSE,
				log_target_class=LOG_CLASS_CONN,
				log_target=f"{self.uuid}",
			)
		logger.info(f"Connection {self.uuid} closed.")
		if exc_value:
			logger.exception(exc_value)
			raise exc_value

	def __validate_entered__(self) -> None:
		"""Ensure the LDAPConnector is used within a context manager."""
		if not self._entered:
			raise Exception(
				"LDAPConnector can only be used as a context manager or forcing _entered to True."
			)

	def __new_uuid__(self) -> None:
		self.uuid = uuid4()

	def bind(self) -> None:
		self.__validate_entered__()
		# Connect.
		try:
			connection_args = {
				"user": self.user_dn,
				"password": self._temp_password,
				"auto_bind": True,
				"raise_exceptions": True,
				"receive_timeout": RuntimeSettings.LDAP_AUTH_RECEIVE_TIMEOUT,
				"check_names": True,
			}
			# Do not use this in production or testing
			# It can leak sensitive data such as decrypted credentials
			if DEVELOPMENT_LOG_LDAP_BIND_CREDENTIALS is True:  # pragma: no cover
				logger.info(connection_args)

			# ! LDAP / LDAPS
			c = ldap3.Connection(self.server_pool, **connection_args)
		except LDAPException as ex:
			logger.exception(ex)
			str_ex = "LDAP Connection creation failed: {ex}".format(ex=str(ex))
			raise exc_ldap.CouldNotOpenConnection(data={"message": str_ex})

		# ! Unset Password ! #
		del self._temp_password
		# Configure.
		try:
			if RuntimeSettings.LDAP_AUTH_USE_TLS:
				logger.debug(
					f"Starting TLS (LDAP Use TLS: {str(RuntimeSettings.LDAP_AUTH_USE_TLS)})"
				)
				c.start_tls()
			c.bind(read_server_info=True)
			# Return the connection.
			logger.debug(f"LDAP connect for user {self.user_dn} succeeded")
			self.connection = c
		except LDAPException as ex:
			logger.exception(ex)
			str_ex = "LDAP bind failed: {ex}".format(ex=str(ex))
			raise exc_ldap.CouldNotOpenConnection(data={"message": str_ex})

	def rebind(self, user_dn, password):
		self.__validate_entered__()
		if not password or len(password) < 1:
			self.connection.unbind()
			raise ValueError("Password length smaller than one, unbinding connection.")
		try:
			self.connection.rebind(user=user_dn, password=password, read_server_info=True)
		except LDAPException as ex:
			logger.error(f"Rebind failed for user {str(user_dn)}.")
			return None
		return self.connection.result

	def get_user(self, **kwargs) -> User | None:
		self.__validate_entered__()
		"""
		Returns the user with the given identifier.

		The user identifier should be keyword arguments matching the fields
		in settings.LDAP_AUTH_USER_LOOKUP_FIELDS.
		"""
		searchFilter = ""
		for field in RuntimeSettings.LDAP_AUTH_USER_LOOKUP_FIELDS:
			searchFilter = search_filter_add(
				searchFilter,
				f"{RuntimeSettings.LDAP_AUTH_USER_FIELDS[field]}={kwargs['username']}",
				LDAP_FILTER_OR,
			)
		# Search the LDAP database.
		if self.connection.search(
			search_base=RuntimeSettings.LDAP_AUTH_SEARCH_BASE,
			search_filter=searchFilter,
			search_scope=ldap3.SUBTREE,
			attributes=ldap3.ALL_ATTRIBUTES,
			get_operational_attributes=True,
			size_limit=1,
		):
			return self._get_or_create_user(self.connection.response[0])
		logger.warning("LDAP user lookup failed")
		return None

	def _get_user_fields(self, attributes) -> dict:
		_fields = {
			local_attr_name: (
				attributes[ldap_attr_name][0]
				if isinstance(attributes[ldap_attr_name], (list, tuple))
				else attributes[ldap_attr_name]
			)
			for local_attr_name, ldap_attr_name in RuntimeSettings.LDAP_AUTH_USER_FIELDS.items()
			if ldap_attr_name in attributes
		}
		return import_func(RuntimeSettings.LDAP_AUTH_CLEAN_USER_DATA)(_fields)

	def _get_or_create_user(self, user_data) -> User:
		"""
		Returns a Django user for the given LDAP user data.

		If the user does not exist, then it will be created.
		"""
		self.__validate_entered__()

		attributes = user_data.get("attributes")
		if attributes is None:
			logger.warning("LDAP user attributes empty")
			return None

		User = get_user_model()

		# Create the user data.
		user_fields = self._get_user_fields(attributes=attributes)

		# Create the user lookup.
		user_lookup = {}
		for field_name in RuntimeSettings.LDAP_AUTH_USER_LOOKUP_FIELDS:
			_v = user_fields.pop(field_name, "")
			if _v and len(_v) >= 1:
				user_lookup[field_name] = _v

		# Update or create the user.
		user, created = User.objects.update_or_create(defaults=user_fields, **user_lookup)

		# If the user was created, set them an unusable password.
		if created:
			user.set_unusable_password()
			user.save()

		# Update relations
		# sync_user_relations_func = import_func(LDAP_AUTH_SYNC_USER_RELATIONS)
		sync_user_relations_func = sync_user_relations
		sync_user_relations_arginfo = getfullargspec(sync_user_relations_func)
		args = {}  # additional keyword arguments
		for argname in sync_user_relations_arginfo.kwonlyargs:
			if argname == "connection":
				args["connection"] = self.connection
			else:
				raise TypeError(
					f"Unknown kw argument {argname} in signature for LDAP_AUTH_SYNC_USER_RELATIONS"
				)

		# call sync_user_relations_func() with original args plus supported named extras
		sync_user_relations_func(user, attributes, **args)

		# All done!
		logger.info("LDAP user lookup succeeded")
		return user


# For testing
class LDAPInfo(LDAPConnector):
	def __init__(self, user: User = None, force_admin=False, get_ldap_info=ldap3.ALL, **kwargs):
		super().__init__(user=user, force_admin=force_admin, get_ldap_info=get_ldap_info)
		self.refresh_server_info()

	def refresh_server_info(self):
		server_pool: ldap3.ServerPool = self.connection.server_pool
		current_server: ldap3.Server = server_pool.get_current_server(self.connection)
		current_server.get_info_from_server(self.connection)
		self.schema = current_server.schema
		self.info = current_server.info

	def get_domain_root(self):
		try:
			domain_root = self.info.other["defaultNamingContext"][0]
			return domain_root
		except Exception as e:
			logger.exception(exc_info=e)

	def get_schema_naming_context(self):
		try:
			schema_naming_context = self.info.other["schemaNamingContext"][0]
			return schema_naming_context
		except Exception as e:
			logger.exception(exc_info=e)

	def get_forest_root(self):
		try:
			forest_root = self.info.other["rootDomainNamingContext"][0]
			return forest_root
		except Exception as e:
			logger.exception(exc_info=e)


def test_ldap_connection(
	username,
	user_dn,
	password,
	ldapAuthConnectionUser,
	ldapAuthConnectionPassword,
	ldapAuthURL,
	ldapAuthConnectTimeout,
	ldapAuthReceiveTimeout,
	ldapAuthUseSSL,
	ldapAuthUseTLS,
	ldapAuthTLSVersion,
):
	format_username = import_func(RuntimeSettings.LDAP_AUTH_FORMAT_USERNAME)

	if password != ldapAuthConnectionPassword and username != "admin":
		password = password
	elif username == "admin":
		user_dn = ldapAuthConnectionUser
		password = ldapAuthConnectionPassword

	if not isinstance(ldapAuthConnectTimeout, int):
		logger.info("ldapAuthConnectTimeout is not an int, using default")
		ldapAuthConnectTimeout = 5
	if not isinstance(ldapAuthReceiveTimeout, int):
		logger.info("ldapAuthReceiveTimeout is not an int, using default")
		ldapAuthReceiveTimeout = 5

	# Initialize Server Args Dictionary
	server_args = {"connect_timeout": ldapAuthConnectTimeout}

	# Build server pool
	server_pool = ldap3.ServerPool(None, ldap3.RANDOM, active=True, exhaust=5)
	auth_url = ldapAuthURL
	if not isinstance(auth_url, Iterable):
		raise TypeError("auth_url must be str or Iterable.")
	elif isinstance(auth_url, str):
		auth_url = [auth_url]

	if not isinstance(ldapAuthTLSVersion, Enum):
		ldapAuthTLSVersion = getattr(ssl, ldapAuthTLSVersion)

	# Include SSL, if requested.
	server_args["use_ssl"] = ldapAuthUseSSL
	# Include SSL / TLS, if requested.
	if ldapAuthUseTLS:
		server_args["tls"] = ldap3.Tls(
			ciphers="ALL",
			version=ldapAuthTLSVersion,
		)
	for u in auth_url:
		server_pool.add(
			ldap3.Server(
				u, allowed_referral_hosts=[("*", True)], get_info=ldap3.NONE, **server_args
			)
		)
	# Connect.
	try:
		# Include SSL / TLS, if requested.
		connection_args = {
			"user": user_dn,
			"password": password,
			"auto_bind": True,
			"raise_exceptions": True,
			"receive_timeout": ldapAuthReceiveTimeout,
		}

		# ! LDAP / LDAPS
		c = ldap3.Connection(server_pool, **connection_args)
	except LDAPException as ex:
		logger.warning("LDAP connection test failed.", exc_info=ex)
		raise exc_ldap.CouldNotOpenConnection(
			data={
				"message": "LDAP connection test failed.",
			}
		)

	# Configure.
	try:
		if ldapAuthUseTLS:
			logger.debug(f"Starting TLS (LDAP Use TLS: {ldapAuthUseTLS})")
			c.start_tls()
		# Perform initial authentication bind.
		c.bind(read_server_info=True)
		# Return the connection.
		logger.debug("LDAP connect for user " + user_dn + " succeeded")
		return c
	except LDAPException as ex:
		logger.warning("LDAP connection bind failed.", exc_info=ex)
		raise exc_ldap.CouldNotOpenConnection(
			data={
				"message": "LDAP connection bind failed.",
			}
		)
