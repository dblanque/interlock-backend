################################################################################
#################### INTERLOCK IS LICENSED UNDER GNU AGPLv3 ####################
################## ORIGINAL PROJECT CREATED BY DYLAN BLANQUÉ ###################
########################## AND BR CONSULTING S.R.L. ############################
################################################################################
# Module: interlock_backend.ldap.accountTypes
# Contains:
# - Bind User connector for Administrative Privilege Operations
# - Recursive directory listing functions

#---------------------------------- IMPORTS -----------------------------------#
from enum import Enum
import traceback, ldap3, ssl, logging, sys
from django_python3_ldap.utils import import_func
from inspect import getfullargspec
from django.contrib.auth import get_user_model
from interlock_backend.encrypt import (
	aes_encrypt,
	aes_decrypt
)
from interlock_backend.ldap.adsi import search_filter_add
from ldap3.core.exceptions import LDAPException
from core.exceptions import ldap as exc_ldap
from core.views.mixins.logs import LogMixin
from core.models.user import User, USER_PASSWORD_FIELDS
from typing import TypedDict
from typing_extensions import NotRequired
from core.models.ldap_settings_runtime import RunningSettings
from uuid import (
	uuid1,
	getnode as uuid_getnode
)
from random import getrandbits
###############################################################################

this_module = sys.modules[__name__]
DBLogMixin = LogMixin()
logger = logging.getLogger(__name__)

def recursive_member_search(user_dn: str, connection, group_dn):
	# Add filter for username
	ldap_filter_object = ""
	ldap_filter_object = search_filter_add(ldap_filter_object, f"distinguishedName={group_dn}")
	ldap_filter_object = search_filter_add(ldap_filter_object, f"objectClass=group")
	try:
		connection.search(
			RunningSettings.LDAP_AUTH_SEARCH_BASE, 
			ldap_filter_object, 
			attributes=['member', 'objectClass', 'distinguishedName']
		)
	except:
		raise
	for e in connection.entries:
		if 'group' in e.objectClass:
			if user_dn in e.member: return True
			for dn in e.member:
				r = recursive_member_search(
					group_dn=dn,
					user_dn=user_dn,
					connection=connection
				)
				if r == True: return r
	return False

def sync_user_relations(
		user: User,
		ldap_attributes,
		*,
		connection=None,
		dn=None
	):
	user.dn = str(ldap_attributes['distinguishedName']).lstrip("['").rstrip("']")
	if 'Administrator' in ldap_attributes[RunningSettings.LDAP_AUTH_USER_FIELDS["username"]]:
		user.is_staff = True
		user.is_superuser = True
		if 'memberOf' in ldap_attributes:
			user.ldap_groups = ldap_attributes['memberOf']
		user.save()
	elif recursive_member_search(user_dn=user.dn, connection=connection, group_dn=RunningSettings.ADMIN_GROUP_TO_SEARCH):
		user.is_staff = True
		user.is_superuser = True
		if 'memberOf' in ldap_attributes:
			user.ldap_groups = ldap_attributes['memberOf']
		if user.email is not None and 'mail' in ldap_attributes:
			user.email = str(ldap_attributes['mail']).lstrip("['").rstrip("']") or ""
		user.save()
	else:
		user.is_staff = False
		user.is_superuser = False
		if 'memberOf' in ldap_attributes:
			user.ldap_groups = ldap_attributes['memberOf']
		if user.email is not None and 'mail' in ldap_attributes:
			user.email = str(ldap_attributes['mail']).lstrip("['").rstrip("']") or ""
		user.save()

def authenticate(*args, **kwargs):
	"""
	Authenticates with the LDAP server, and returns
	the corresponding Django user instance.

	The user identifier should be keyword arguments matching the fields
	in settings.LDAP_AUTH_USER_LOOKUP_FIELDS, plus a `password` argument.
	"""
	username = kwargs["username"]
	if username == 'admin':
		return None
	password = kwargs.pop("password", None)
	auth_user_lookup_fields = RunningSettings.LDAP_AUTH_USER_LOOKUP_FIELDS
	ldap_kwargs = {
		key: value for (key, value) in kwargs.items()
		if key in auth_user_lookup_fields
	}

	# Check that this is valid login data.
	if not password or 'username' not in frozenset(ldap_kwargs.keys()):
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

	encrypted_data = aes_encrypt(password)
	for index, field in enumerate(USER_PASSWORD_FIELDS):
		setattr(user, field, encrypted_data[index])
	del password
	user.is_local = False
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
	def __enter__(self):
		logger.info(f"Connection {self.uuid} opened.")
		# LOG Open Connection Events
		if RunningSettings.LDAP_LOG_OPEN_CONNECTION == True and self.is_authenticating == False:
			DBLogMixin.log(
				user_id=self.user.id,
				actionType="OPEN",
				objectClass="CONN",
				affectedObject=f"{self.uuid}"
			)
		return self
	
	def __exit__(self, exc_type, exc_value, traceback) -> None:
		self.connection.unbind()
		# LOG Open Connection Events
		if RunningSettings.LDAP_LOG_CLOSE_CONNECTION == True and self.is_authenticating == False:
			DBLogMixin.log(
				user_id=self.user.id,
				actionType="CLOSE",
				objectClass="CONN",
				affectedObject=f"{self.uuid}"
			)
		logger.info(f"Connection {self.uuid} closed.")
		if exc_value:
			logger.exception(exc_value)
			raise exc_value

	def __newUuid__(self):
		self.uuid = uuid1(node=uuid_getnode(), clock_seq=getrandbits(14))

	def __init__(self,
		user_dn=None,
		password=None,
		user: User=None,
		force_admin=False,
		plain_text_password=False,
		get_ldap_info=ldap3.NONE,
		is_authenticating=False,
		**kwargs
		):
		self.default_user_dn = RunningSettings.LDAP_AUTH_CONNECTION_USER_DN
		self.default_user_pwd = RunningSettings.LDAP_AUTH_CONNECTION_PASSWORD
		self.__newUuid__()
		self.is_authenticating = is_authenticating
		decrypted_password = self.default_user_pwd

		if not isinstance(RunningSettings.LDAP_AUTH_TLS_VERSION, Enum):
			ldapAuthTLSVersion = getattr(ssl, RunningSettings.LDAP_AUTH_TLS_VERSION)
		else:
			ldapAuthTLSVersion = RunningSettings.LDAP_AUTH_TLS_VERSION

		# If it's an Initial Authentication we need to use the bind user first
		if force_admin == True or user is not None:
			# If initial auth or user is local interlock superadmin
			if force_admin == True or (user.username == 'admin' and user.is_local == True):
				user_dn = self.default_user_dn
				password = decrypted_password

		if not user_dn and not force_admin:
			print(traceback.format_exc())
			raise ValueError(f"No user_dn was provided for LDAP Connector ({user_dn})")

		logger.debug("Connection Parameters: ")
		logger.debug(f'User: {user}')
		logger.debug(f'User DN: {user_dn}')
		logger.debug(f'LDAP URL: {RunningSettings.LDAP_AUTH_URL}')
		logger.debug(f'LDAP Connect Timeout: {RunningSettings.LDAP_AUTH_CONNECT_TIMEOUT}')
		logger.debug(f'LDAP Receive Timeout: {RunningSettings.LDAP_AUTH_RECEIVE_TIMEOUT}')
		logger.debug(f'LDAP Use SSL: {RunningSettings.LDAP_AUTH_USE_SSL}')
		logger.debug(f'LDAP Use TLS: {RunningSettings.LDAP_AUTH_USE_TLS}')
		logger.debug(f'LDAP TLS Version: {ldapAuthTLSVersion}')

		if password != decrypted_password and plain_text_password == False:
			password = aes_decrypt(
				*[getattr(user, field) for field in USER_PASSWORD_FIELDS]
			)

		# Initialize Server Args Dictionary
		server_args = {
			'get_info': get_ldap_info,
			'connect_timeout': RunningSettings.LDAP_AUTH_CONNECT_TIMEOUT
		}

		# Build server pool
		self.server_pool = ldap3.ServerPool(None, ldap3.RANDOM, active=True, exhaust=5)
		self.auth_url = RunningSettings.LDAP_AUTH_URL
		if not isinstance(self.auth_url, list):
			self.auth_url = [self.auth_url]

		# Include SSL, if requested.
		server_args['use_ssl'] = RunningSettings.LDAP_AUTH_USE_SSL
		# Include TLS, if requested.
		if RunningSettings.LDAP_AUTH_USE_TLS:
			self.tlsSettings = ldap3.Tls(
				ciphers='ALL',
				version=ldapAuthTLSVersion,
			)
			server_args['tls'] = self.tlsSettings
		else:
			self.tlsSettings = None

		for u in self.auth_url:
			server = ldap3.Server(
							u,
							allowed_referral_hosts=[("*", True)],
							**server_args
						)
			self.server_pool.add(server)

		self.user = user
		self.user_dn = user_dn
		self.auth_url = self.auth_url
		self.connection = None
		# Connect.
		try:
			connection_args = {
				"user": user_dn,
				"password": password,
				"auto_bind": True,
				"raise_exceptions": True,
				"receive_timeout": RunningSettings.LDAP_AUTH_RECEIVE_TIMEOUT,
				"check_names": True,
			}

			# ! LDAP / LDAPS
			c = ldap3.Connection(
				self.server_pool,
				**connection_args
			)
		except LDAPException as ex:
			str_ex = "LDAP connect failed: {ex}".format(ex=ex)
			logger.error(str_ex)
			# logger.error([v for k,v in vars(RunningSettings).items() if not k.startswith("__")])
			exception = exc_ldap.CouldNotOpenConnection
			data = {
				"code": exception.default_code,
				"message": str_ex
			}
			exception.set_detail(exception, data)
			raise exception

		# ! Unset Password ! #
		del password
		# Configure.
		try:
			if RunningSettings.LDAP_AUTH_USE_TLS:
				logger.debug(f"Starting TLS (LDAP Use TLS: {RunningSettings.LDAP_AUTH_USE_TLS})")
				c.start_tls()
			c.bind(read_server_info=True)
			# Return the connection.
			logger.debug("LDAP connect for user " + user_dn + " succeeded")
			self.connection = c
		except LDAPException as ex:
			str_ex = "LDAP bind failed: {ex}".format(ex=ex)
			logger.error(str_ex)
			logger.exception(ex)
			exception = exc_ldap.CouldNotOpenConnection
			data = {
				"code": exception.default_code,
				"message": str_ex
			}
			exception.set_detail(exception, data)
			raise exception

	def rebind(self, user_dn, password):
		if len(password) < 1: 
			self.connection.unbind()
			raise ValueError("Password length smaller than one, unbinding connection.")
		try:
			self.connection.rebind(
				user=user_dn,
				password=password,
				read_server_info=True
			)
		except:
			return None
		return self.connection.result

	def get_user(self, **kwargs):
		"""
		Returns the user with the given identifier.

		The user identifier should be keyword arguments matching the fields
		in settings.LDAP_AUTH_USER_LOOKUP_FIELDS.
		"""
		searchFilter = ""
		for i in RunningSettings.LDAP_AUTH_USER_LOOKUP_FIELDS:
			searchFilter = search_filter_add(searchFilter, RunningSettings.LDAP_AUTH_USER_FIELDS[i]+"="+kwargs['username'], '|')
		# Search the LDAP database.
		if self.connection.search(
			search_base=RunningSettings.LDAP_AUTH_SEARCH_BASE,
			search_filter=searchFilter,
			search_scope=ldap3.SUBTREE,
			attributes=ldap3.ALL_ATTRIBUTES,
			get_operational_attributes=True,
			size_limit=1,
		):
			return self._get_or_create_user(self.connection.response[0])
		logger.warning("LDAP user lookup failed")
		return None

	def _get_or_create_user(self, user_data):
		"""
		Returns a Django user for the given LDAP user data.

		If the user does not exist, then it will be created.
		"""

		attributes = user_data.get("attributes")
		if attributes is None:
			logger.warning("LDAP user attributes empty")
			return None

		User = get_user_model()

		# Create the user data.
		user_fields = {
			field_name: (
				attributes[attribute_name][0]
				if isinstance(attributes[attribute_name], (list, tuple)) else
				attributes[attribute_name]
			)
			for field_name, attribute_name
			in RunningSettings.LDAP_AUTH_USER_FIELDS.items()
			if attribute_name in attributes
		}
		user_fields = import_func(RunningSettings.LDAP_AUTH_CLEAN_USER_DATA)(user_fields)
		# ! Removed this because it broke user updating
		# Create the user lookup.
		# user_lookup = {
		#     field_name: user_fields.pop(field_name, "")
		#     for field_name
		#     in LDAP_AUTH_USER_LOOKUP_FIELDS
		# }
		user_lookup = {
			'username': user_fields['username']
		}
		# Update or create the user.
		user, created = User.objects.update_or_create(
			defaults=user_fields,
			**user_lookup
		)
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
			elif argname == "dn":
				args["dn"] = user_data.get("dn")
			else:
				raise TypeError(f"Unknown kw argument {argname} in signature for LDAP_AUTH_SYNC_USER_RELATIONS")
		# call sync_user_relations_func() with original args plus supported named extras
		sync_user_relations_func(user, attributes, **args)
		# All done!
		logger.info("LDAP user lookup succeeded")
		return user

class LDAPInfo(LDAPConnector):
	def __init__(
		self, 
		user_dn=None, 
		password=None, 
		user=None, 
		force_admin=False,
		get_ldap_info=ldap3.ALL
		):
		super().__init__(
			user_dn=user_dn,
			password=password,
			user=user,
			force_admin=force_admin,
			get_ldap_info=get_ldap_info
		)
		self.refresh_server_info()

	def refresh_server_info(self):
		current_server = self.connection.server_pool.get_current_server(self.connection)
		current_server.get_info_from_server(self.connection)
		self.schema = current_server.schema
		self.info = current_server.info

	def get_domain_root(self):
		try:
			domainRoot = self.info.other['defaultNamingContext'][0]
		except Exception as e:
			print(e)
		return domainRoot

	def get_schema_naming_context(self):
		try:
			schemaNamingContext = self.info.other['schemaNamingContext'][0]
		except Exception as e:
			print(e)
		return schemaNamingContext

	def get_forest_root(self):
		try:
			forestRoot = self.info.other['rootDomainNamingContext'][0]
		except Exception as e:
			print(e)
		return forestRoot

def test_ldap_connection(
		username,
		user_dn, # Actually this is user_dn
		password,
		ldapAuthConnectionUser,
		ldapAuthConnectionPassword,
		ldapAuthURL,
		ldapAuthConnectTimeout,
		ldapAuthReceiveTimeout,
		ldapAuthUseSSL,
		ldapAuthUseTLS,
		ldapAuthTLSVersion
	):
	format_username = import_func(RunningSettings.LDAP_AUTH_FORMAT_USERNAME)

	if password != ldapAuthConnectionPassword and username != 'admin':
		password = password
	elif username == 'admin':
		user_dn = ldapAuthConnectionUser
		password = ldapAuthConnectionPassword

	if not isinstance(ldapAuthConnectTimeout, int):
		logger.info('ldapAuthConnectTimeout is not an int, using default')
		ldapAuthConnectTimeout = 5
	if not isinstance(ldapAuthReceiveTimeout, int):
		logger.info('ldapAuthReceiveTimeout is not an int, using default')
		ldapAuthReceiveTimeout = 5

	# Initialize Server Args Dictionary
	server_args = {
		'connect_timeout': ldapAuthConnectTimeout
	}

	# Build server pool
	server_pool = ldap3.ServerPool(None, ldap3.RANDOM, active=True, exhaust=5)
	auth_url = ldapAuthURL
	if not isinstance(auth_url, list):
		auth_url = [auth_url]

	if not isinstance(ldapAuthTLSVersion, Enum):
		ldapAuthTLSVersion = getattr(ssl, ldapAuthTLSVersion)

	# Include SSL, if requested.
	server_args['use_ssl'] = ldapAuthUseSSL
	# Include SSL / TLS, if requested.
	if ldapAuthUseTLS == True:
		server_args['tls'] = ldap3.Tls(
			ciphers='ALL',
			version=ldapAuthTLSVersion,
		)
	for u in auth_url:
		server_pool.add(
			ldap3.Server(
				u,
				allowed_referral_hosts=[("*", True)],
				get_info=ldap3.NONE,
				**server_args
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
		c = ldap3.Connection(
			server_pool,
			**connection_args
		)
	except LDAPException as ex:
		str_ex = "LDAP connect failed: {ex}".format(ex=ex)
		logger.warning(str_ex)
		exception = exc_ldap.CouldNotOpenConnection
		data = {
			"code": exception.default_code,
			"message": str_ex
		}
		exception.set_detail(exception, data)
		raise exception

	# ! Unset Password ! #
	del password
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
		str_ex = "LDAP bind failed: {ex}".format(ex=ex)
		logger.warning(str_ex)
		exception = exc_ldap.CouldNotOpenConnection
		data = {
			"code": exception.default_code,
			"message": str_ex
		}
		exception.set_detail(exception, data)
		raise exception
