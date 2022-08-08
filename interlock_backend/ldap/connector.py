# ldap_connector.py
###############################################################################
# Contains:
# - Bind User connector for Administrative Privilege Operations
# - Recursive directory listing functions
###############################################################################
# Originally Created by Dylan Blanqué and BR Consulting S.R.L. (2022)

from enum import Enum
from django_python3_ldap.utils import import_func
from inspect import getfullargspec
from django.contrib.auth import get_user_model
from interlock_backend.ldap.encrypt import (
    decrypt,
    encrypt
)
from interlock_backend.ldap.adsi import addSearchFilter
from interlock_backend.ldap.settings_func import (
    SettingsList,
    getSetting
)
import ldap3
from ldap3.core.exceptions import LDAPException
from core.exceptions import ldap as exc_ldap
from core.models.log import logToDB
import ssl
import logging

logger = logging.getLogger(__name__)

def authenticate(*args, **kwargs):
    """
    Authenticates with the LDAP server, and returns
    the corresponding Django user instance.

    The user identifier should be keyword arguments matching the fields
    in settings.LDAP_AUTH_USER_LOOKUP_FIELDS, plus a `password` argument.
    """
    ldap_settings_list = SettingsList(**{"search":{
        'LDAP_AUTH_USER_LOOKUP_FIELDS',
    }})
    username = kwargs["username"]
    password = kwargs.pop("password", None)
    auth_user_lookup_fields = frozenset(ldap_settings_list.LDAP_AUTH_USER_LOOKUP_FIELDS)
    ldap_kwargs = {
        key: value for (key, value) in kwargs.items()
        if key in auth_user_lookup_fields
    }

    encryptedPass = encrypt(password)
    encryptedPass = str(encryptedPass).strip("b'").rstrip("'")

    # Check that this is valid login data.
    if not password or 'username' not in frozenset(ldap_kwargs.keys()):
        return None

    # Connect to LDAP.
    # with orig_connection(password=password, **ldap_kwargs) as c:
    c = LDAPConnector(password=password, initialAuth=True, plainPassword=True)
    if c.connection is None:
        return None
    user = c.get_user(**ldap_kwargs)
    if user is None or not c.rebind(user=user.dn, password=password):
        return None
    user.encryptedPassword = encryptedPass
    user.is_local = False
    user.save()
    return user

class LDAPConnector(object):
    defaultUserDn = getSetting('LDAP_AUTH_CONNECTION_USER_DN')
    defaultUserPassword = getSetting('LDAP_AUTH_CONNECTION_PASSWORD')

    def __init__(self, 
        user_dn=None, 
        password=None, 
        user=None, 
        initialAuth=False, 
        plainPassword=False
        ):
        self.ldap_settings_list = SettingsList(**{"search":{
            'LDAP_AUTH_USER_FIELDS',
            'LDAP_AUTH_CLEAN_USER_DATA',
            'LDAP_AUTH_SEARCH_BASE',
            'LDAP_AUTH_USER_LOOKUP_FIELDS',
            'LDAP_AUTH_SYNC_USER_RELATIONS',
            'LDAP_AUTH_URL',
            'LDAP_AUTH_CONNECTION_USER_DN',
            'LDAP_AUTH_CONNECTION_PASSWORD',
            'LDAP_AUTH_CONNECT_TIMEOUT',
            'LDAP_AUTH_RECEIVE_TIMEOUT',
            'LDAP_AUTH_USE_TLS',
            'LDAP_AUTH_TLS_VERSION',
            'LDAP_AUTH_FORMAT_USERNAME',
            'LDAP_LOG_OPEN_CONNECTION'
        }})
        ldapAuthURL = self.ldap_settings_list.LDAP_AUTH_URL
        ldapAuthConnectionPassword = self.ldap_settings_list.LDAP_AUTH_CONNECTION_PASSWORD
        ldapAuthConnectTimeout = self.ldap_settings_list.LDAP_AUTH_CONNECT_TIMEOUT
        ldapAuthReceiveTimeout = self.ldap_settings_list.LDAP_AUTH_RECEIVE_TIMEOUT
        ldapAuthUseTLS = self.ldap_settings_list.LDAP_AUTH_USE_TLS
        ldapAuthTLSVersion = self.ldap_settings_list.LDAP_AUTH_TLS_VERSION

        # If no user_dn and no user assume it's initial auth
        if user_dn is None:
            user_dn = self.defaultUserDn
        if password is None:
            password = self.defaultUserPassword

        if initialAuth == True or user is not None:
            if initialAuth == True or (user.username == 'admin' and user.is_local == True):
                user_dn = self.ldap_settings_list.LDAP_AUTH_CONNECTION_USER_DN
                password = ldapAuthConnectionPassword

        logger.debug("Connection Parameters: ")
        logger.debug(user)
        logger.debug(user_dn)
        logger.debug(password)
        # logger.debug(ldapAuthConnectionPassword)
        logger.debug(ldapAuthURL)
        logger.debug(ldapAuthConnectTimeout)
        logger.debug(ldapAuthReceiveTimeout)
        logger.debug(ldapAuthUseTLS)
        logger.debug(ldapAuthTLSVersion)

        if password != ldapAuthConnectionPassword and plainPassword == False:
            password = str(decrypt(password))

        # Build server pool
        server_pool = ldap3.ServerPool(None, ldap3.RANDOM, active=True, exhaust=5)
        auth_url = ldapAuthURL
        if not isinstance(auth_url, list):
            auth_url = [auth_url]

        if not isinstance(ldapAuthTLSVersion, Enum):
            ldapAuthTLSVersion = getattr(ssl, ldapAuthTLSVersion)

        # Include SSL / TLS, if requested.
        if ldapAuthUseTLS:
            tlsSettings = ldap3.Tls(
                ciphers='ALL',
                version=ldapAuthTLSVersion,
            )
        else:
            tlsSettings = None
        for u in auth_url:
            server_pool.add(
                ldap3.Server(
                    u,
                    allowed_referral_hosts=[("*", True)],
                    get_info=ldap3.NONE,
                    connect_timeout=ldapAuthConnectTimeout,
                    use_ssl=ldapAuthUseTLS,
                    tls=tlsSettings
                )
            )

        self.user = user_dn
        self.auth_url = auth_url
        self.connection = None
        # Connect.
        try:
            # LOG Open Connection Events
            if user is not None and self.ldap_settings_list.LDAP_LOG_OPEN_CONNECTION == True:
                logToDB(
                    user_id=user.id,
                    actionType="OPEN",
                    objectClass="CONN"
                )
            connection_args = {
                "user": user_dn,
                "password": password,
                "auto_bind": True,
                "raise_exceptions": True,
                "receive_timeout": ldapAuthReceiveTimeout,
            }
            c = ldap3.Connection(
                server_pool,
                **connection_args,
            )
        except LDAPException as ex:
            str_ex = "LDAP connect failed: {ex}".format(ex=ex)
            logger.warning(str_ex)
            exception = exc_ldap.CouldNotOpenConnection
            data = {
                "code": exception.default_code,
                "message": str_ex
            }
            exception.setDetail(exception, data)
            raise exception

        # ! Unset Password ! #
        password = ""
        # Configure.
        try:
            c.bind(read_server_info=True)
            # Return the connection.
            logger.debug("LDAP connect for user " + user_dn + " succeeded")
            self.connection = c
        except LDAPException as ex:
            str_ex = "LDAP bind failed: {ex}".format(ex=ex)
            logger.warning(str_ex)
            exception = exc_ldap.CouldNotOpenConnection
            data = {
                "code": exception.default_code,
                "message": str_ex
            }
            exception.setDetail(exception, data)
            raise exception

    def rebind(self, user, password):
        try:
            self.connection.rebind(
                user=user,
                password=password,
                read_server_info=True
            )
            return self.connection.result
        except:
            return None

    def get_user(self, **kwargs):
        """
        Returns the user with the given identifier.

        The user identifier should be keyword arguments matching the fields
        in settings.LDAP_AUTH_USER_LOOKUP_FIELDS.
        """
        ldapAuthSearchBase = self.ldap_settings_list.LDAP_AUTH_SEARCH_BASE
        ldapAuthUserFields = self.ldap_settings_list.LDAP_AUTH_USER_FIELDS
        searchFilter = ""
        for i in self.ldap_settings_list.LDAP_AUTH_USER_LOOKUP_FIELDS:
            searchFilter = addSearchFilter(searchFilter, ldapAuthUserFields[i]+"="+kwargs['username'], '|')
        # Search the LDAP database.
        if self.connection.search(
            search_base=ldapAuthSearchBase,
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
            in self.ldap_settings_list.LDAP_AUTH_USER_FIELDS.items()
            if attribute_name in attributes
        }
        user_fields = import_func(self.ldap_settings_list.LDAP_AUTH_CLEAN_USER_DATA)(user_fields)
        # ! Removed this because it broke user updating
        # Create the user lookup.
        # user_lookup = {
        #     field_name: user_fields.pop(field_name, "")
        #     for field_name
        #     in self.ldap_settings_list.LDAP_AUTH_USER_LOOKUP_FIELDS
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
        sync_user_relations_func = import_func(self.ldap_settings_list.LDAP_AUTH_SYNC_USER_RELATIONS)
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


def testLDAPConnection(
        username,
        user_dn, # Actually this is user_dn
        password,
        ldapAuthConnectionUser,
        ldapAuthConnectionPassword,
        ldapAuthURL,
        ldapAuthConnectTimeout,
        ldapAuthReceiveTimeout,
        ldapAuthUseTLS,
        ldapAuthTLSVersion
    ):
    ldap_settings_list = SettingsList(**{"search":{
        'LDAP_AUTH_FORMAT_USERNAME'
    }})
    format_username = import_func(ldap_settings_list.LDAP_AUTH_FORMAT_USERNAME)

    if password != ldapAuthConnectionPassword and username != 'admin':
        password = str(decrypt(password))
    elif username == 'admin':
        user_dn = ldapAuthConnectionUser
        password = ldapAuthConnectionPassword

    if not isinstance(ldapAuthConnectTimeout, int):
        logger.info('ldapAuthConnectTimeout is not an int, using default')
        ldapAuthConnectTimeout = 5
    if not isinstance(ldapAuthReceiveTimeout, int):
        logger.info('ldapAuthReceiveTimeout is not an int, using default')
        ldapAuthReceiveTimeout = 5

    # Build server pool
    server_pool = ldap3.ServerPool(None, ldap3.RANDOM, active=True, exhaust=5)
    auth_url = ldapAuthURL
    if not isinstance(auth_url, list):
        auth_url = [auth_url]

    if not isinstance(ldapAuthTLSVersion, Enum):
        ldapAuthTLSVersion = getattr(ssl, ldapAuthTLSVersion)

    # Include SSL / TLS, if requested.
    if ldapAuthUseTLS:
        tlsSettings = ldap3.Tls(
            ciphers='ALL',
            version=ldapAuthTLSVersion,
        )
    else:
        tlsSettings = None
    for u in auth_url:
        server_pool.add(
            ldap3.Server(
                u,
                allowed_referral_hosts=[("*", True)],
                get_info=ldap3.NONE,
                connect_timeout=ldapAuthConnectTimeout,
                use_ssl=ldapAuthUseTLS,
                tls=tlsSettings
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
        c = ldap3.Connection(
            server_pool,
            **connection_args,
        )
    except LDAPException as ex:
        str_ex = "LDAP connect failed: {ex}".format(ex=ex)
        logger.warning(str_ex)
        exception = exc_ldap.CouldNotOpenConnection
        data = {
            "code": exception.default_code,
            "message": str_ex
        }
        exception.setDetail(exception, data)
        raise exception

    # ! Unset Password ! #
    del password
    # Configure.
    try:
        c.bind(read_server_info=True)
        # Perform initial authentication bind.
        # Rebind as specified settings username and password for querying.
        # c.rebind(
        #     user=format_username({username}),
        #     password=password,
        # )
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
        exception.setDetail(exception, data)
        raise exception
